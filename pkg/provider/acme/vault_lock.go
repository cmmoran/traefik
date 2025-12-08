package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type vaultLock struct {
	Client     *vault.Client
	MountPath  string
	Key        string
	OwnerID    string
	StaleAfter time.Duration

	refMu    sync.Mutex
	refCount int
}

func newVaultLock(client *vault.Client, mountPath, key, ownerID string, staleAfter time.Duration) (*vaultLock, error) {
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	v := &vaultLock{
		Client:     client,
		MountPath:  mountPath,
		Key:        key,
		OwnerID:    ownerID,
		StaleAfter: staleAfter,
	}

	if err := v.ensureInitialized(context.Background()); err != nil {
		if !errors.Is(err, ErrLockAlreadyInitialized) {
			return nil, fmt.Errorf("failed to initialize lock: %w", err)
		}
	}
	return v, nil
}

type lockPayload struct {
	Locked    bool   `json:"locked" mapstructure:"locked"`
	Owner     string `json:"owner" mapstructure:"owner"`
	Timestamp int64  `json:"timestamp" mapstructure:"timestamp"`
}

var (
	ErrLockHeld               = errors.New("lock is currently held by another instance")
	ErrLockAlreadyInitialized = errors.New("lock is already initialized")
)

type lockInfo struct {
	Owner string
}

type lockContextKey struct{}

var lockCtxKey = lockContextKey{}

func withLockInfo(ctx context.Context, info lockInfo) context.Context {
	return context.WithValue(ctx, lockCtxKey, info)
}

func getLockInfo(ctx context.Context) (lockInfo, bool) {
	info, ok := ctx.Value(lockCtxKey).(lockInfo)
	return info, ok
}

func (v *vaultLock) DoWithLock(ctx context.Context, fn func(context.Context) error) error {
	logger := log.Ctx(ctx).With().Str("lib", "vaultlock").Logger()
	v.refMu.Lock()
	if v.refCount == 0 {
		var acquired bool
		var err error
		ctx, acquired, err = v.tryLock(ctx)
		if err != nil {
			v.refMu.Unlock()
			return fmt.Errorf("lock attempt failed: %w", err)
		}
		if !acquired {
			v.refMu.Unlock()
			return ErrLockHeld
		}
	}
	logger.Debug().Msgf("Lock acquired incrementing refCount %d", v.refCount)
	v.refCount++
	v.refMu.Unlock()

	defer func() {
		v.refMu.Lock()
		logger.Debug().Msgf("Lock relenquished decrementing refCount %d", v.refCount)
		v.refCount--
		if v.refCount == 0 {
			_, err := v.unlock(ctx)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to unlock store")
			}
		}
		v.refMu.Unlock()
	}()

	return fn(ctx)
}

func (v *vaultLock) IsLocked(ctx context.Context) (bool, error) {
	if v.hasLock(ctx) {
		return true, nil
	}

	var (
		curr      lockPayload
		lockStale bool
	)
	resp, err := v.Client.Secrets.KvV2Read(ctx, v.Key, vault.WithMountPath(v.MountPath))
	if err != nil {
		if vault.IsErrorStatus(err, 404) {
			curr = lockPayload{}
			lockStale = true
		} else {
			return false, fmt.Errorf("failed to read lock: %w", err)
		}
	} else {
		if err = decodePayload(resp.Data.Data, &curr); err != nil {
			return false, fmt.Errorf("failed to parse lock payload: %w", err)
		}
		lockStale = !curr.Locked || time.Since(time.Unix(curr.Timestamp, 0)) > v.StaleAfter
	}

	return curr.Locked && !lockStale, nil
}

func (v *vaultLock) ensureInitialized(ctx context.Context) error {
	mount := vault.WithMountPath(v.MountPath)

	meta, err := v.Client.Secrets.KvV2ReadMetadata(ctx, v.Key, mount)
	if err == nil {
		if !meta.Data.CasRequired {
			_, err = v.Client.Secrets.KvV2WriteMetadata(ctx, v.Key, schema.KvV2WriteMetadataRequest{
				CasRequired: true,
			}, mount)
		}
		resp, rerr := v.Client.Secrets.KvV2Read(ctx, v.Key, vault.WithMountPath(v.MountPath))
		var curr lockPayload
		if rerr != nil {
			if vault.IsErrorStatus(rerr, 404) {
				curr = lockPayload{}
			} else if resp != nil && resp.Data.Data != nil {
				rerr = decodePayload(resp.Data.Data, &curr)
			}
			if rerr != nil || time.Since(time.Unix(curr.Timestamp, 0)) > v.StaleAfter {
				_, err = v.Client.Secrets.KvV2Write(ctx, v.Key, schema.KvV2WriteRequest{
					Data: map[string]interface{}{
						"locked":    false,
						"owner":     "",
						"timestamp": 0,
					},
					Options: map[string]interface{}{
						"cas": meta.Data.CurrentVersion,
					},
					Version: int32(meta.Data.CurrentVersion),
				}, mount)
				if err != nil {
					if !vault.IsErrorStatus(err, http.StatusBadRequest) {
						return fmt.Errorf("failed to reset lock metadata: %w", err)
					}
				}
			}
		}

		return ErrLockAlreadyInitialized
	}

	if !vault.IsErrorStatus(err, http.StatusNotFound) {
		return fmt.Errorf("failed to check lock metadata: %w", err)
	}

	_, err = v.Client.Secrets.KvV2Write(ctx, v.Key, schema.KvV2WriteRequest{
		Data: map[string]interface{}{
			"locked":    false,
			"owner":     "",
			"timestamp": 0,
		},
		Options: map[string]interface{}{
			"cas": 0,
		},
		Version: 0,
	}, mount)
	if err != nil {
		return ErrLockAlreadyInitialized
	}
	return err
}

func (v *vaultLock) hasLock(ctx context.Context) bool {
	logger := log.Ctx(ctx)
	if info, ok := getLockInfo(ctx); ok && info.Owner == v.OwnerID {
		resp, err := v.Client.Secrets.KvV2Read(ctx, v.Key, vault.WithMountPath(v.MountPath))
		if err == nil {
			version, _ := extractVersion(resp.Data.Metadata)
			var curr lockPayload
			_ = decodePayload(resp.Data.Data, &curr)
			expiry := time.Unix(curr.Timestamp, 0).Add(v.StaleAfter)
			if time.Until(expiry) < v.StaleAfter/2 {
				logger.Debug().Msgf("Lock is expiring soon, renewing it. Expiry: %s", expiry)
				newPayload := map[string]interface{}{
					"locked":    true,
					"owner":     v.OwnerID,
					"timestamp": time.Now().Unix(),
				}
				if _, err = v.Client.Secrets.KvV2Write(ctx, v.Key, schema.KvV2WriteRequest{
					Data: newPayload,
					Options: map[string]interface{}{
						"cas": version,
					},
					Version: version,
				}, vault.WithMountPath(v.MountPath)); err != nil {
					logger.Error().Err(err).Msg("Failed to renew lock")
				} else {
					logger.Debug().Msgf("Lock renewed, Expiry: %s", time.Unix(curr.Timestamp, 0).Add(v.StaleAfter))
				}
			}
		}
		return true
	}

	return false
}

func (v *vaultLock) tryLock(ctx context.Context) (context.Context, bool, error) {
	if v.hasLock(ctx) {
		return ctx, true, nil
	}

	var (
		version   int32
		curr      lockPayload
		lockStale bool
		logger    = log.Ctx(ctx)
	)
	resp, err := v.Client.Secrets.KvV2Read(ctx, v.Key, vault.WithMountPath(v.MountPath))
	if err != nil {
		if vault.IsErrorStatus(err, 404) {
			curr = lockPayload{}
			lockStale = true
		} else {
			return ctx, false, fmt.Errorf("failed to read lock: %w", err)
		}
	} else {
		version, err = extractVersion(resp.Data.Metadata)
		if err != nil {
			return ctx, false, fmt.Errorf("failed to extract version: %w", err)
		}
		if err = decodePayload(resp.Data.Data, &curr); err != nil {
			return ctx, false, fmt.Errorf("failed to parse lock payload: %w", err)
		}
		lockStale = !curr.Locked || time.Since(time.Unix(curr.Timestamp, 0)) > v.StaleAfter
	}

	if curr.Locked && curr.Owner != v.OwnerID && !lockStale {
		return ctx, false, errors.Join(ErrLockHeld, fmt.Errorf("lock is currently held by %q", curr.Owner))
	} else {
		logger.Debug().Str("me", v.OwnerID).Any("current", curr).Msg("Lock is not held")
	}

	newData := map[string]interface{}{
		"locked":    true,
		"owner":     v.OwnerID,
		"timestamp": time.Now().Unix(),
	}

	_, err = v.Client.Secrets.KvV2Write(ctx, v.Key, schema.KvV2WriteRequest{
		Data: newData,
		Options: map[string]interface{}{
			"cas": version,
		},
		Version: version,
	}, vault.WithMountPath(v.MountPath))

	if err != nil {
		if vault.IsErrorStatus(err, http.StatusBadRequest) {
			return ctx, false, ErrLockHeld
		}
		return ctx, false, fmt.Errorf("CAS lock write failed: %w", err)
	}

	lockContent := lockInfo{Owner: v.OwnerID}
	logger.Debug().Str("me", v.OwnerID).Int32("version", version).Any("lockInfo", lockContent).Msgf("Lock acquired, Expiry: %s", time.Unix(curr.Timestamp, 0).Add(v.StaleAfter))
	return withLockInfo(ctx, lockContent), true, nil
}

func (v *vaultLock) unlock(ctx context.Context) (context.Context, error) {
	resp, err := v.Client.Secrets.KvV2Read(ctx, v.Key, vault.WithMountPath(v.MountPath))
	if err != nil {
		return ctx, fmt.Errorf("failed to read lock before unlock: %w", err)
	}

	version, err := extractVersion(resp.Data.Metadata)
	if err != nil {
		return ctx, fmt.Errorf("failed to extract version: %w", err)
	}

	var curr lockPayload
	if err = decodePayload(resp.Data.Data, &curr); err != nil {
		return ctx, fmt.Errorf("failed to decode payload: %w", err)
	}

	if curr.Owner != v.OwnerID {
		return ctx, fmt.Errorf("not lock owner — expected %q, found %q", v.OwnerID, curr.Owner)
	}

	newData := map[string]interface{}{
		"locked":    false,
		"owner":     "",
		"timestamp": time.Now().Unix(),
	}

	_, err = v.Client.Secrets.KvV2Write(ctx, v.Key, schema.KvV2WriteRequest{
		Data: newData,
		Options: map[string]interface{}{
			"cas": version,
		},
		Version: version,
	}, vault.WithMountPath(v.MountPath))

	return context.WithValue(ctx, lockCtxKey, nil), err
}

func extractVersion(metadata map[string]interface{}) (int32, error) {
	raw, ok := metadata["version"]
	if !ok {
		return 0, fmt.Errorf("metadata missing 'version'")
	}
	switch val := raw.(type) {
	case float64:
		return int32(val), nil
	case int:
		return int32(val), nil
	case int64:
		return int32(val), nil
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return 0, fmt.Errorf("json.Number to int64 failed: %w", err)
		}
		return int32(i), nil
	default:
		return 0, fmt.Errorf("unexpected type for 'version': %T", val)
	}
}

func decodePayload(data map[string]interface{}, into *lockPayload) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
