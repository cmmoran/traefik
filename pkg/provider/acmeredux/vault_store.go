package acmeredux

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/rs/zerolog/log"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/types"
)

var _ Store = (*VaultStore)(nil)

// VaultStore Stores implementation for vault storage.
type VaultStore struct {
	vaultConfig *VaultConfig
	client      *vault.Client
	filename    string
	vaultLock   *vaultLock
	initMu      sync.Mutex

	lock       sync.RWMutex
	storedData map[string]*StoredData
}

// NewVaultStore initializes a new VaultStore with a vault.
func NewVaultStore(filename string, config *VaultConfig, _ *safe.Pool) *VaultStore {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	found := true
	for strings.HasPrefix(filename, "/") && found {
		filename, found = strings.CutPrefix(filename, "/")
	}
	store := &VaultStore{
		vaultConfig: config,
		filename:    filename,
	}
	logger.Info().Msgf("Created VaultStore mountpath=%s filename=%s", store.vaultConfig.EnginePath, store.filename)
	store.Init()
	return store
}

func (v *VaultStore) Init() {
	_ = v.initializeClient()
	_ = v.initializeLock()
}

func (v *VaultStore) initializeClient() error {
	v.initMu.Lock()
	defer v.initMu.Unlock()

	if v.client != nil {
		return nil
	}

	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	tlsConfig := vault.TLSConfiguration{}
	if v.vaultConfig.Tls != nil {

		if len(v.vaultConfig.Tls.CABundle) > 0 {
			tlsConfig.ServerCertificate = vault.ServerCertificateEntry{
				FromFile: v.vaultConfig.Tls.CABundle,
			}
		}
		if len(v.vaultConfig.Tls.Key) > 0 && len(v.vaultConfig.Tls.Cert) > 0 {
			tlsConfig.ClientCertificate = vault.ClientCertificateEntry{
				FromFile: v.vaultConfig.Tls.Cert,
			}
			tlsConfig.ClientCertificateKey = vault.ClientCertificateKeyEntry{
				FromFile: v.vaultConfig.Tls.Key,
			}
		}
		tlsConfig.InsecureSkipVerify = v.vaultConfig.Tls.SkipVerify
		if v.vaultConfig.Tls.SkipVerify && len(v.vaultConfig.Tls.ServerName) > 0 {
			tlsConfig.ServerName = v.vaultConfig.Tls.ServerName
		}
	}
	client, err := vault.New(vault.WithAddress(v.vaultConfig.Url), vault.WithTLS(tlsConfig))
	if err != nil {
		return fmt.Errorf("error creating vault client: %w", err)
	}

	if len(v.vaultConfig.Namespace) > 0 {
		if err := client.SetNamespace(v.vaultConfig.Namespace); err != nil {
			logger.Error().Msgf("Error setting namespace=%s", v.vaultConfig.Namespace)
		}
	}
	ctx := context.Background()
	switch {
	case len(v.vaultConfig.Auth.Token) > 0:
		var err error
		if err = client.SetToken(v.vaultConfig.Auth.Token); err != nil {
			return fmt.Errorf("error setting client token from vault: %w", err)
		}
	case v.vaultConfig.Auth.CertAuth != nil:
		var (
			err  error
			resp *vault.Response[map[string]interface{}]
		)
		ro := make([]vault.RequestOption, 0)
		if len(v.vaultConfig.Auth.CertAuth.EnginePath) > 0 {
			ro = append(ro, vault.WithMountPath(v.vaultConfig.Auth.CertAuth.EnginePath))
		}
		if resp, err = client.Auth.CertLogin(ctx, schema.CertLoginRequest{
			Name: v.vaultConfig.Auth.CertAuth.Name,
		}, ro...); err != nil {
			return fmt.Errorf("vault cert login failed: %w", err)
		}

		logger.Info().Msg("Vault Login, no err")
		if resp.Auth != nil {
			if err = client.SetToken(resp.Auth.ClientToken); err != nil {
				return fmt.Errorf("error setting client token from vault: %w", err)
			}
		}
	case v.vaultConfig.Auth.AppRole != nil:
		var (
			err  error
			resp *vault.Response[map[string]interface{}]
		)
		ro := make([]vault.RequestOption, 0)
		if len(v.vaultConfig.Auth.AppRole.EnginePath) > 0 {
			ro = append(ro, vault.WithMountPath(v.vaultConfig.Auth.AppRole.EnginePath))
		}
		if resp, err = client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
			RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
			SecretId: v.vaultConfig.Auth.AppRole.SecretID,
		}, ro...); err != nil {
			if terr := client.SetToken(v.vaultConfig.Auth.AppRole.SecretID); terr != nil {
				return fmt.Errorf("vault approle login failed and unwrap token setup failed: %w", err)
			}
			unwrappResponse, uerr := client.System.Unwrap(ctx, schema.UnwrapRequest{})
			if uerr != nil {
				return fmt.Errorf("vault approle login failed and unwrap failed: %w", err)
			}
			unwrappedSecretId := unwrappResponse.Data["secret_id"].(string)
			if resp, err = client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
				RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
				SecretId: unwrappedSecretId,
			}, ro...); err != nil {
				return fmt.Errorf("vault approle login failed after unwrap: %w", err)
			}

			logger.Info().Msg("Vault AppRole Login, no err")
			// Update client token
			if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
				if err = client.SetToken(resp.Auth.ClientToken); err != nil {
					return fmt.Errorf("error setting client token from vault: %w", err)
				}
			}
		} else {
			logger.Info().Msg("Vault AppRole Login, no err")
		}
		// Update client token
		if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
			if err = client.SetToken(resp.Auth.ClientToken); err != nil {
				return fmt.Errorf("error setting client token from vault: %w", err)
			}
		}
	}

	v.client = client
	return nil
}

func (v *VaultStore) initializeLock() error {
	v.initMu.Lock()
	defer v.initMu.Unlock()

	if v.vaultLock != nil {
		return nil
	}
	if v.client == nil {
		return errors.New("vault client is not initialized")
	}

	logger := log.With().Str(logs.ProviderName, "acme").Logger()

	if v.vaultConfig.LockOwnerId == "" {
		v.vaultConfig.LockOwnerId = uuid.New().String()
	} else if strings.HasPrefix(v.vaultConfig.LockOwnerId, "env:") {
		lockEnvVar := strings.TrimPrefix(v.vaultConfig.LockOwnerId, "env:")
		if lockEnv, ok := os.LookupEnv(lockEnvVar); ok {
			v.vaultConfig.LockOwnerId = lockEnv
		} else {
			logger.Warn().Msgf("Vault Lock OwnerId env var %s not found, falling back to uuid", lockEnvVar)
			v.vaultConfig.LockOwnerId = uuid.New().String()
		}
	}
	logger.Info().Msgf("Vault Lock OwnerId=%s", v.vaultConfig.LockOwnerId)

	if v.vaultConfig.StaleLock <= 0 {
		v.vaultConfig.StaleLock = ptypes.Duration(time.Minute * 5)
	}

	vl, err := newVaultLock(
		v.client,
		v.vaultConfig.EnginePath,
		fmt.Sprintf("%s.lock", v.filename),
		v.vaultConfig.LockOwnerId,
		time.Duration(v.vaultConfig.StaleLock),
	)
	if err != nil {
		return fmt.Errorf("vault lock is not initialized: %w", err)
	}

	v.vaultLock = vl
	logger.Info().Msg("Vault Token set! Checking certificate storage")
	v.checkVaultStorage()
	return nil
}

func (v *VaultStore) waitForClientReady(ctx context.Context) error {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	for {
		if err := v.initializeClient(); err == nil {
			return nil
		} else {
			logger.Warn().Err(err).Msg("Vault client/store not ready yet; waiting for acmeredux startup/runtime to continue")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (v *VaultStore) waitForLockReady(ctx context.Context) error {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	for {
		if err := v.waitForClientReady(ctx); err != nil {
			return err
		}
		if err := v.initializeLock(); err == nil {
			return nil
		} else {
			logger.Warn().Err(err).Msg("Vault lock is not ready yet; waiting for acmeredux lease operations to continue")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (v *VaultStore) writeSnapshot(ctx context.Context, snapshot map[string]*StoredData) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	version := int32(0)
	resp, rerr := v.client.Secrets.KvV2Read(ctx, v.filename, vault.WithMountPath(v.vaultConfig.EnginePath))
	if rerr != nil {
		if !vault.IsErrorStatus(rerr, http.StatusNotFound) {
			return rerr
		}
	} else {
		version, rerr = extractVersion(resp.Data.Metadata)
		if rerr != nil {
			return rerr
		}
	}

	var wresp *vault.Response[schema.KvV2WriteResponse]
	wresp, rerr = v.client.Secrets.KvV2Write(
		ctx,
		v.filename,
		schema.KvV2WriteRequest{
			Data: map[string]any{
				"data": data,
			},
			Options: map[string]interface{}{
				"cas": version,
			},
			Version: version,
		},
		vault.WithMountPath(v.vaultConfig.EnginePath),
	)
	if rerr != nil {
		return rerr
	}

	log.Ctx(ctx).Info().Msgf("Wrote acme json with requestID: %v", wresp.RequestID)
	return nil
}

func cloneAccount(account *Account) *Account {
	if account == nil {
		return nil
	}

	clone := *account
	if account.PrivateKey != nil {
		clone.PrivateKey = append([]byte(nil), account.PrivateKey...)
	}
	if account.Registration != nil {
		reg := *account.Registration
		clone.Registration = &reg
	}

	return &clone
}

// saveLocked persists a fresh, lock-held view of the full ACME document.
// The caller must already be executing inside DoWithLock; this method must not
// reacquire the Vault lock internally.
func (v *VaultStore) saveLocked(ctx context.Context, resolverName string, mutate func(*StoredData)) error {
	if v.vaultLock != nil && !v.vaultLock.hasLock(ctx) {
		return errors.New("vault lock must be held before calling saveLocked")
	}

	// Once the cluster lock is held, Vault becomes the authoritative source of
	// truth for the next full-document write. Reload under the lock so a stale
	// local cache cannot overwrite a newer committed snapshot from another node.
	if _, err := v.get(resolverName, true); err != nil {
		return err
	}

	v.lock.RLock()
	snapshot := deepCopyStoredDataMap(v.storedData)
	v.lock.RUnlock()

	if snapshot == nil {
		snapshot = map[string]*StoredData{}
	}
	if snapshot[resolverName] == nil {
		snapshot[resolverName] = &StoredData{}
	}

	mutate(snapshot[resolverName])

	if err := v.writeSnapshot(ctx, snapshot); err != nil {
		return err
	}

	v.lock.Lock()
	v.storedData = snapshot
	v.lock.Unlock()

	return nil
}

func (v *VaultStore) checkVaultStorage() {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	hasData, data, err := v.checkVault()
	if hasData {
		if decodedData, derr := base64.StdEncoding.DecodeString(string(data)); derr == nil {
			data = decodedData
		}
		sd := &StoredData{}
		if err = json.Unmarshal(data, &sd); err != nil {
			logger.Error().Err(err).Msg("Error unmarshalling certificate data")
		} else {
			if len(sd.Certificates) > 0 {
				logger.Info().Msgf("Vault storage %d certificate(s)", len(sd.Certificates))
				for _, sdc := range sd.Certificates {
					if len(sdc.Certificate.Certificate) >= 0 && len(sdc.Key) > 0 {
						logger.Info().Msgf("Vault storage certificate: %s", sdc.Domain.ToStrArray())
					}
				}
			}
		}
		logger.Info().Msgf("Vault storage has certificate(s): cert: len(data) == %d", len(data))
	} else {
		if err != nil {
			logger.Error().Msgf("Vault storage has no certificate (error=%v)", err)
		} else {
			logger.Error().Err(err).Msg("Vault storage has no certificate")
		}
	}
}

func (v *VaultStore) checkVault() (bool, []byte, error) {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	logger.Info().Msgf("Checking Vault for certificate filename[%s] mount[%s]", v.filename, v.vaultConfig.EnginePath)
	ctx := context.Background()
	resp, err := v.client.Secrets.KvV2Read(
		ctx,
		v.filename,
		vault.WithMountPath(v.vaultConfig.EnginePath),
	)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			writeErr := v.doWithLock(ctx, func(ctx context.Context) error {
				_, werr := v.client.Secrets.KvV2Write(
					ctx,
					v.filename,
					schema.KvV2WriteRequest{
						Data: map[string]interface{}{
							"data": &StoredData{
								Account:      nil,
								Certificates: make([]*CertAndStore, 0),
							},
						},
						Options: map[string]interface{}{
							"cas": 0,
						},
						Version: 0,
					},
					vault.WithMountPath(v.vaultConfig.EnginePath),
				)
				if werr != nil && !vault.IsErrorStatus(werr, http.StatusBadRequest) {
					return werr
				}
				return nil
			})
			if writeErr != nil {
				return false, nil, writeErr
			}

			// created and saved an empty *StoredData to vault
			return false, nil, nil
		}
		logger.Error().Err(err).Msgf("Error while checking Vault for certificate filename[%s] mount[%s]", v.filename, v.vaultConfig.EnginePath)
		return false, nil, err
	}

	if resp.Data.Data != nil {
		if storeValue, ok := resp.Data.Data["data"]; ok {
			if storeValue != nil {
				switch t := storeValue.(type) {
				case []byte:
					return true, t, nil
				case string:
					return true, []byte(t), nil
				default:
					return false, nil, nil
				}
			}
		} else {
			return false, nil, errors.New("vault data is invalid")
		}
	}

	return false, nil, nil
}

func (v *VaultStore) get(resolverName string, force ...bool) (*StoredData, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.storedData == nil || (len(force) > 0 && force[0] == true) {
		v.storedData = map[string]*StoredData{}

		hasData, data, err := v.checkVault()
		if err != nil {
			return nil, err
		}

		if hasData {
			logger := log.With().Str(logs.ProviderName, "acme").Logger()

			if len(data) > 0 {
				if decodedData, derr := base64.StdEncoding.DecodeString(string(data)); derr == nil {
					data = decodedData
				}
				if err = json.Unmarshal(data, &v.storedData); err != nil {
					return nil, err
				}
			}

			// Delete all certificates with no value
			changed := false
			for _, storedData := range v.storedData {
				var certificates []*CertAndStore
				for _, certificate := range storedData.Certificates {
					if len(certificate.Certificate.Certificate) == 0 || len(certificate.Key) == 0 {
						logger.Debug().Msgf("Deleting empty certificate %v for %v", certificate, certificate.Domain.ToStrArray())
						continue
					}
					certificates = append(certificates, certificate)
				}
				if len(certificates) < len(storedData.Certificates) {
					changed = true
					storedData.Certificates = certificates
				}
			}
			if changed {
				logger.Debug().Msg("certificates have changed in cache; stale empty entries will be persisted on the next store write")
			}
		}
	}

	if v.storedData[resolverName] == nil {
		v.storedData[resolverName] = &StoredData{}
	}
	return v.storedData[resolverName], nil
}

// unSafeCopyOfStoredData creates maps copy of storedData. Is not thread safe, you should use `s.lock`.
func deepCopyStoredDataMap(src map[string]*StoredData) map[string]*StoredData {
	if src == nil {
		return nil
	}
	out := make(map[string]*StoredData, len(src))
	for key, stored := range src {
		if stored == nil {
			out[key] = nil
			continue
		}

		var account *Account
		if stored.Account != nil {
			acc := *stored.Account
			if stored.Account.PrivateKey != nil {
				acc.PrivateKey = append([]byte(nil), stored.Account.PrivateKey...)
			}
			if stored.Account.Registration != nil {
				reg := *stored.Account.Registration
				acc.Registration = &reg
			}
			account = &acc
		}

		var certs []*CertAndStore
		if stored.Certificates != nil {
			certs = make([]*CertAndStore, 0, len(stored.Certificates))
			for _, cert := range stored.Certificates {
				if cert == nil {
					certs = append(certs, nil)
					continue
				}
				clone := *cert
				clone.Store = cert.Store
				clone.Domain = types.Domain{
					Main: cert.Domain.Main,
				}
				if cert.Domain.SANs != nil {
					clone.Domain.SANs = append([]string(nil), cert.Domain.SANs...)
				}
				if cert.Certificate.Certificate != nil {
					clone.Certificate.Certificate = append([]byte(nil), cert.Certificate.Certificate...)
				}
				if cert.Certificate.Key != nil {
					clone.Certificate.Key = append([]byte(nil), cert.Certificate.Key...)
				}
				certs = append(certs, &clone)
			}
		}

		out[key] = &StoredData{
			Account:      account,
			Certificates: certs,
		}
	}
	return out
}

// GetResolverState returns a detached copy of the resolver state.
func (v *VaultStore) GetResolverState(resolverName string, force ...bool) (*StoredData, error) {
	if err := v.waitForClientReady(context.Background()); err != nil {
		return nil, err
	}

	storedData, err := v.get(resolverName, force...)
	if err != nil {
		return nil, err
	}

	return deepCopyStoredDataMap(map[string]*StoredData{resolverName: storedData})[resolverName], nil
}

// SaveAccountLocked persists the account while the caller already holds the
// Vault lock. It rewrites the full ACME document from a fresh Vault reload and
// must not reacquire the lock internally.
func (v *VaultStore) SaveAccountLocked(ctx context.Context, resolverName string, account *Account) error {
	return v.saveLocked(ctx, resolverName, func(storedData *StoredData) {
		storedData.Account = cloneAccount(account)
	})
}

// UpsertCertificateLocked updates exactly one certificate entry while the
// caller already holds the Vault lock. It force-reloads Vault state after the
// lock is acquired, rewrites the full ACME document, and returns a detached
// copy of the committed resolver certificate slice.
func (v *VaultStore) UpsertCertificateLocked(ctx context.Context, resolverName string, cert Certificate, tlsStore string) ([]*CertAndStore, error) {
	if v.vaultLock != nil && !v.vaultLock.hasLock(ctx) {
		return nil, errors.New("vault lock must be held before calling UpsertCertificateLocked")
	}

	if _, err := v.get(resolverName, true); err != nil {
		return nil, err
	}

	v.lock.RLock()
	snapshot := deepCopyStoredDataMap(v.storedData)
	v.lock.RUnlock()

	if snapshot == nil {
		snapshot = map[string]*StoredData{}
	}
	if snapshot[resolverName] == nil {
		snapshot[resolverName] = &StoredData{}
	}

	updatedCertificates := cloneCertAndStores(snapshot[resolverName].Certificates)
	certUpdated := false
	for _, domainsCertificate := range updatedCertificates {
		if sameDomain(cert.Domain, domainsCertificate.Certificate.Domain) {
			domainsCertificate.Certificate = cert
			domainsCertificate.Store = tlsStore
			certUpdated = true
			break
		}
	}
	if !certUpdated {
		updatedCertificates = append(updatedCertificates, &CertAndStore{Certificate: cert, Store: tlsStore})
	}

	snapshot[resolverName].Certificates = updatedCertificates
	if err := v.writeSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}

	committedCertificates := cloneCertAndStores(updatedCertificates)

	v.lock.Lock()
	v.storedData = snapshot
	v.lock.Unlock()

	return committedCertificates, nil
}

func (v *VaultStore) doWithLock(ctx context.Context, f func(context.Context) error) error {
	if err := v.waitForLockReady(ctx); err != nil {
		return err
	}
	return v.vaultLock.DoWithLock(ctx, f)
}

func (v *VaultStore) WithResolverLease(ctx context.Context, resolverName string, f func(context.Context, *StoredData) error) error {
	return v.doWithLock(ctx, func(leaseCtx context.Context) error {
		state, err := v.GetResolverState(resolverName, true)
		if err != nil {
			return err
		}
		return f(leaseCtx, state)
	})
}

func (v *VaultStore) IsLocked(ctx context.Context) (bool, error) {
	if err := v.waitForLockReady(ctx); err != nil {
		return false, err
	}
	return v.vaultLock.IsLocked(ctx)
}
