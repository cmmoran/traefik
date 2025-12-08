//go:build integration
// +build integration

package acmeredux

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultLock(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" && os.Getenv("BAO_ADDR") == "" {
		t.Skip("requires Vault/OpenBao; set VAULT_ADDR or BAO_ADDR to run")
	}
	if os.Getenv("VAULT_TOKEN") == "" && os.Getenv("BAO_TOKEN") == "" {
		t.Skip("requires Vault/OpenBao token; set VAULT_TOKEN or BAO_TOKEN to run")
	}

	cleanupClient, err := vault.New(vault.WithEnvironment())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = cleanupClient.Secrets.KvV2DeleteMetadataAndAllVersions(
			context.Background(),
			"test.lock",
			vault.WithMountPath("acme/traefik"),
		)
	})

	client, err := vault.New(vault.WithEnvironment())
	require.NoError(t, err)
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		require.NoError(t, client.SetToken(token))
	} else if token := os.Getenv("BAO_TOKEN"); token != "" {
		require.NoError(t, client.SetToken(token))
	}

	logger := log.Output(os.Stdout).With().Logger()
	ctx := logger.WithContext(context.Background())

	vlA, err := newVaultLock(client, "acme/traefik", "test.lock", "owner-a", 10*time.Second)
	require.NoError(t, err)
	vlB, err := newVaultLock(client, "acme/traefik", "test.lock", "owner-b", 10*time.Second)
	require.NoError(t, err)

	t.Run("exclusive lock", func(t *testing.T) {
		var active int32
		var maxActive int32
		var errCount int32
		start := make(chan struct{})
		wg := new(sync.WaitGroup)

		worker := func(vl *vaultLock) {
			defer wg.Done()
			<-start
			for i := 0; i < 5; i++ {
				err := vl.DoWithLock(ctx, func(ctx context.Context) error {
					now := atomic.AddInt32(&active, 1)
					for {
						prev := atomic.LoadInt32(&maxActive)
						if now <= prev || atomic.CompareAndSwapInt32(&maxActive, prev, now) {
							break
						}
					}
					time.Sleep(50 * time.Millisecond)
					atomic.AddInt32(&active, -1)
					return nil
				})
				if err != nil {
					if errors.Is(err, ErrLockHeld) {
						atomic.AddInt32(&errCount, 1)
					} else {
						t.Errorf("unexpected error: %v", err)
					}
				}
			}
		}

		wg.Add(2)
		go worker(vlA)
		go worker(vlB)
		close(start)
		wg.Wait()

		assert.Equal(t, int32(1), atomic.LoadInt32(&maxActive))
	})

	t.Run("non-stale lock blocks", func(t *testing.T) {
		require.NoError(t, writeLockPayload(ctx, client, "acme/traefik", "test.lock", lockPayload{
			Locked:    true,
			Owner:     "other",
			Timestamp: time.Now().Unix(),
		}))

		err := vlA.DoWithLock(ctx, func(ctx context.Context) error {
			return nil
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLockHeld))
	})

	t.Run("stale lock is reclaimed", func(t *testing.T) {
		staleAfter := 1 * time.Second
		vlStale, err := newVaultLock(client, "acme/traefik", "test.lock", "owner-stale", staleAfter)
		require.NoError(t, err)

		require.NoError(t, writeLockPayload(ctx, client, "acme/traefik", "test.lock", lockPayload{
			Locked:    true,
			Owner:     "other",
			Timestamp: time.Now().Add(-3 * staleAfter).Unix(),
		}))

		var called bool
		require.NoError(t, vlStale.DoWithLock(ctx, func(ctx context.Context) error {
			called = true
			return nil
		}))
		assert.True(t, called)
	})
}

func writeLockPayload(ctx context.Context, client *vault.Client, mountPath, key string, payload lockPayload) error {
	version := int32(0)
	resp, err := client.Secrets.KvV2Read(ctx, key, vault.WithMountPath(mountPath))
	if err != nil {
		if !vault.IsErrorStatus(err, http.StatusNotFound) {
			return err
		}
	} else {
		version, err = extractVersion(resp.Data.Metadata)
		if err != nil {
			return err
		}
	}

	_, err = client.Secrets.KvV2Write(ctx, key, schema.KvV2WriteRequest{
		Data: map[string]interface{}{
			"locked":    payload.Locked,
			"owner":     payload.Owner,
			"timestamp": payload.Timestamp,
		},
		Options: map[string]interface{}{
			"cas": version,
		},
		Version: version,
	}, vault.WithMountPath(mountPath))
	return err
}
