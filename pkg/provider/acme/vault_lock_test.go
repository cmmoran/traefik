package acme

import (
	"context"
	"github.com/hashicorp/vault-client-go"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"os"
	"sync"
	"testing"
	"time"
)

func TestVaultLock(t *testing.T) {
	c := make(chan bool)
	go func() {
		name := "nuc-a"
		client, err := vault.New(vault.WithEnvironment())
		require.NoError(t, err)
		vl, err := newVaultLock(client, "acme/traefik", "test.lock", name, time.Second*10)
		require.NoError(t, err)
		logger := log.Output(os.Stdout).With().Logger()
		ctxA := logger.WithContext(context.Background())
		for {
			select {
			case <-c:
				return
			default:
				wg := new(sync.WaitGroup)
				wg.Add(2)
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxA, func(ctx context.Context) error {
						t.Logf("A: got lock")
						time.Sleep(5 * time.Second)
						return nil
					}); err == nil {
						t.Logf("A...")
					}

				}()
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxA, func(ctx context.Context) error {
						t.Logf("SUB A: got lock")
						time.Sleep(1 * time.Second)
						return nil
					}); err == nil {
						t.Logf("SUB A...")
					}
				}()

				wg.Wait()
				time.Sleep(1 * time.Second)
			}
		}
	}()
	go func() {
		name := "nuc-b"
		client, err := vault.New(vault.WithEnvironment())
		require.NoError(t, err)
		vl, err := newVaultLock(client, "acme/traefik", "test.lock", name, time.Second*10)
		require.NoError(t, err)
		logger := log.Output(os.Stdout).With().Logger()
		ctxB := logger.WithContext(context.Background())
		for {
			select {
			case <-c:
				return
			default:
				wg := new(sync.WaitGroup)
				wg.Add(2)
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxB, func(ctx context.Context) error {
						t.Logf("B: got lock")
						time.Sleep(5 * time.Second)
						return nil
					}); err == nil {
						t.Logf("B...")
					}

				}()
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxB, func(ctx context.Context) error {
						t.Logf("SUB B: got lock")
						time.Sleep(1 * time.Second)
						return nil
					}); err == nil {
						t.Logf("SUB B...")
					}
				}()

				wg.Wait()
				time.Sleep(1 * time.Second)
			}
		}
	}()
	go func() {
		name := "nuc-c"
		client, err := vault.New(vault.WithEnvironment())
		require.NoError(t, err)
		vl, err := newVaultLock(client, "acme/traefik", "test.lock", name, time.Second*10)
		require.NoError(t, err)
		logger := log.Output(os.Stdout).With().Logger()
		ctxC := logger.WithContext(context.Background())
		for {
			select {
			case <-c:
				return
			default:
				wg := new(sync.WaitGroup)
				wg.Add(2)
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxC, func(ctx context.Context) error {
						t.Logf("C: got lock")
						time.Sleep(5 * time.Second)
						return nil
					}); err == nil {
						t.Logf("C...")
					}

				}()
				go func() {
					defer wg.Done()
					if err = vl.DoWithLock(ctxC, func(ctx context.Context) error {
						t.Logf("SUB C: got lock")
						time.Sleep(1 * time.Second)
						return nil
					}); err == nil {
						t.Logf("SUB C...")
					}
				}()

				wg.Wait()
				time.Sleep(1 * time.Second)
			}
		}
	}()
	time.Sleep(1 * time.Minute)
	c <- true
}
