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
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/types"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/rs/zerolog/log"

	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
)

var _ Store = (*VaultStore)(nil)

// VaultStore Stores implementation for vault storage.
type VaultStore struct {
	saveDataChan chan map[string]*StoredData
	vaultConfig  *VaultConfig
	client       *vault.Client
	filename     string
	vaultLock    *vaultLock

	lock       sync.RWMutex
	storedData map[string]*StoredData
}

// NewVaultStore initializes a new VaultStore with a vault.
func NewVaultStore(filename string, config *VaultConfig, routinesPool *safe.Pool) *VaultStore {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	found := true
	for strings.HasPrefix(filename, "/") && found {
		filename, found = strings.CutPrefix(filename, "/")
	}
	store := &VaultStore{
		saveDataChan: make(chan map[string]*StoredData, 1),
		vaultConfig:  config,
		filename:     filename,
	}
	logger.Info().Msgf("Created VaultStore mountpath=%s filename=%s", store.vaultConfig.EnginePath, store.filename)
	store.Init()
	store.listenSaveAction(routinesPool)
	return store
}

func (v *VaultStore) Init() {
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
	var err error
	v.client, err = vault.New(vault.WithAddress(v.vaultConfig.Url), vault.WithTLS(tlsConfig))
	if err != nil {
		logger.Error().Err(err).Msg("Error creating vault client")
		return
	}

	if len(v.vaultConfig.Namespace) > 0 {
		if err := v.client.SetNamespace(v.vaultConfig.Namespace); err != nil {
			logger.Error().Msgf("Error setting namespace=%s", v.vaultConfig.Namespace)
		}
	}
	ctx := context.Background()
	switch {
	case len(v.vaultConfig.Auth.Token) > 0:
		var (
			err error
		)
		if err = v.client.SetToken(v.vaultConfig.Auth.Token); err != nil {
			logger.Error().Err(err).Msg("Error setting client token from vault")
		} else {
			logger.Info().Msg("Vault Token set! Checking certificate storage")
			v.checkVaultStorage()
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
		if resp, err = v.client.Auth.CertLogin(ctx, schema.CertLoginRequest{
			Name: v.vaultConfig.Auth.CertAuth.Name,
		}, ro...); err != nil {
			logger.Error().Err(err).Msg("Vault Login, err")
			return
		}

		logger.Info().Msg("Vault Login, no err")
		if resp.Auth != nil {
			if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
				logger.Error().Err(err).Msg("Error setting client token from vault")
			} else {
				logger.Info().Msg("Vault Token set! Checking certificate storage")
				v.checkVaultStorage()
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
		if resp, err = v.client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
			RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
			SecretId: v.vaultConfig.Auth.AppRole.SecretID,
		}, ro...); err != nil {
			if terr := v.client.SetToken(v.vaultConfig.Auth.AppRole.SecretID); terr != nil {
				return
			}
			unwrappResponse, uerr := v.client.System.Unwrap(ctx, schema.UnwrapRequest{})
			if uerr != nil {
				return
			}
			unwrappedSecretId := unwrappResponse.Data["secret_id"].(string)
			if resp, err = v.client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
				RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
				SecretId: unwrappedSecretId,
			}, ro...); err != nil {
				return
			}

			logger.Info().Msg("Vault AppRole Login, no err")
			// Update client token
			if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
				if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
					return
				}
			}
		} else {
			logger.Info().Msg("Vault AppRole Login, no err")
		}
		// Update client token
		if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
			if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
				logger.Error().Err(err).Msg("Error setting client token from vault")
				return
			}

			logger.Info().Msg("Vault AppRole Token set! Checking certificate storage")
			v.checkVaultStorage()
		}
	}
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

	if vl, err := newVaultLock(
		v.client,
		v.vaultConfig.EnginePath,
		fmt.Sprintf("%s.lock", v.filename),
		v.vaultConfig.LockOwnerId,
		time.Duration(v.vaultConfig.StaleLock),
	); err != nil {
		logger.Warn().Msg("Vault lock is not initialized, not locking store")
	} else {
		v.vaultLock = vl
	}
}

func (v *VaultStore) save(resolverName string, storedData *StoredData) {
	v.lock.Lock()

	v.storedData[resolverName] = storedData

	// we cannot pass v.storedData directly, map is reference type and as result
	// we can face with race condition, so we need to work with objects copy
	snapshot := deepCopyStoredDataMap(v.storedData)
	v.lock.Unlock()
	v.enqueueSave(snapshot)
}

// listenSaveAction listens to a chan to store ACME data in vault in json format into `VaultStore.VaultConfig.url`.
func (v *VaultStore) listenSaveAction(routinesPool *safe.Pool) {
	routinesPool.GoCtx(func(ctx context.Context) {
		logger := log.With().Str(logs.ProviderName, "acme").Logger()

		for {
			select {
			case <-ctx.Done():
				return
			case object := <-v.saveDataChan:
				select {
				case <-ctx.Done():
					return
				default:
				}
				data, err := json.Marshal(object)
				if err != nil {
					logger.Error().Err(err).Send()
					continue
				}

				for {
					if ctx.Err() != nil {
						return
					}

					err = v.DoWithLock(ctx, func(ctx context.Context) error {
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

						logger.Info().Msgf("Wrote acme json with requestID: %v", wresp.RequestID)
						return nil
					})
					if err == nil {
						break
					}
					if errors.Is(err, ErrLockHeld) {
						logger.Debug().Msg("Vault lock is held by another instance, retrying")
					} else {
						logger.Error().Err(err).Msg("Failed to write acme data to Vault, retrying")
					}

					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}

			}
		}
	})
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
			writeErr := v.DoWithLock(ctx, func(ctx context.Context) error {
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
			var changed = false
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
				logger.Debug().Msgf("certificates have changed, persisting changes")
				snapshot := deepCopyStoredDataMap(v.storedData)
				v.enqueueSave(snapshot)
			}
		}
	}

	if v.storedData[resolverName] == nil {
		v.storedData[resolverName] = &StoredData{}
	}
	return v.storedData[resolverName], nil
}

// unSafeCopyOfStoredData creates maps copy of storedData. Is not thread safe, you should use `s.lock`.
func (v *VaultStore) enqueueSave(snapshot map[string]*StoredData) {
	select {
	case v.saveDataChan <- snapshot:
		return
	default:
	}

	select {
	case <-v.saveDataChan:
	default:
	}

	select {
	case v.saveDataChan <- snapshot:
	default:
	}
}

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

// GetAccount returns ACME Account.
func (v *VaultStore) GetAccount(resolverName string) (*Account, error) {
	storedData, err := v.get(resolverName)
	if err != nil {
		return nil, err
	}

	return storedData.Account, nil

}

// SaveAccount stores ACME Account.
func (v *VaultStore) SaveAccount(resolverName string, account *Account) error {
	storedData, err := v.get(resolverName)
	if err != nil {
		return err
	}

	storedData.Account = account
	v.save(resolverName, storedData)

	return nil
}

// GetCertificates returns ACME Certificates list.
func (v *VaultStore) GetCertificates(resolverName string, force ...bool) ([]*CertAndStore, error) {
	storedData, err := v.get(resolverName, force...)
	if err != nil {
		return nil, err
	}

	return storedData.Certificates, nil
}

// SaveCertificates stores ACME Certificates list.
func (v *VaultStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	storedData, err := v.get(resolverName)
	if err != nil {
		return err
	}

	storedData.Certificates = certificates
	v.save(resolverName, storedData)

	return nil
}

func (v *VaultStore) DoWithLock(ctx context.Context, f func(context.Context) error) error {
	if v.vaultLock == nil {
		logger := log.Ctx(ctx).With().Str(logs.ProviderName, "acme").Logger()
		logger.Warn().Msg("Vault lock is not initialized, not locking store")
		return f(ctx)
	}
	return v.vaultLock.DoWithLock(ctx, f)
}

func (v *VaultStore) IsLocked(ctx context.Context) (bool, error) {
	if v.vaultLock == nil {
		logger := log.Ctx(ctx).With().Str(logs.ProviderName, "acme").Logger()
		logger.Warn().Msg("Vault lock is not initialized, store cannot be locked")
		return false, nil
	}
	return v.vaultLock.IsLocked(ctx)
}
