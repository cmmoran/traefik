package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/hashicorp/vault-client-go/schema"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault-client-go"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
)

var _ Store = (*VaultStore)(nil)

// VaultStore Stores implementation for vault storage.
type VaultStore struct {
	saveDataChan chan map[string]*StoredData
	vaultConfig  *VaultConfig
	client       *vault.Client
	filename     string

	lock       sync.RWMutex
	storedData map[string]*StoredData
}

// NewVaultStore initializes a new VaultStore with a vault.
func NewVaultStore(filename string, config *VaultConfig) *VaultStore {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()
	found := true
	for strings.HasPrefix(filename, "/") && found {
		filename, found = strings.CutPrefix(filename, "/")
	}
	store := &VaultStore{
		saveDataChan: make(chan map[string]*StoredData),
		vaultConfig:  config,
		filename:     filename,
	}
	logger.Info().Msgf("Created VaultStore mountpath=%s filename=%s", store.vaultConfig.EnginePath, store.filename)
	store.Init()
	store.listenSaveAction()
	return store
}

// listenSaveAction listens to a chan to store ACME data in vault in json format into `VaultStore.VaultConfig.url`.
func (v *VaultStore) listenSaveAction() {
	safe.Go(func() {
		logger := log.With().Str(logs.ProviderName, "acme").Logger()

		var (
			err  error
			data []byte
			resp *vault.Response[schema.KvV2WriteResponse]
		)
		for object := range v.saveDataChan {
			data, err = json.Marshal(object)
			if err != nil {
				logger.Error().Err(err).Send()
			}

			resp, err = v.client.Secrets.KvV2Write(context.Background(), v.filename, schema.KvV2WriteRequest{
				Data: map[string]any{
					"data": data,
				},
			}, vault.WithMountPath(v.vaultConfig.EnginePath))
			if err != nil {
				logger.Error().Err(err).Send()
			}

			logger.Info().Msgf("Wrote acme json with requestID: %v", resp.RequestID)
		}
	})
}

func (v *VaultStore) Init() {
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
	v.client, _ = vault.New(vault.WithAddress(v.vaultConfig.Url), vault.WithTLS(tlsConfig))

	if len(v.vaultConfig.Namespace) > 0 {
		if err := v.client.SetNamespace(v.vaultConfig.Namespace); err != nil {
			log.Error().Msgf("Error setting namespace=%s", v.vaultConfig.Namespace)
		}
	}
	switch {
	case len(v.vaultConfig.Auth.Token) > 0:
		var (
			err error
		)
		if err = v.client.SetToken(v.vaultConfig.Auth.Token); err != nil {
			log.Error().Err(err).Msg("Error setting client token from vault")
		} else {
			log.Info().Msg("Vault Token set! Checking certificate storage")
			hasData, data, cerr := v.checkVault()
			if hasData {
				log.Info().Msgf("Vault storage has certificate(s): cert: len(data) == %d", len(data))
			} else {
				if cerr != nil {
					log.Error().Err(err).Msg("Vault storage has no certificate (error)")
				} else {
					log.Error().Err(err).Msg("Vault storage has no certificate")
				}
			}
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
		if resp, err = v.client.Auth.CertLogin(context.Background(), schema.CertLoginRequest{
			Name: v.vaultConfig.Auth.CertAuth.Name,
		}, ro...); err != nil {
			log.Error().Err(err).Msg("Vault Login, err")
			return
		} else {
			log.Info().Msg("Vault Login, no err")
			if resp.Auth != nil {
				if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
					log.Error().Err(err).Msg("Error setting client token from vault")
				} else {
					log.Info().Msg("Vault Token set! Checking certificate storage")
					hasData, data, cerr := v.checkVault()
					if hasData {
						log.Info().Msgf("Vault storage has certificate(s): cert: len(data) == %d", len(data))
					} else {
						if cerr != nil {
							log.Error().Msgf("Vault storage has no certificate (error=%v)", err)
						} else {
							log.Error().Err(err).Msg("Vault storage has no certificate")
						}
					}
				}
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
		if resp, err = v.client.Auth.AppRoleLogin(context.Background(), schema.AppRoleLoginRequest{
			RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
			SecretId: v.vaultConfig.Auth.AppRole.SecretID,
		}, ro...); err != nil {
			if terr := v.client.SetToken(v.vaultConfig.Auth.AppRole.SecretID); terr != nil {
				return
			}
			if unwrappResponse, uerr := v.client.System.Unwrap(context.Background(), schema.UnwrapRequest{}); uerr != nil {
				return
			} else {
				unwrappedSecretId := unwrappResponse.Data["secret_id"].(string)
				if resp, err = v.client.Auth.AppRoleLogin(context.Background(), schema.AppRoleLoginRequest{
					RoleId:   v.vaultConfig.Auth.AppRole.RoleID,
					SecretId: unwrappedSecretId,
				}, ro...); err != nil {
					return
				} else {
					log.Info().Msg("Vault AppRole Login, no err")
				}
				// Update client token
				if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
					if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
						return
					}
				}
			}
		} else {
			log.Info().Msg("Vault AppRole Login, no err")
		}
		// Update client token
		if resp != nil && resp.Auth != nil && len(resp.Auth.ClientToken) != 0 {
			if err = v.client.SetToken(resp.Auth.ClientToken); err != nil {
				log.Error().Err(err).Msg("Error setting client token from vault")
				return
			} else {
				log.Info().Msg("Vault AppRole Token set! Checking certificate storage")
				hasData, data, cerr := v.checkVault()
				if hasData {
					log.Info().Msgf("Vault storage has certificate(s): cert: len(data) == %d", len(data))
				} else {
					if cerr != nil {
						log.Error().Msgf("Vault storage has no certificate (error=%v)", err)
					} else {
						log.Error().Err(err).Msg("Vault storage has no certificate")
					}
				}
			}
		}
	}
}

func (v *VaultStore) save(resolverName string, storedData *StoredData) {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.storedData[resolverName] = storedData

	// we cannot pass v.storedData directly, map is reference type and as result
	// we can face with race condition, so we need to work with objects copy
	v.saveDataChan <- v.unSafeCopyOfStoredData()
}

func (v *VaultStore) checkVault() (bool, []byte, error) {
	log.Info().Msgf("Checking Vault for certificate filename[%s] mount[%s]", v.filename, v.vaultConfig.EnginePath)
	if resp, err := v.client.Secrets.KvV2Read(context.Background(), v.filename, vault.WithMountPath(v.vaultConfig.EnginePath)); err != nil {
		if vault.IsErrorStatus(err, http.StatusNotFound) {
			if _, err = v.client.Secrets.KvV2Write(context.Background(), v.filename, schema.KvV2WriteRequest{
				Data: map[string]interface{}{
					"data": &StoredData{
						Account:      nil,
						Certificates: make([]*CertAndStore, 0),
					},
				},
			}, vault.WithMountPath(v.vaultConfig.EnginePath)); err != nil {
				return false, nil, err
			} else {
				// created and saved an empty *StoredData to vault
				return false, nil, nil
			}
		}
		log.Error().Msgf("Error while checking Vault for certificate filename[%s] mount[%s], err=%v", v.filename, v.vaultConfig.EnginePath, err)
		return false, nil, err
	} else {
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
	}

	return false, nil, nil
}

func (v *VaultStore) get(resolverName string) (*StoredData, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.storedData == nil {
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
			var certificates []*CertAndStore
			for _, storedData := range v.storedData {
				for _, certificate := range storedData.Certificates {
					if len(certificate.Certificate.Certificate) == 0 || len(certificate.Key) == 0 {
						logger.Debug().Msgf("Deleting empty certificate %v for %v", certificate, certificate.Domain.ToStrArray())
						continue
					}
					certificates = append(certificates, certificate)
				}
				if len(certificates) < len(storedData.Certificates) {
					storedData.Certificates = certificates

					// we cannot pass v.storedData directly, map is reference type and as result
					// we can face with race condition, so we need to work with objects copy
					v.saveDataChan <- v.unSafeCopyOfStoredData()
				}
			}
		}
	}

	if v.storedData[resolverName] == nil {
		v.storedData[resolverName] = &StoredData{}
	}
	return v.storedData[resolverName], nil
}

// unSafeCopyOfStoredData creates maps copy of storedData. Is not thread safe, you should use `s.lock`.
func (v *VaultStore) unSafeCopyOfStoredData() map[string]*StoredData {
	result := map[string]*StoredData{}
	for k, val := range v.storedData {
		result[k] = val
	}
	return result
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
func (v *VaultStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	storedData, err := v.get(resolverName)
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
