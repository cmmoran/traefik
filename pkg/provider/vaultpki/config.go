package vaultpki

import (
	"strings"

	ptypes "github.com/traefik/paerser/types"
)

// Configuration defines a Vault/OpenBao PKI resolver for client certificates.
type Configuration struct {
	URL         string          `description:"Vault/OpenBao URL" json:"url,omitempty" toml:"url,omitempty" yaml:"url,omitempty"`
	TLS         *TLSConfig      `description:"TLS settings for Vault/OpenBao" json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`
	Namespace   string          `description:"Vault namespace" json:"namespace,omitempty" toml:"namespace,omitempty" yaml:"namespace,omitempty"`
	PKIPath     string          `description:"PKI mount path" json:"pkiPath,omitempty" toml:"pkiPath,omitempty" yaml:"pkiPath,omitempty"`
	Role        string          `description:"PKI role name" json:"role,omitempty" toml:"role,omitempty" yaml:"role,omitempty"`
	Auth        *AuthConfig     `description:"Auth configuration" json:"auth,omitempty" toml:"auth,omitempty" yaml:"auth,omitempty"`
	Issue       *IssueConfig    `description:"Default issue parameters" json:"issue,omitempty" toml:"issue,omitempty" yaml:"issue,omitempty"`
	RenewBefore ptypes.Duration `description:"Renew certificate before expiration" json:"renewBefore,omitempty" toml:"renewBefore,omitempty" yaml:"renewBefore,omitempty"`
	CacheDir    string          `description:"Directory to cache issued certificates" json:"cacheDir,omitempty" toml:"cacheDir,omitempty" yaml:"cacheDir,omitempty"`
}

// IssueConfig controls client certificate issuance parameters.
type IssueConfig struct {
	CommonName string          `description:"Common Name" json:"commonName,omitempty" toml:"commonName,omitempty" yaml:"commonName,omitempty"`
	AltNames   []string        `description:"Additional DNS SANs" json:"altNames,omitempty" toml:"altNames,omitempty" yaml:"altNames,omitempty"`
	URISans    []string        `description:"URI SANs" json:"uriSans,omitempty" toml:"uriSans,omitempty" yaml:"uriSans,omitempty"`
	TTL        ptypes.Duration `description:"Requested certificate TTL" json:"ttl,omitempty" toml:"ttl,omitempty" yaml:"ttl,omitempty"`
}

// AuthConfig controls Vault/OpenBao authentication.
type AuthConfig struct {
	Token    string          `description:"Static token" json:"token,omitempty" toml:"token,omitempty" yaml:"token,omitempty"`
	CertAuth *CertAuthConfig `description:"Certificate auth" json:"certAuth,omitempty" toml:"certAuth,omitempty" yaml:"certAuth,omitempty"`
	AppRole  *AppRoleConfig  `description:"AppRole auth" json:"appRole,omitempty" toml:"appRole,omitempty" yaml:"appRole,omitempty"`
}

// CertAuthConfig defines certificate auth parameters.
type CertAuthConfig struct {
	Name       string `description:"Cert auth role name" json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty"`
	EnginePath string `description:"Auth mount path" json:"enginePath,omitempty" toml:"enginePath,omitempty" yaml:"enginePath,omitempty"`
}

// AppRoleConfig defines AppRole auth parameters.
type AppRoleConfig struct {
	RoleID     string `description:"Role ID" json:"roleID,omitempty" toml:"roleID,omitempty" yaml:"roleID,omitempty"`
	SecretID   string `description:"Secret ID" json:"secretID,omitempty" toml:"secretID,omitempty" yaml:"secretID,omitempty"`
	EnginePath string `description:"Auth mount path" json:"enginePath,omitempty" toml:"enginePath,omitempty" yaml:"enginePath,omitempty"`
}

// TLSConfig defines TLS settings for Vault/OpenBao.
type TLSConfig struct {
	CABundle   string `description:"CA bundle path" json:"caBundle,omitempty" toml:"caBundle,omitempty" yaml:"caBundle,omitempty"`
	Cert       string `description:"Client cert path" json:"cert,omitempty" toml:"cert,omitempty" yaml:"cert,omitempty"`
	Key        string `description:"Client key path" json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
	SkipVerify bool   `description:"Skip TLS verification" json:"skipVerify,omitempty" toml:"skipVerify,omitempty" yaml:"skipVerify,omitempty"`
	ServerName string `description:"Override server name" json:"serverName,omitempty" toml:"serverName,omitempty" yaml:"serverName,omitempty"`
}

func (c *Configuration) SetDefaults() {
	if c.PKIPath == "" {
		c.PKIPath = "pki"
	}
	if c.CacheDir == "" {
		c.CacheDir = "/etc/traefik/pki"
	}
	if c.Issue == nil {
		c.Issue = &IssueConfig{}
	}
}

func (c *Configuration) CacheFileBase(resolverName string, issue IssueConfig) string {
	base := "default"
	if issue.CommonName != "" {
		base = issue.CommonName
	}
	base = strings.ReplaceAll(base, "/", "_")
	return resolverName + "." + base + ".pem"
}
