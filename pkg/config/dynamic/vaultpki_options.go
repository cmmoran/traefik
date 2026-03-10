package dynamic

import ptypes "github.com/traefik/paerser/types"

// +k8s:deepcopy-gen=true

// CertResolverOptions defines resolver-specific TLS overrides.
type CertResolverOptions struct {
	VaultPKI *VaultPKIOverrides `json:"vaultPKI,omitempty" toml:"vaultPKI,omitempty" yaml:"vaultPKI,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// VaultPKIOverrides defines override parameters for Vault PKI server certificates.
type VaultPKIOverrides struct {
	CommonName string          `description:"Common Name." json:"commonName,omitempty" toml:"commonName,omitempty" yaml:"commonName,omitempty"`
	AltNames   []string        `description:"Additional DNS SANs." json:"altNames,omitempty" toml:"altNames,omitempty" yaml:"altNames,omitempty"`
	URISans    []string        `description:"URI SANs." json:"uriSans,omitempty" toml:"uriSans,omitempty" yaml:"uriSans,omitempty"`
	TTL        ptypes.Duration `description:"Requested certificate TTL." json:"ttl,omitempty" toml:"ttl,omitempty" yaml:"ttl,omitempty"`
}

// +k8s:deepcopy-gen=true

// ClientCertResolverOptions defines resolver-specific client certificate overrides.
type ClientCertResolverOptions struct {
	VaultPKI *VaultPKIClientOverrides `json:"vaultPKI,omitempty" toml:"vaultPKI,omitempty" yaml:"vaultPKI,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// VaultPKIClientOverrides defines override parameters for Vault PKI client certificates.
type VaultPKIClientOverrides struct {
	CommonName string          `description:"Common Name." json:"commonName,omitempty" toml:"commonName,omitempty" yaml:"commonName,omitempty"`
	AltNames   []string        `description:"Additional DNS SANs." json:"altNames,omitempty" toml:"altNames,omitempty" yaml:"altNames,omitempty"`
	URISans    []string        `description:"URI SANs." json:"uriSans,omitempty" toml:"uriSans,omitempty" yaml:"uriSans,omitempty"`
	TTL        ptypes.Duration `description:"Requested certificate TTL." json:"ttl,omitempty" toml:"ttl,omitempty" yaml:"ttl,omitempty"`
}
