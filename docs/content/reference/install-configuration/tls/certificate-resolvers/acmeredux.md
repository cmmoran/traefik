---
title: "Traefik & ACME Redux Certificates Resolver"
description: "ACME-compatible certificate resolver with Vault-backed storage and locking for multi-instance deployments."
---

## Configuration Example

Below is an example of a basic configuration for ACME Redux in Traefik.

```yaml tab="File (YAML)"
entryPoints:
  web:
    address: ":80"

  websecure:
    address: ":443"

certificatesResolvers:
  myresolver:
    acmeRedux:
      email: your-email@example.com
      vaultStorage:
        url: http://127.0.0.1:8200
        enginePath: acme/traefik
        key: acme-redux
        auth:
          token: your-vault-token
      httpChallenge:
        # used during the challenge
        entryPoint: web
```

```toml tab="File (TOML)"
[entryPoints]
  [entryPoints.web]
    address = ":80"

  [entryPoints.websecure]
    address = ":443"

[certificatesResolvers.myresolver.acmeRedux]
  email = "your-email@example.com"
  [certificatesResolvers.myresolver.acmeRedux.vaultStorage]
    url = "http://127.0.0.1:8200"
    enginePath = "acme/traefik"
    key = "acme-redux"
    [certificatesResolvers.myresolver.acmeRedux.vaultStorage.auth]
      token = "your-vault-token"
  [certificatesResolvers.myresolver.acmeRedux.httpChallenge]
    # used during the challenge
    entryPoint = "web"
```

```bash tab="CLI"
--entryPoints.web.address=:80
--entryPoints.websecure.address=:443
# ...
--certificatesresolvers.myresolver.acmeredux.email=your-email@example.com
--certificatesresolvers.myresolver.acmeredux.vaultstorage.url=http://127.0.0.1:8200
--certificatesresolvers.myresolver.acmeredux.vaultstorage.enginepath=acme/traefik
--certificatesresolvers.myresolver.acmeredux.vaultstorage.key=acme-redux
--certificatesresolvers.myresolver.acmeredux.vaultstorage.auth.token=your-vault-token
# used during the challenge
--certificatesresolvers.myresolver.acmeredux.httpchallenge.entrypoint=web
```

```yaml tab="Helm Chart Values"
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

certificatesResolvers:
  myresolver:
    acmeRedux:
      email: "your-email@example.com"
      vaultStorage:
        url: "http://127.0.0.1:8200"
        enginePath: "acme/traefik"
        key: "acme-redux"
        auth:
          token: "your-vault-token"
      httpChallenge:
        entryPoint: "web"
```

## Configuration Options

ACME Redux certificate resolvers have the following configuration options:

| Field | Description | Default | Required |
|:------|:------------|:--------|:---------|
| <a id="opt-acmeRedux-email" href="#opt-acmeRedux-email" title="#opt-acmeRedux-email">`acmeRedux.email`</a> | Email address used for registration. | "" | Yes |
| <a id="opt-acmeRedux-caServer" href="#opt-acmeRedux-caServer" title="#opt-acmeRedux-caServer">`acmeRedux.caServer`</a> | CA server to use. | https://acme-v02.api.letsencrypt.org/directory | No |
| <a id="opt-acmeRedux-preferredChain" href="#opt-acmeRedux-preferredChain" title="#opt-acmeRedux-preferredChain">`acmeRedux.preferredChain`</a> | Preferred chain to use. | "" | No |
| <a id="opt-acmeRedux-profile" href="#opt-acmeRedux-profile" title="#opt-acmeRedux-profile">`acmeRedux.profile`</a> | Certificate profile to use. | "" | No |
| <a id="opt-acmeRedux-emailAddresses" href="#opt-acmeRedux-emailAddresses" title="#opt-acmeRedux-emailAddresses">`acmeRedux.emailAddresses`</a> | CSR email addresses to use. | [] | No |
| <a id="opt-acmeRedux-disableCommonName" href="#opt-acmeRedux-disableCommonName" title="#opt-acmeRedux-disableCommonName">`acmeRedux.disableCommonName`</a> | Disable common name inside CSR and certificates. | false | No |
| <a id="opt-acmeRedux-keyType" href="#opt-acmeRedux-keyType" title="#opt-acmeRedux-keyType">`acmeRedux.keyType`</a> | KeyType to use. | "RSA4096" | No |
| <a id="opt-acmeRedux-certificatesDuration" href="#opt-acmeRedux-certificatesDuration" title="#opt-acmeRedux-certificatesDuration">`acmeRedux.certificatesDuration`</a> | Certificates duration in hours, used to determine renewal dates. | 2160 | No |
| <a id="opt-acmeRedux-clientTimeout" href="#opt-acmeRedux-clientTimeout" title="#opt-acmeRedux-clientTimeout">`acmeRedux.clientTimeout`</a> | Timeout for a complete HTTP transaction with the ACME server. | 2m | No |
| <a id="opt-acmeRedux-clientResponseHeaderTimeout" href="#opt-acmeRedux-clientResponseHeaderTimeout" title="#opt-acmeRedux-clientResponseHeaderTimeout">`acmeRedux.clientResponseHeaderTimeout`</a> | Timeout for receiving response headers from the ACME server. | 30s | No |
| <a id="opt-acmeRedux-caCertificates" href="#opt-acmeRedux-caCertificates" title="#opt-acmeRedux-caCertificates">`acmeRedux.caCertificates`</a> | Paths to PEM-encoded CA certs used to authenticate an ACME server not in system roots. | [] | No |
| <a id="opt-acmeRedux-caSystemCertPool" href="#opt-acmeRedux-caSystemCertPool" title="#opt-acmeRedux-caSystemCertPool">`acmeRedux.caSystemCertPool`</a> | Define if a copy of the system cert pool is used. | false | No |
| <a id="opt-acmeRedux-caServerName" href="#opt-acmeRedux-caServerName" title="#opt-acmeRedux-caServerName">`acmeRedux.caServerName`</a> | CA server name used for TLS verification when needed. | "" | No |
| <a id="opt-acmeRedux-eab-kid" href="#opt-acmeRedux-eab-kid" title="#opt-acmeRedux-eab-kid">`acmeRedux.eab.kid`</a> | External Account Binding key identifier. | "" | No |
| <a id="opt-acmeRedux-eab-hmacEncoded" href="#opt-acmeRedux-eab-hmacEncoded" title="#opt-acmeRedux-eab-hmacEncoded">`acmeRedux.eab.hmacEncoded`</a> | External Account Binding HMAC key (base64url encoded). | "" | No |
| <a id="opt-acmeRedux-dnsChallenge" href="#opt-acmeRedux-dnsChallenge" title="#opt-acmeRedux-dnsChallenge">`acmeRedux.dnsChallenge`</a> | Activate DNS-01 challenge. | - | No |
| <a id="opt-acmeRedux-dnsChallenge-provider" href="#opt-acmeRedux-dnsChallenge-provider" title="#opt-acmeRedux-dnsChallenge-provider">`acmeRedux.dnsChallenge.provider`</a> | DNS challenge provider. | "" | No |
| <a id="opt-acmeRedux-dnsChallenge-resolvers" href="#opt-acmeRedux-dnsChallenge-resolvers" title="#opt-acmeRedux-dnsChallenge-resolvers">`acmeRedux.dnsChallenge.resolvers`</a> | DNS servers used to resolve the FQDN authority. | [] | No |
| <a id="opt-acmeRedux-dnsChallenge-delayBeforeCheck" href="#opt-acmeRedux-dnsChallenge-delayBeforeCheck" title="#opt-acmeRedux-dnsChallenge-delayBeforeCheck">`acmeRedux.dnsChallenge.delayBeforeCheck`</a> | (Deprecated) Delay before DNS propagation checks. | 0s | No |
| <a id="opt-acmeRedux-dnsChallenge-disablePropagationCheck" href="#opt-acmeRedux-dnsChallenge-disablePropagationCheck" title="#opt-acmeRedux-dnsChallenge-disablePropagationCheck">`acmeRedux.dnsChallenge.disablePropagationCheck`</a> | (Deprecated) Disable DNS propagation checks. | false | No |
| <a id="opt-acmeRedux-dnsChallenge-propagation-delayBeforeChecks" href="#opt-acmeRedux-dnsChallenge-propagation-delayBeforeChecks" title="#opt-acmeRedux-dnsChallenge-propagation-delayBeforeChecks">`acmeRedux.dnsChallenge.propagation.delayBeforeChecks`</a> | Delay before checking TXT record propagation. | 0s | No |
| <a id="opt-acmeRedux-dnsChallenge-propagation-disableChecks" href="#opt-acmeRedux-dnsChallenge-propagation-disableChecks" title="#opt-acmeRedux-dnsChallenge-propagation-disableChecks">`acmeRedux.dnsChallenge.propagation.disableChecks`</a> | Disable TXT propagation checks (not recommended). | false | No |
| <a id="opt-acmeRedux-dnsChallenge-propagation-disableANSChecks" href="#opt-acmeRedux-dnsChallenge-propagation-disableANSChecks" title="#opt-acmeRedux-dnsChallenge-propagation-disableANSChecks">`acmeRedux.dnsChallenge.propagation.disableANSChecks`</a> | Disable checks against authoritative nameservers. | false | No |
| <a id="opt-acmeRedux-dnsChallenge-propagation-requireAllRNS" href="#opt-acmeRedux-dnsChallenge-propagation-requireAllRNS" title="#opt-acmeRedux-dnsChallenge-propagation-requireAllRNS">`acmeRedux.dnsChallenge.propagation.requireAllRNS`</a> | Require TXT propagation on all recursive nameservers. | false | No |
| <a id="opt-acmeRedux-httpChallenge" href="#opt-acmeRedux-httpChallenge" title="#opt-acmeRedux-httpChallenge">`acmeRedux.httpChallenge`</a> | Activate HTTP-01 challenge. | - | No |
| <a id="opt-acmeRedux-httpChallenge-entryPoint" href="#opt-acmeRedux-httpChallenge-entryPoint" title="#opt-acmeRedux-httpChallenge-entryPoint">`acmeRedux.httpChallenge.entryPoint`</a> | EntryPoint used for HTTP-01 challenge. | "" | Yes |
| <a id="opt-acmeRedux-httpChallenge-delay" href="#opt-acmeRedux-httpChallenge-delay" title="#opt-acmeRedux-httpChallenge-delay">`acmeRedux.httpChallenge.delay`</a> | Delay between challenge creation and validation. | 0s | No |
| <a id="opt-acmeRedux-tlsChallenge" href="#opt-acmeRedux-tlsChallenge" title="#opt-acmeRedux-tlsChallenge">`acmeRedux.tlsChallenge`</a> | Activate TLS-ALPN-01 challenge. | - | No |
| <a id="opt-acmeRedux-tlsChallenge-delay" href="#opt-acmeRedux-tlsChallenge-delay" title="#opt-acmeRedux-tlsChallenge-delay">`acmeRedux.tlsChallenge.delay`</a> | Delay between challenge creation and validation. | 0s | No |
| <a id="opt-acmeRedux-vaultStorage" href="#opt-acmeRedux-vaultStorage" title="#opt-acmeRedux-vaultStorage">`acmeRedux.vaultStorage`</a> | Vault storage configuration. | - | Yes |
| <a id="opt-acmeRedux-vaultStorage-url" href="#opt-acmeRedux-vaultStorage-url" title="#opt-acmeRedux-vaultStorage-url">`acmeRedux.vaultStorage.url`</a> | Vault cluster URL. | "http://127.0.0.1:8200" | No |
| <a id="opt-acmeRedux-vaultStorage-namespace" href="#opt-acmeRedux-vaultStorage-namespace" title="#opt-acmeRedux-vaultStorage-namespace">`acmeRedux.vaultStorage.namespace`</a> | Vault namespace. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-enginePath" href="#opt-acmeRedux-vaultStorage-enginePath" title="#opt-acmeRedux-vaultStorage-enginePath">`acmeRedux.vaultStorage.enginePath`</a> | Vault secrets engine path. | "acme/traefik" | No |
| <a id="opt-acmeRedux-vaultStorage-key" href="#opt-acmeRedux-vaultStorage-key" title="#opt-acmeRedux-vaultStorage-key">`acmeRedux.vaultStorage.key`</a> | Vault storage key used for ACME data. | "acme-redux.json" | Yes |
| <a id="opt-acmeRedux-vaultStorage-lockOwnerId" href="#opt-acmeRedux-vaultStorage-lockOwnerId" title="#opt-acmeRedux-vaultStorage-lockOwnerId">`acmeRedux.vaultStorage.lockOwnerId`</a> | Optional owner ID for Vault CAS lock ownership. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-staleLock" href="#opt-acmeRedux-vaultStorage-staleLock" title="#opt-acmeRedux-vaultStorage-staleLock">`acmeRedux.vaultStorage.staleLock`</a> | Expiration duration used for stale Vault CAS locks. | 0s | No |
| <a id="opt-acmeRedux-vaultStorage-tls-caBundle" href="#opt-acmeRedux-vaultStorage-tls-caBundle" title="#opt-acmeRedux-vaultStorage-tls-caBundle">`acmeRedux.vaultStorage.tls.caBundle`</a> | CA bundle path for TLS validation to Vault. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-tls-cert" href="#opt-acmeRedux-vaultStorage-tls-cert" title="#opt-acmeRedux-vaultStorage-tls-cert">`acmeRedux.vaultStorage.tls.cert`</a> | Client certificate path for TLS authentication to Vault. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-tls-key" href="#opt-acmeRedux-vaultStorage-tls-key" title="#opt-acmeRedux-vaultStorage-tls-key">`acmeRedux.vaultStorage.tls.key`</a> | Client key path for TLS authentication to Vault. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-tls-serverName" href="#opt-acmeRedux-vaultStorage-tls-serverName" title="#opt-acmeRedux-vaultStorage-tls-serverName">`acmeRedux.vaultStorage.tls.serverName`</a> | TLS server name override for Vault endpoint verification. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-tls-skipVerify" href="#opt-acmeRedux-vaultStorage-tls-skipVerify" title="#opt-acmeRedux-vaultStorage-tls-skipVerify">`acmeRedux.vaultStorage.tls.skipVerify`</a> | Skip Vault TLS certificate verification. | false | No |
| <a id="opt-acmeRedux-vaultStorage-auth-token" href="#opt-acmeRedux-vaultStorage-auth-token" title="#opt-acmeRedux-vaultStorage-auth-token">`acmeRedux.vaultStorage.auth.token`</a> | Static Vault token authentication. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-appRole-roleID" href="#opt-acmeRedux-vaultStorage-auth-appRole-roleID" title="#opt-acmeRedux-vaultStorage-auth-appRole-roleID">`acmeRedux.vaultStorage.auth.appRole.roleID`</a> | Vault AppRole role ID. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-appRole-secretID" href="#opt-acmeRedux-vaultStorage-auth-appRole-secretID" title="#opt-acmeRedux-vaultStorage-auth-appRole-secretID">`acmeRedux.vaultStorage.auth.appRole.secretID`</a> | Vault AppRole secret ID. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-appRole-enginePath" href="#opt-acmeRedux-vaultStorage-auth-appRole-enginePath" title="#opt-acmeRedux-vaultStorage-auth-appRole-enginePath">`acmeRedux.vaultStorage.auth.appRole.enginePath`</a> | Vault AppRole auth mount path. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-certAuth-name" href="#opt-acmeRedux-vaultStorage-auth-certAuth-name" title="#opt-acmeRedux-vaultStorage-auth-certAuth-name">`acmeRedux.vaultStorage.auth.certAuth.name`</a> | Vault cert auth role name. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-certAuth-enginePath" href="#opt-acmeRedux-vaultStorage-auth-certAuth-enginePath" title="#opt-acmeRedux-vaultStorage-auth-certAuth-enginePath">`acmeRedux.vaultStorage.auth.certAuth.enginePath`</a> | Vault cert auth mount path. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-kubernetes-role" href="#opt-acmeRedux-vaultStorage-auth-kubernetes-role" title="#opt-acmeRedux-vaultStorage-auth-kubernetes-role">`acmeRedux.vaultStorage.auth.kubernetes.role`</a> | Vault Kubernetes auth role. | "" | No |
| <a id="opt-acmeRedux-vaultStorage-auth-kubernetes-enginePath" href="#opt-acmeRedux-vaultStorage-auth-kubernetes-enginePath" title="#opt-acmeRedux-vaultStorage-auth-kubernetes-enginePath">`acmeRedux.vaultStorage.auth.kubernetes.enginePath`</a> | Vault Kubernetes auth mount path. | "" | No |

## Notes

- `acmeRedux` always uses Vault-backed storage. Local file storage is not supported.
- The `vaultStorage.key` value is used as the Vault KV key under `vaultStorage.enginePath`.
