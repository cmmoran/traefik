---
title: "Vault/OpenBao PKI"
description: "Issue TLS certificates via Vault/OpenBao PKI for Traefik routers and mTLS clients."
---

## Overview

The `vaultpki` certificate resolver issues TLS certificates by calling the Vault/OpenBao PKI API.
It can be used in two modes:

- `vaultPKIServer`: issue certificates for routers (Traefik listening side).
- `vaultPKIClient`: issue certificates for upstream mTLS (Traefik client side).

## Static Configuration

```yaml tab="Structured (YAML)"
certificatesResolvers:
  vaultresolver:
    vaultPKIServer:
      url: "https://vault.example.internal"
      pkiPath: "pki"
      role: "traefik-server"
      auth:
        token: "${VAULT_TOKEN}"
      issue:
        ttl: "24h"
      renewBefore: "6h"
      cacheDir: "/etc/traefik/pki"

    vaultPKIClient:
      url: "https://vault.example.internal"
      pkiPath: "pki"
      role: "traefik-client"
      auth:
        token: "${VAULT_TOKEN}"
      issue:
        ttl: "12h"
      renewBefore: "3h"
      cacheDir: "/etc/traefik/pki"
```

```toml tab="Structured (TOML)"
[certificatesResolvers.vaultresolver.vaultPKIServer]
  url = "https://vault.example.internal"
  pkiPath = "pki"
  role = "traefik-server"
  renewBefore = "6h"
  cacheDir = "/etc/traefik/pki"

  [certificatesResolvers.vaultresolver.vaultPKIServer.auth]
    token = "${VAULT_TOKEN}"

  [certificatesResolvers.vaultresolver.vaultPKIServer.issue]
    ttl = "24h"

[certificatesResolvers.vaultresolver.vaultPKIClient]
  url = "https://vault.example.internal"
  pkiPath = "pki"
  role = "traefik-client"
  renewBefore = "3h"
  cacheDir = "/etc/traefik/pki"

  [certificatesResolvers.vaultresolver.vaultPKIClient.auth]
    token = "${VAULT_TOKEN}"

  [certificatesResolvers.vaultresolver.vaultPKIClient.issue]
    ttl = "12h"
```

## Router Overrides

Use `tls.certResolverOptions.vaultPKI` to override Vault PKI issue parameters per router.
This is useful for URI SANs or custom TTLs.

```yaml tab="HTTP Router (YAML)"
http:
  routers:
    api:
      rule: "Host(`api.example.internal`)"
      service: "api"
      tls:
        certResolver: "vaultresolver"
        certResolverOptions:
          vaultPKI:
            uriSans:
              - "spiffe://prod/stack-a/api"
            ttl: "8h"
```

```yaml tab="TCP Router (YAML)"
tcp:
  routers:
    db:
      rule: "HostSNI(`db.example.internal`)"
      service: "db"
      tls:
        certResolver: "vaultresolver"
        certResolverOptions:
          vaultPKI:
            uriSans:
              - "spiffe://prod/stack-b/db"
            ttl: "4h"
```

```toml tab="HTTP Router (TOML)"
[http.routers.api]
  rule = "Host(`api.example.internal`)"
  service = "api"

  [http.routers.api.tls]
    certResolver = "vaultresolver"

    [http.routers.api.tls.certResolverOptions.vaultPKI]
      uriSans = ["spiffe://prod/stack-a/api"]
      ttl = "8h"
```

```toml tab="TCP Router (TOML)"
[tcp.routers.db]
  rule = "HostSNI(`db.example.internal`)"
  service = "db"

  [tcp.routers.db.tls]
    certResolver = "vaultresolver"

    [tcp.routers.db.tls.certResolverOptions.vaultPKI]
      uriSans = ["spiffe://prod/stack-b/db"]
      ttl = "4h"
```

## Client Certificate Resolver

Use `serversTransports.clientCertResolver` and `serversTransports.clientCertResolverOptions` to issue client certificates.
For Vault/OpenBao PKI, set `clientCertResolver` to `vaultpki` and provide overrides under `clientCertResolverOptions.vaultPKI`.

```yaml tab="Dynamic (YAML)"
http:
  serversTransports:
    vault-mtls:
      clientCertResolver: "vaultpki"
      clientCertResolverOptions:
        vaultPKI:
          uriSans:
            - "spiffe://prod/stack-a/client"
          ttl: "2h"
```

```toml tab="Dynamic (TOML)"
[http.serversTransports.vault-mtls]
  clientCertResolver = "vaultpki"

  [http.serversTransports.vault-mtls.clientCertResolverOptions.vaultPKI]
    uriSans = ["spiffe://prod/stack-a/client"]
    ttl = "2h"
```
