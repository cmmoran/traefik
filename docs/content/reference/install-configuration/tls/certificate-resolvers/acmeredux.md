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

ACME Redux certificate resolvers use the same ACME settings as the standard ACME resolver, but require Vault-backed storage via `vaultStorage`.

| Field | Description | Default | Required |
|:------|:------------|:--------|:---------|
| <a id="opt-acmeRedux-email" href="#opt-acmeRedux-email" title="#opt-acmeRedux-email">`acmeRedux.email`</a> | Email address used for registration. | "" | Yes |
| <a id="opt-acmeRedux-vaultStorage-key" href="#opt-acmeRedux-vaultStorage-key" title="#opt-acmeRedux-vaultStorage-key">`acmeRedux.vaultStorage.key`</a> | Vault storage key used for ACME data. | "acme-redux.json" | Yes |
| <a id="opt-acmeRedux-vaultStorage" href="#opt-acmeRedux-vaultStorage" title="#opt-acmeRedux-vaultStorage">`acmeRedux.vaultStorage`</a> | Vault storage configuration. | - | Yes |

All other ACME options match the standard `acme` resolver.

## Notes

- `acmeRedux` always uses Vault-backed storage. Local file storage is not supported.
- The `vaultStorage.key` value is used as the Vault KV key under `vaultStorage.enginePath`.
