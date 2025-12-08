---
title: "Traefik APIKey Documentation"
description: "The APIKey middleware in Traefik Proxy secures HTTP routes by requiring a valid API key. Read the technical documentation."
---

# APIKey

Adding API Key Authentication
{: .subtitle }

The APIKey middleware grants access to services only when a valid API key is provided.
Keys can be sent via a header, a query parameter, or a cookie.

## Configuration Examples

!!! note ""

    When using Docker labels, `$` must be escaped as `$$`.

```yaml tab="Docker & Swarm"
labels:
  - "traefik.http.middlewares.test-apikey.apikey.keysource.header=Authorization"
  - "traefik.http.middlewares.test-apikey.apikey.keysource.headerauthscheme=Bearer"
  - "traefik.http.middlewares.test-apikey.apikey.secretnonbase64encoded=true"
  - "traefik.http.middlewares.test-apikey.apikey.secretvalues=$$2y$$05$$D4SPFxzfWKcx1OXfVhRbvOTH/QB0Lm6AXTk8.NOmU4rPLX2t6UUuW,$$2y$$05$$HbLL.g5dUqJippH0RuAGL.RaM9wNS2cT7hp6.vbv5okdCmVBSDzzK"
```

```yaml tab="Kubernetes"
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: test-apikey
spec:
  apiKey:
    keySource:
      headerAuthScheme: Bearer
      header: Authorization
    secretNonBase64Encoded: true
    secretValues:
      - "urn:k8s:secret:apikey:secret"
      - "urn:k8s:secret:apikey:othersecret"
---
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: apikey
stringData:
  secret: $2y$05$D4SPFxzfWKcx1OXfVhRbvOTH/QB0Lm6AXTk8.NOmU4rPLX2t6UUuW
  othersecret: $2y$05$HbLL.g5dUqJippH0RuAGL.RaM9wNS2cT7hp6.vbv5okdCmVBSDzzK
```

```yaml tab="Consul Catalog"
- "traefik.http.middlewares.test-apikey.apikey.keysource.header=Authorization"
- "traefik.http.middlewares.test-apikey.apikey.keysource.headerauthscheme=Bearer"
- "traefik.http.middlewares.test-apikey.apikey.secretnonbase64encoded=true"
- "traefik.http.middlewares.test-apikey.apikey.secretvalues=$2y$05$D4SPFxzfWKcx1OXfVhRbvOTH/QB0Lm6AXTk8.NOmU4rPLX2t6UUuW,$2y$05$HbLL.g5dUqJippH0RuAGL.RaM9wNS2cT7hp6.vbv5okdCmVBSDzzK"
```

```yaml tab="File (YAML)"
http:
  middlewares:
    test-apikey:
      apiKey:
        keySource:
          headerAuthScheme: Bearer
          header: Authorization
        secretNonBase64Encoded: true
        secretValues:
          - "$2y$05$D4SPFxzfWKcx1OXfVhRbvOTH/QB0Lm6AXTk8.NOmU4rPLX2t6UUuW"
          - "$2y$05$HbLL.g5dUqJippH0RuAGL.RaM9wNS2cT7hp6.vbv5okdCmVBSDzzK"
          - "file:///run/secrets/traefik-apikey"
```

```toml tab="File (TOML)"
[http.middlewares]
  [http.middlewares.test-apikey.apiKey]
    secretNonBase64Encoded = true
    secretValues = ["$2y$05$D4SPFxzfWKcx1OXfVhRbvOTH/QB0Lm6AXTk8.NOmU4rPLX2t6UUuW", "$2y$05$HbLL.g5dUqJippH0RuAGL.RaM9wNS2cT7hp6.vbv5okdCmVBSDzzK"]
    [http.middlewares.test-apikey.apiKey.keySource]
      headerAuthScheme = "Bearer"
      header = "Authorization"
```

## Configuration Options

### `keySource.header`

Defines the header name containing the secret sent by the client.

### `keySource.headerAuthScheme`

Defines the scheme when using `Authorization` as the header name.
For example, `Authorization: Bearer <token>`.

### `keySource.query`

Defines the query parameter name containing the secret sent by the client.

### `keySource.cookie`

Defines the cookie name containing the secret sent by the client.

!!! note ""

    One of `keySource.header`, `keySource.query`, or `keySource.cookie` must be set.
    Only one source can be configured at a time.

### `secretNonBase64Encoded`

Defines whether the secret sent by the client is base64 encoded.
When `false`, the middleware base64-decodes the client value before verification.

### `secretValues`

Contains the hash of the API keys.
Supported hashing algorithms are Bcrypt, SHA1 and MD5.
The hash should be generated using `htpasswd`.

Values may reference a file path (for example: `/run/secrets/traefik-apikey`) or use the `file://` prefix.
Each non-empty line in the file is treated as a secret value.

For Kubernetes, values may reference a Secret using the URN format:
`urn:k8s:secret:[name]:[valueKey]`.
