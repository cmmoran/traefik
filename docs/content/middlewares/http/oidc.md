---
title: "Traefik OIDC Documentation"
description: "The OIDC middleware in Traefik Proxy secures HTTP routes by delegating authentication to an OpenID Connect provider."
---

# OIDC

OpenID Connect Authentication
{: .subtitle }

The OIDC middleware secures your applications by delegating authentication to an OpenID Connect provider.
Sessions are stored in signed and encrypted cookies.

## Configuration Examples

!!! note ""

    When using Docker labels, `$` must be escaped as `$$`.

```yaml tab="Docker & Swarm"
labels:
  - "traefik.http.middlewares.test-oidc.oidc.issuer=https://tenant.auth0.com/realms/myrealm"
  - "traefik.http.middlewares.test-oidc.oidc.redirecturl=/callback"
  - "traefik.http.middlewares.test-oidc.oidc.clientid=my-oidc-client-name"
  - "traefik.http.middlewares.test-oidc.oidc.clientsecret=mysecret"
  - "traefik.http.middlewares.test-oidc.oidc.scopes=openid,profile"
  - "traefik.http.middlewares.test-oidc.oidc.session.expiry=3600"
```

```yaml tab="Kubernetes"
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: test-oidc
spec:
  oidc:
    issuer: "https://tenant.auth0.com/realms/myrealm"
    redirectUrl: "/callback"
    clientID: "urn:k8s:secret:my-secret:clientId"
    clientSecret: "urn:k8s:secret:my-secret:clientSecret"
    session:
      expiry: 3600
---
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
stringData:
  clientId: my-oidc-client-name
  clientSecret: mysecret
```

```yaml tab="Consul Catalog"
- "traefik.http.middlewares.test-oidc.oidc.issuer=https://tenant.auth0.com/realms/myrealm"
- "traefik.http.middlewares.test-oidc.oidc.redirecturl=/callback"
- "traefik.http.middlewares.test-oidc.oidc.clientid=my-oidc-client-name"
- "traefik.http.middlewares.test-oidc.oidc.clientsecret=mysecret"
- "traefik.http.middlewares.test-oidc.oidc.scopes=openid,profile"
```

```yaml tab="File (YAML)"
http:
  middlewares:
    test-oidc:
      oidc:
        issuer: "https://tenant.auth0.com/realms/myrealm"
        redirectUrl: "/callback"
        clientID: "my-oidc-client-name"
        clientSecret: "mysecret"
        scopes:
          - openid
          - profile
        session:
          expiry: 3600
```

```toml tab="File (TOML)"
[http.middlewares]
  [http.middlewares.test-oidc.oidc]
    issuer = "https://tenant.auth0.com/realms/myrealm"
    redirectUrl = "/callback"
    clientID = "my-oidc-client-name"
    clientSecret = "mysecret"
    scopes = ["openid", "profile"]
    [http.middlewares.test-oidc.oidc.session]
      expiry = 3600
```

## Configuration Options

### `issuer`

Defines the URL to the OpenID Connect provider.

### `redirectUrl`

Defines the callback URL the provider redirects to once authorization is complete.

### `clientID`, `clientSecret`

Define the client credentials used with the OpenID Connect provider.
The `clientSecret` value may reference a file path (for example: `/run/secrets/oidc-client-secret`)
or use the `file://` prefix to read the client secret from a mounted file.

### `claims`, `usernameClaim`, `forwardHeaders`

Define claim-based authorization, log username extraction, and forwarded headers.

### `loginUrl`, `logoutUrl`, `disableLogin`

Control the login/logout entry points and whether automatic redirects are disabled.

### `session`, `stateCookie`, `csrf`, `clientConfig`

Configure cookie behavior, CSRF protection, and client TLS/timeouts.

For the full list of options and advanced configuration, see the
[reference documentation](../../reference/routing-configuration/http/middlewares/oidc.md).

!!! note ""

    Redis session store configuration is accepted but currently ignored; sessions remain cookie-based.
