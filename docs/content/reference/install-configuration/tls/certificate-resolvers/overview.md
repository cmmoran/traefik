---
title: "Certificates Resolver"
description: "Automatic Certificate Management using ACME, Vault/OpenBao, and Tailscale."
---


In Traefik, TLS Certificates can be generated using Certificates Resolvers.

In Traefik, four certificate resolvers exist:

- [`acme`](./acme.md): It allows generating ACME certificates stored in a file (not distributed).
- [`acmeRedux`](./acmeredux.md): It allows generating ACME certificates with Vault-backed storage and locking for multi-instance deployments (Vault-compatible service required).
- [`tailscale`](./tailscale.md): It allows provisioning TLS certificates for internal Tailscale services.
- [`vaultpki`](./vaultpki.md): It allows issuing certificates through Vault/OpenBao PKI for server and client mTLS.

The Certificates resolvers are defined in the static configuration.

!!! note Referencing a certificate resolver
    Defining a certificate resolver does not imply that routers are going to use it automatically.
    Each router or entrypoint that is meant to use the resolver must explicitly reference it.

{% include-markdown "includes/traefik-for-business-applications.md" %}
