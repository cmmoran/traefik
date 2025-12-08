---
title: "Traefik GeoIP Documentation"
description: "The GeoIP middleware in Traefik Proxy enriches requests with GeoIP headers using MaxMind MMDB files."
---

# GeoIP

Adding GeoIP Headers
{: .subtitle }

The GeoIP middleware enriches incoming requests with geographic and ASN headers based on MaxMind MMDB files.

## Configuration Examples

```yaml tab="Docker & Swarm"
labels:
  - "traefik.http.middlewares.geoip.geoip.dbpath=/data/GeoLite2-City.mmdb,/data/GeoLite2-ASN.mmdb"
  - "traefik.http.middlewares.geoip.geoip.excludeips=10.0.0.0/8,192.168.0.0/16"
  - "traefik.http.middlewares.geoip.geoip.ipstrategy.excludedips=173.245.48.0/20,103.21.244.0/22"
  - "traefik.http.middlewares.geoip.geoip.setrealip=true"
```

```yaml tab="Kubernetes"
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: geoip
spec:
  geoIP:
    dbPath:
      - /data/GeoLite2-City.mmdb
      - /data/GeoLite2-ASN.mmdb
    excludeIPs:
      - 10.0.0.0/8
      - 192.168.0.0/16
    ipStrategy:
      excludedIPs:
        - 173.245.48.0/20
        - 103.21.244.0/22
    setRealIP: true
```

```yaml tab="Consul Catalog"
- "traefik.http.middlewares.geoip.geoip.dbpath=/data/GeoLite2-City.mmdb,/data/GeoLite2-ASN.mmdb"
- "traefik.http.middlewares.geoip.geoip.excludeips=10.0.0.0/8,192.168.0.0/16"
- "traefik.http.middlewares.geoip.geoip.ipstrategy.excludedips=173.245.48.0/20,103.21.244.0/22"
- "traefik.http.middlewares.geoip.geoip.setrealip=true"
```

```yaml tab="File (YAML)"
http:
  middlewares:
    geoip:
      geoIP:
        dbPath:
          - /data/GeoLite2-City.mmdb
          - /data/GeoLite2-ASN.mmdb
        excludeIPs:
          - 10.0.0.0/8
          - 192.168.0.0/16
        ipStrategy:
          excludedIPs:
            - 173.245.48.0/20
            - 103.21.244.0/22
        setRealIP: true
```

```toml tab="File (TOML)"
[http.middlewares]
  [http.middlewares.geoip.geoIP]
    dbPath = ["/data/GeoLite2-City.mmdb", "/data/GeoLite2-ASN.mmdb"]
    excludeIPs = ["10.0.0.0/8", "192.168.0.0/16"]
    [http.middlewares.geoip.geoIP.ipStrategy]
      excludedIPs = ["173.245.48.0/20", "103.21.244.0/22"]
    setRealIP = true
```

## Added Headers

When data is available, the middleware sets the following headers:

- `Ip-Country`
- `Ip-Country-Code`
- `Ip-Region`
- `Ip-City`
- `Ip-Latitude`
- `Ip-Longitude`
- `Ip-Geohash`
- `Asn-System-Number`
- `Asn-System-Org`
- `Asn-Network`

## Configuration Options

### `dbPath`

List of MaxMind MMDB file paths (City, Country, and/or ASN).
At least one path is required.

### `excludeIPs`

List of IPs or CIDRs to skip (for example: `10.0.0.0/8`).

### `setRealIP`

When `true`, sets `X-Real-Ip` to the resolved client IP.

### `ipStrategy`

Configures how the client IP is selected (e.g., `depth` or `excludedIPs`) using the same behavior as `ipAllowList`.

### `debug`

Enables verbose logging for lookups and errors.
