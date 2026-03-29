# unbound2technitium

Migrate your [Unbound](https://nlnetlabs.nl/projects/unbound/about/) DNS server configuration to [Technitium DNS Server](https://technitium.com/dns/) via its HTTP API.

Parses `unbound.conf` and automatically creates zones, records, forwarders, ACLs, blocklists, and settings in Technitium. Generates a detailed migration report highlighting anything that needs manual attention.

## Features

**Fully automated migration of:**
- Forward zones (catch-all and conditional) with DoT/DoH/DoQ/TCP/UDP protocol detection
- Stub zones and auth zones (secondary)
- Local zones and records (A, AAAA, CNAME, MX, TXT, PTR, SRV, NS, CAA, DNAME, NAPTR, SSHFP, TLSA, URI, RP)
- `redirect` zones (Unbound's wildcard equivalent) with automatic `*` record synthesis
- `transparent` zones with proper forwarding passthrough
- Blocked zones (`deny`, `refuse`, `always_nxdomain`) imported via Technitium's blocked zone API
- RPZ zones with automatic blocklist URL extraction
- DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC listener settings
- Access controls mapped to Technitium's recursion ACL
- DNSSEC validation detection
- EDNS Client Subnet (ECS) settings
- Rate limiting guidance
- Query logging
- Cache tuning (min/max TTL, negative TTL, serve-stale with full parameter mapping, prefetch)
- `include:` and `include-toplevel:` directive handling with glob expansion
- Split-horizon views with skeleton JSON config for Technitium's Split Horizon DNS App

**Report-only notes for features without direct equivalents:**
- `deny-any`, `dns64-prefix`, `response-ip`, tag-based ACLs, `private-domain`, `private-address` (rebind protection), TLS cipher configuration

## Requirements

- Python 3.8+
- `curl`
- A running Technitium DNS Server instance

No Python dependencies required. HTTP calls use `curl` under the hood to avoid macOS application firewall issues with Python's socket layer.

## Usage

```bash
# Dry run -- parse config and show what would happen, no changes made
python3 unbound_to_technitium.py \
    --unbound-conf /etc/unbound/unbound.conf \
    --dry-run

# Full migration
python3 unbound_to_technitium.py \
    --unbound-conf /etc/unbound/unbound.conf \
    --technitium-url http://localhost:5380 \
    --username admin --password 'MySecurePass'

# With extra include directories
python3 unbound_to_technitium.py \
    --unbound-conf /etc/unbound/unbound.conf \
    --include-dir /etc/unbound/unbound.conf.d \
    --technitium-url http://192.168.1.10:5380 \
    --username admin --password admin
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--unbound-conf` | *(required)* | Path to `unbound.conf` |
| `--technitium-url` | `http://localhost:5380` | Technitium web UI URL |
| `--username` | `admin` | Technitium admin username |
| `--password` | `admin` | Technitium admin password |
| `--include-dir` | *(none)* | Extra directories to scan for `*.conf` includes (repeatable) |
| `--dry-run` | `false` | Parse and report only, don't touch Technitium |
| `--verbose` / `-v` | `false` | Verbose logging |

## Example

Given this Unbound config:

```
server:
    prefetch: yes
    serve-expired: yes
    cache-min-ttl: 300
    access-control: 192.168.0.0/16 allow

    local-zone: "myapp.example.com." redirect
    local-data: "myapp.example.com. IN A 192.168.1.100"

    local-zone: "ads.example.com" deny

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net

forward-zone:
    name: "corp.internal"
    forward-addr: 10.0.0.53
```

The script will:

1. Configure Technitium to forward to `dns.quad9.net:853 (9.9.9.9)` over TLS
2. Create a `myapp.example.com` Primary zone with an A record and `*.myapp.example.com` wildcard (redirect zone)
3. Import `ads.example.com` to Technitium's blocked zone list (deny zone)
4. Create a `corp.internal` Conditional Forwarder zone pointing to `10.0.0.53`
5. Set recursion ACL to allow `192.168.0.0/16`
6. Enable cache prefetch and serve-stale
7. Save a full migration report to `migration_report.txt`

## Unbound Zone Type Mapping

| Unbound Zone Type | Technitium Behavior |
|---|---|
| `static` | Primary zone with records |
| `redirect` | Primary zone with records + wildcard (`*`) records |
| `transparent` | Skipped if a forward-zone exists (becomes Forwarder zone), otherwise skipped (pass-through) |
| `deny` / `refuse` / `always_nxdomain` | Imported to Technitium's blocked zone list |
| `forward-zone` (name `.`) | Global forwarder settings |
| `forward-zone` (named) | Conditional Forwarder zone |
| `stub-zone` | Stub zone |
| `auth-zone` | Secondary zone |

## Post-Migration Recommendations

- **Blocklists**: Add blocklist URLs in Technitium Settings for ad blocking (oisd, hagezi, steven-black)
- **DNS Rebinding Protection**: Install the DNS Rebinding Protection app and configure your `private-address` / `private-domain` entries
- **Split Horizon**: If you use Unbound views, install the Split Horizon DNS App and use the skeleton JSON from the migration report
- **TLS Certificates**: If migrating server-side DoT/DoH, convert your PEM cert+key to PKCS12 format for Technitium

## Sample Config

`unbound_sample.conf` is included to exercise all supported features for testing.

## License

MIT
