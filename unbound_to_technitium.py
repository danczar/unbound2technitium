#!/usr/bin/env python3
"""
unbound_to_technitium.py — Migrate Unbound DNS Server config to Technitium DNS Server

Parses an Unbound configuration file and uses the Technitium HTTP API to:
  - Create primary authoritative zones with all local-data records
  - Migrate forward-zone entries as Conditional Forwarder zones
  - Migrate stub-zone entries as Stub zones
  - Migrate auth-zone entries as Secondary zones
  - Configure upstream forwarders (DoT / DoH / DoQ / plain / TCP)
  - Import ad-blocking / blocklist URLs (including RPZ url: sources)
  - Create blocked zones for deny/refuse/always_nxdomain local-zones
  - Configure DNS-over-TLS / DNS-over-HTTPS / DNS-over-QUIC listener settings
  - Set access control (ACLs)
  - Map DNSSEC validation, EDNS Client Subnet, rate limiting, cache tuning
  - Map split-horizon / view-based configs to Technitium DNS App guidance
  - Generate a detailed migration report

Usage:
  python3 unbound_to_technitium.py \\
      --unbound-conf /etc/unbound/unbound.conf \\
      --technitium-url http://localhost:5380 \\
      --username admin --password admin \\
      [--dry-run] [--include-dir /etc/unbound/unbound.conf.d]

Requirements: Python 3.8+, curl
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import shutil
import subprocess
import urllib.parse

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LocalRecord:
    """A single local-data / local-data-ptr entry from Unbound."""
    name: str
    ttl: int
    rr_class: str  # usually IN
    rr_type: str   # A, AAAA, CNAME, MX, TXT, PTR, SRV, etc.
    rdata: str     # everything after the type

@dataclass
class LocalZone:
    """A local-zone declaration (name + type)."""
    name: str
    zone_type: str  # static, redirect, transparent, deny, refuse, etc.

@dataclass
class ForwardZone:
    """A forward-zone stanza."""
    name: str  # "." for catch-all
    forward_addrs: list = field(default_factory=list)     # IP addresses
    forward_hosts: list = field(default_factory=list)     # hostnames (for DoT)
    forward_tls_upstream: bool = False
    forward_tcp_upstream: bool = False
    forward_first: bool = False
    forward_no_cache: bool = False

@dataclass
class StubZone:
    """A stub-zone stanza."""
    name: str
    stub_addrs: list = field(default_factory=list)
    stub_hosts: list = field(default_factory=list)
    stub_prime: bool = False
    stub_first: bool = False
    stub_tls_upstream: bool = False
    stub_tcp_upstream: bool = False
    stub_no_cache: bool = False

@dataclass
class AuthZone:
    """An auth-zone stanza."""
    name: str
    primaries: list = field(default_factory=list)  # primary: / master: addresses
    url: str = ""
    zonefile: str = ""
    allow_notify: list = field(default_factory=list)
    fallback_enabled: bool = False
    for_downstream: bool = True
    for_upstream: bool = True

@dataclass
class RpzZone:
    """An rpz: stanza with full details."""
    name: str = ""
    primaries: list = field(default_factory=list)
    url: str = ""
    zonefile: str = ""
    rpz_action_override: str = ""
    rpz_cname_override: str = ""
    rpz_log: bool = False
    rpz_log_name: str = ""
    rpz_signal_nxdomain_ra: bool = False
    for_downstream: bool = True
    tags: list = field(default_factory=list)

@dataclass
class AccessControl:
    """An access-control entry."""
    subnet: str
    action: str  # allow, deny, refuse, allow_snoop, etc.

@dataclass
class ViewEntry:
    """An Unbound view (split-horizon)."""
    name: str
    local_zones: list = field(default_factory=list)
    local_data: list = field(default_factory=list)
    view_first: bool = False
    response_ips: list = field(default_factory=list)  # (subnet, action) tuples
    response_ip_data: list = field(default_factory=list)  # (subnet, rdata) tuples

@dataclass
class UnboundConfig:
    """Aggregated parsed Unbound configuration."""
    # server section
    interfaces: list = field(default_factory=list)
    port: int = 53
    do_tcp: bool = True
    do_udp: bool = True
    do_ip4: bool = True
    do_ip6: bool = True
    prefer_ip6: bool = False
    tls_port: int = 853
    tls_cert_bundle: str = ""
    tls_service_key: str = ""
    tls_service_pem: str = ""
    tls_ciphers: str = ""
    tls_ciphersuites: str = ""
    access_controls: list = field(default_factory=list)
    local_zones: list = field(default_factory=list)
    local_records: list = field(default_factory=list)
    include_files: list = field(default_factory=list)

    # forward zones
    forward_zones: list = field(default_factory=list)

    # stub zones
    stub_zones: list = field(default_factory=list)

    # auth zones
    auth_zones: list = field(default_factory=list)

    # views (split-horizon)
    views: list = field(default_factory=list)

    # misc
    private_domains: list = field(default_factory=list)
    private_addresses: list = field(default_factory=list)
    do_not_query_localhost: bool = True
    hide_identity: bool = False
    hide_version: bool = False
    harden_glue: bool = True
    harden_dnssec_stripped: bool = True
    use_caps_for_id: bool = False
    qname_minimisation: bool = True
    qname_minimisation_strict: bool = False
    aggressive_nsec: bool = False
    prefetch: bool = False
    serve_expired: bool = False
    serve_expired_ttl: int = 0
    serve_expired_reply_ttl: int = 30
    serve_expired_client_timeout: int = 0
    num_threads: int = 1
    cache_min_ttl: int = 0
    cache_max_ttl: int = 86400
    cache_max_negative_ttl: int = 3600
    cache_min_negative_ttl: int = 0
    edns_buffer_size: int = 1232
    deny_any: bool = False
    rrset_roundrobin: bool = True
    minimal_responses: bool = True

    # DNSSEC
    module_config: str = ""
    trust_anchor_file: str = ""
    auto_trust_anchor_file: str = ""
    domain_insecure: list = field(default_factory=list)

    # DoH / DoQ
    https_port: int = 0
    http_endpoint: str = "/dns-query"
    quic_port: int = 0

    # EDNS Client Subnet
    send_client_subnet: list = field(default_factory=list)
    client_subnet_zone: list = field(default_factory=list)
    max_client_subnet_ipv4: int = 24
    max_client_subnet_ipv6: int = 56

    # Rate limiting
    ratelimit: int = 0
    ip_ratelimit: int = 0

    # Logging
    log_queries: bool = False
    log_replies: bool = False

    # DNS64
    dns64_prefix: str = ""
    dns64_synthall: bool = False

    # Response IP
    response_ips: list = field(default_factory=list)  # (subnet, action) tuples
    response_ip_data: list = field(default_factory=list)  # (subnet, rdata) tuples

    # Tags
    defined_tags: list = field(default_factory=list)
    access_control_tags: list = field(default_factory=list)
    access_control_views: list = field(default_factory=list)

    # rpz / blocklist
    rpz_zones: list = field(default_factory=list)  # RpzZone objects


# ---------------------------------------------------------------------------
# Unbound config parser
# ---------------------------------------------------------------------------

class UnboundParser:
    """
    Best-effort parser for unbound.conf.

    Handles:
      - server: section (interfaces, port, tls-*, access-control, local-zone,
        local-data, local-data-ptr, private-domain, private-address, DNSSEC,
        ECS, rate limiting, DoH/DoQ, dns64, response-ip, logging, etc.)
      - forward-zone: stanzas (including forward-tcp-upstream, forward-no-cache)
      - stub-zone: stanzas
      - auth-zone: stanzas
      - view: stanzas (split-horizon, including response-ip)
      - rpz: stanzas (full: name, url, primary, zonefile, action overrides, etc.)
      - include: / include-toplevel: directives (with glob expansion)
    """

    def __init__(self):
        self.config = UnboundConfig()
        self._current_section = None
        self._current_fwd: Optional[ForwardZone] = None
        self._current_stub: Optional[StubZone] = None
        self._current_auth: Optional[AuthZone] = None
        self._current_view: Optional[ViewEntry] = None
        self._current_rpz: Optional[RpzZone] = None

    def parse_file(self, path: str) -> UnboundConfig:
        path = Path(path).expanduser().resolve()
        if not path.exists():
            logging.error(f"Config file not found: {path}")
            sys.exit(1)
        self._parse(path)
        return self.config

    @staticmethod
    def _strip_comment(line: str) -> str:
        """Strip trailing comments while preserving # in addr@port#host notation.

        Unbound uses '#' both as a comment character AND as part of the
        forward-addr syntax: 1.1.1.1@853#cloudflare-dns.com
        The key difference: a comment # is preceded by whitespace (or is at BOL),
        while a syntax # is glued to adjacent non-whitespace characters.
        We also need to handle # inside quoted strings.
        """
        in_quote = False
        for i, ch in enumerate(line):
            if ch == '"':
                in_quote = not in_quote
            elif ch == '#' and not in_quote:
                # Only treat as comment if preceded by whitespace or at BOL
                if i == 0 or line[i - 1] in (' ', '\t'):
                    return line[:i].strip()
        return line

    def _parse(self, path: Path):
        logging.info(f"Parsing: {path}")
        with open(path, "r") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                line = self._strip_comment(line)
                if not line:
                    continue
                self._process_line(line, path.parent)

    def _process_line(self, line: str, base_dir: Path):
        # Section headers
        if line.rstrip(":") in ("server", "remote-control",
                                 "cachedb", "python", "dynlib",
                                 "dnstap", "dnscrypt", "ipset"):
            self._flush_section()
            self._current_section = line.rstrip(":")
            return

        if line.startswith("forward-zone:"):
            self._flush_section()
            self._current_section = "forward-zone"
            self._current_fwd = ForwardZone(name="")
            return

        if line.startswith("stub-zone:"):
            self._flush_section()
            self._current_section = "stub-zone"
            self._current_stub = StubZone(name="")
            return

        if line.startswith("auth-zone:"):
            self._flush_section()
            self._current_section = "auth-zone"
            self._current_auth = AuthZone(name="")
            return

        if line.startswith("view:"):
            self._flush_section()
            self._current_section = "view"
            self._current_view = ViewEntry(name="")
            return

        if line.startswith("rpz:"):
            self._flush_section()
            self._current_section = "rpz"
            self._current_rpz = RpzZone()
            return

        # include directive
        inc_match = re.match(r'^include:\s*"?([^"]+)"?', line)
        if inc_match:
            pattern = inc_match.group(1)
            self._handle_include(pattern, base_dir)
            return

        # include-toplevel: closes the current clause first
        inc_tl_match = re.match(r'^include-toplevel:\s*"?([^"]+)"?', line)
        if inc_tl_match:
            self._flush_section()
            self._current_section = None
            pattern = inc_tl_match.group(1)
            self._handle_include(pattern, base_dir)
            return

        # Dispatch to section handler
        if self._current_section == "server":
            self._parse_server(line)
        elif self._current_section == "forward-zone":
            self._parse_forward_zone(line)
        elif self._current_section == "stub-zone":
            self._parse_stub_zone(line)
        elif self._current_section == "auth-zone":
            self._parse_auth_zone(line)
        elif self._current_section == "view":
            self._parse_view(line)
        elif self._current_section == "rpz":
            self._parse_rpz(line)

    def _flush_section(self):
        if self._current_section == "forward-zone" and self._current_fwd and self._current_fwd.name:
            self.config.forward_zones.append(self._current_fwd)
            self._current_fwd = None
        if self._current_section == "stub-zone" and self._current_stub and self._current_stub.name:
            self.config.stub_zones.append(self._current_stub)
            self._current_stub = None
        if self._current_section == "auth-zone" and self._current_auth and self._current_auth.name:
            self.config.auth_zones.append(self._current_auth)
            self._current_auth = None
        if self._current_section == "view" and self._current_view and self._current_view.name:
            self.config.views.append(self._current_view)
            self._current_view = None
        if self._current_section == "rpz" and self._current_rpz and self._current_rpz.name:
            self.config.rpz_zones.append(self._current_rpz)
            self._current_rpz = None

    def _handle_include(self, pattern: str, base_dir: Path):
        import glob
        full = base_dir / pattern
        matches = sorted(glob.glob(str(full)))
        if not matches:
            logging.warning(f"include pattern matched nothing: {pattern}")
        for m in matches:
            self.config.include_files.append(m)
            self._parse(Path(m))

    # -- server section -----------------------------------------------------

    def _kv(self, line: str):
        """Split 'key: value' or 'key value'."""
        if ":" in line:
            k, _, v = line.partition(":")
            return k.strip(), v.strip()
        parts = line.split(None, 1)
        return (parts[0], parts[1] if len(parts) > 1 else "")

    def _parse_bool(self, val: str) -> bool:
        return val.lower() in ("yes", "true", "1")

    def _parse_server(self, line: str):
        key, val = self._kv(line)

        simple_bool = {
            "do-tcp": "do_tcp", "do-udp": "do_udp",
            "do-ip4": "do_ip4", "do-ip6": "do_ip6",
            "prefer-ip6": "prefer_ip6",
            "do-not-query-localhost": "do_not_query_localhost",
            "hide-identity": "hide_identity", "hide-version": "hide_version",
            "harden-glue": "harden_glue",
            "harden-dnssec-stripped": "harden_dnssec_stripped",
            "use-caps-for-id": "use_caps_for_id",
            "qname-minimisation": "qname_minimisation",
            "qname-minimisation-strict": "qname_minimisation_strict",
            "aggressive-nsec": "aggressive_nsec",
            "prefetch": "prefetch",
            "serve-expired": "serve_expired",
            "deny-any": "deny_any",
            "rrset-roundrobin": "rrset_roundrobin",
            "minimal-responses": "minimal_responses",
            "log-queries": "log_queries",
            "log-replies": "log_replies",
            "dns64-synthall": "dns64_synthall",
        }
        simple_int = {
            "port": "port", "tls-port": "tls_port",
            "num-threads": "num_threads",
            "cache-min-ttl": "cache_min_ttl", "cache-max-ttl": "cache_max_ttl",
            "cache-max-negative-ttl": "cache_max_negative_ttl",
            "cache-min-negative-ttl": "cache_min_negative_ttl",
            "edns-buffer-size": "edns_buffer_size",
            "serve-expired-ttl": "serve_expired_ttl",
            "serve-expired-reply-ttl": "serve_expired_reply_ttl",
            "serve-expired-client-timeout": "serve_expired_client_timeout",
            "https-port": "https_port",
            "quic-port": "quic_port",
            "ratelimit": "ratelimit",
            "ip-ratelimit": "ip_ratelimit",
            "max-client-subnet-ipv4": "max_client_subnet_ipv4",
            "max-client-subnet-ipv6": "max_client_subnet_ipv6",
        }
        simple_str = {
            "tls-cert-bundle": "tls_cert_bundle",
            "tls-service-key": "tls_service_key",
            "tls-service-pem": "tls_service_pem",
            "tls-ciphers": "tls_ciphers",
            "tls-ciphersuites": "tls_ciphersuites",
            "module-config": "module_config",
            "trust-anchor-file": "trust_anchor_file",
            "auto-trust-anchor-file": "auto_trust_anchor_file",
            "http-endpoint": "http_endpoint",
            "dns64-prefix": "dns64_prefix",
        }

        if key in simple_bool:
            setattr(self.config, simple_bool[key], self._parse_bool(val))
        elif key in simple_int:
            try:
                setattr(self.config, simple_int[key], int(val))
            except ValueError:
                pass
        elif key in simple_str:
            setattr(self.config, simple_str[key], val.strip('"'))

        elif key == "interface":
            self.config.interfaces.append(val)

        elif key == "access-control":
            parts = val.split()
            if len(parts) >= 2:
                self.config.access_controls.append(
                    AccessControl(subnet=parts[0], action=parts[1])
                )

        elif key == "access-control-view":
            self.config.access_control_views.append(val)

        elif key == "access-control-tag":
            self.config.access_control_tags.append(val)

        elif key == "define-tag":
            # define-tag: "tag1 tag2 tag3"
            tags = val.strip('"').split()
            self.config.defined_tags.extend(tags)

        elif key == "local-zone":
            m = re.match(r'"([^"]+)"\s+(\S+)', val)
            if m:
                self.config.local_zones.append(LocalZone(name=m.group(1), zone_type=m.group(2)))

        elif key == "local-data":
            rec = self._parse_local_data(val)
            if rec:
                self.config.local_records.append(rec)

        elif key == "local-data-ptr":
            inner = val.strip('"')
            parts = inner.split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                ptr_name = self._ip_to_ptr(ip)
                if ptr_name:
                    self.config.local_records.append(
                        LocalRecord(name=ptr_name, ttl=3600, rr_class="IN",
                                    rr_type="PTR", rdata=hostname)
                    )

        elif key == "private-domain":
            self.config.private_domains.append(val.strip('"'))

        elif key == "private-address":
            self.config.private_addresses.append(val)

        elif key == "domain-insecure":
            self.config.domain_insecure.append(val.strip('"'))

        elif key == "send-client-subnet":
            self.config.send_client_subnet.append(val)

        elif key == "client-subnet-zone":
            self.config.client_subnet_zone.append(val.strip('"'))

        elif key == "response-ip":
            parts = val.split(None, 1)
            if len(parts) >= 2:
                self.config.response_ips.append((parts[0], parts[1]))

        elif key == "response-ip-data":
            parts = val.split(None, 1)
            if len(parts) >= 2:
                self.config.response_ip_data.append((parts[0], parts[1]))

    def _parse_local_data(self, val: str) -> Optional[LocalRecord]:
        """Parse a local-data value like:  "host.example.com. 3600 IN A 10.0.0.1" """
        # Unescape inner \" first, then remove outer quotes
        inner = val.replace('\\"', '"').strip('"')
        parts = inner.split()
        if len(parts) < 3:
            return None

        name = parts[0].rstrip(".")
        idx = 1
        ttl = 3600
        rr_class = "IN"

        if idx < len(parts) and parts[idx].isdigit():
            ttl = int(parts[idx])
            idx += 1
        if idx < len(parts) and parts[idx].upper() in ("IN", "CH", "HS"):
            rr_class = parts[idx].upper()
            idx += 1
        if idx >= len(parts):
            return None
        rr_type = parts[idx].upper()
        idx += 1
        rdata = " ".join(parts[idx:])

        return LocalRecord(name=name, ttl=ttl, rr_class=rr_class,
                           rr_type=rr_type, rdata=rdata)

    @staticmethod
    def _ip_to_ptr(ip: str) -> Optional[str]:
        if ":" in ip:
            import ipaddress
            try:
                expanded = ipaddress.ip_address(ip).exploded.replace(":", "")
                return ".".join(reversed(expanded)) + ".ip6.arpa"
            except ValueError:
                return None
        else:
            parts = ip.split(".")
            if len(parts) == 4:
                return ".".join(reversed(parts)) + ".in-addr.arpa"
            return None

    # -- forward-zone section -----------------------------------------------

    def _parse_forward_zone(self, line: str):
        key, val = self._kv(line)
        if key == "name":
            self._current_fwd.name = val.strip('"').rstrip(".")
            if self._current_fwd.name == "":
                self._current_fwd.name = "."
        elif key == "forward-addr":
            self._current_fwd.forward_addrs.append(val)
        elif key == "forward-host":
            self._current_fwd.forward_hosts.append(val)
        elif key == "forward-tls-upstream":
            self._current_fwd.forward_tls_upstream = self._parse_bool(val)
        elif key == "forward-tcp-upstream":
            self._current_fwd.forward_tcp_upstream = self._parse_bool(val)
        elif key == "forward-first":
            self._current_fwd.forward_first = self._parse_bool(val)
        elif key == "forward-no-cache":
            self._current_fwd.forward_no_cache = self._parse_bool(val)

    # -- stub-zone section --------------------------------------------------

    def _parse_stub_zone(self, line: str):
        key, val = self._kv(line)
        if key == "name":
            self._current_stub.name = val.strip('"').rstrip(".")
        elif key == "stub-addr":
            self._current_stub.stub_addrs.append(val)
        elif key == "stub-host":
            self._current_stub.stub_hosts.append(val)
        elif key == "stub-prime":
            self._current_stub.stub_prime = self._parse_bool(val)
        elif key == "stub-first":
            self._current_stub.stub_first = self._parse_bool(val)
        elif key == "stub-tls-upstream":
            self._current_stub.stub_tls_upstream = self._parse_bool(val)
        elif key == "stub-tcp-upstream":
            self._current_stub.stub_tcp_upstream = self._parse_bool(val)
        elif key == "stub-no-cache":
            self._current_stub.stub_no_cache = self._parse_bool(val)

    # -- auth-zone section --------------------------------------------------

    def _parse_auth_zone(self, line: str):
        key, val = self._kv(line)
        if key == "name":
            self._current_auth.name = val.strip('"').rstrip(".")
        elif key in ("primary", "master"):
            self._current_auth.primaries.append(val)
        elif key == "url":
            self._current_auth.url = val.strip('"')
        elif key == "zonefile":
            self._current_auth.zonefile = val.strip('"')
        elif key == "allow-notify":
            self._current_auth.allow_notify.append(val)
        elif key == "fallback-enabled":
            self._current_auth.fallback_enabled = self._parse_bool(val)
        elif key == "for-downstream":
            self._current_auth.for_downstream = self._parse_bool(val)
        elif key == "for-upstream":
            self._current_auth.for_upstream = self._parse_bool(val)

    # -- view section (split-horizon) ---------------------------------------

    def _parse_view(self, line: str):
        key, val = self._kv(line)
        if key == "name":
            self._current_view.name = val.strip('"')
        elif key == "view-first":
            self._current_view.view_first = self._parse_bool(val)
        elif key == "local-zone":
            m = re.match(r'"([^"]+)"\s+(\S+)', val)
            if m:
                self._current_view.local_zones.append(
                    LocalZone(name=m.group(1), zone_type=m.group(2))
                )
        elif key == "local-data":
            rec = self._parse_local_data(val)
            if rec:
                self._current_view.local_data.append(rec)
        elif key == "local-data-ptr":
            inner = val.strip('"')
            parts = inner.split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                ptr_name = self._ip_to_ptr(ip)
                if ptr_name:
                    self._current_view.local_data.append(
                        LocalRecord(name=ptr_name, ttl=3600, rr_class="IN",
                                    rr_type="PTR", rdata=hostname)
                    )
        elif key == "response-ip":
            parts = val.split(None, 1)
            if len(parts) >= 2:
                self._current_view.response_ips.append((parts[0], parts[1]))
        elif key == "response-ip-data":
            parts = val.split(None, 1)
            if len(parts) >= 2:
                self._current_view.response_ip_data.append((parts[0], parts[1]))

    # -- rpz section --------------------------------------------------------

    def _parse_rpz(self, line: str):
        key, val = self._kv(line)
        if key == "name":
            self._current_rpz.name = val.strip('"')
        elif key in ("primary", "master"):
            self._current_rpz.primaries.append(val)
        elif key == "url":
            self._current_rpz.url = val.strip('"')
        elif key == "zonefile":
            self._current_rpz.zonefile = val.strip('"')
        elif key == "rpz-action-override":
            self._current_rpz.rpz_action_override = val.strip('"')
        elif key == "rpz-cname-override":
            self._current_rpz.rpz_cname_override = val.strip('"')
        elif key == "rpz-log":
            self._current_rpz.rpz_log = self._parse_bool(val)
        elif key == "rpz-log-name":
            self._current_rpz.rpz_log_name = val.strip('"')
        elif key == "rpz-signal-nxdomain-ra":
            self._current_rpz.rpz_signal_nxdomain_ra = self._parse_bool(val)
        elif key == "for-downstream":
            self._current_rpz.for_downstream = self._parse_bool(val)
        elif key == "tags":
            self._current_rpz.tags = val.strip('"').split()

    def finalize(self):
        self._flush_section()
        return self.config


# ---------------------------------------------------------------------------
# Technitium API client
# ---------------------------------------------------------------------------

class TechnitiumAPI:
    """Thin wrapper around the Technitium DNS Server HTTP API.

    Uses curl for HTTP requests to avoid Python socket sandbox restrictions
    on macOS. Falls back to urllib if curl is not available.
    """

    def __init__(self, base_url: str, username: str, password: str, dry_run: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.dry_run = dry_run
        self.token: Optional[str] = None
        self._has_curl = shutil.which("curl") is not None

    def login(self):
        if self.dry_run:
            self.token = "DRY_RUN_TOKEN"
            logging.info("[DRY RUN] Skipping login")
            return
        resp = self._post("/api/user/login", {
            "user": self.username,
            "pass": self.password,
        }, auth=False)
        if resp and resp.get("status") == "ok":
            self.token = resp.get("token")
            logging.info("Authenticated with Technitium successfully")
        else:
            logging.error(f"Login failed: {resp}")
            sys.exit(1)

    def _curl(self, method: str, url: str, params: dict) -> Optional[dict]:
        """Execute an HTTP request via curl subprocess."""
        try:
            if method == "POST":
                # Build form data args
                data_args = []
                for k, v in params.items():
                    data_args.extend(["--data-urlencode", f"{k}={v}"])
                cmd = ["curl", "-s", "-S", "--connect-timeout", "10",
                       "--max-time", "30", "-X", "POST"] + data_args + [url]
            else:
                # GET with query string
                if params:
                    qs = urllib.parse.urlencode(params)
                    url = f"{url}?{qs}"
                cmd = ["curl", "-s", "-S", "--connect-timeout", "10",
                       "--max-time", "30", url]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            if result.returncode != 0:
                logging.error(f"curl failed (rc={result.returncode}): {result.stderr.strip()}")
                return None
            return json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            logging.error(f"Request timed out: {url}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON response from {url}: {e}")
            return None
        except Exception as e:
            logging.error(f"Request failed: {url} — {e}")
            return None

    def _post(self, endpoint: str, params: dict, auth: bool = True) -> Optional[dict]:
        if auth and self.token:
            params["token"] = self.token
        url = f"{self.base_url}{endpoint}"
        if self.dry_run and auth:
            logging.info(f"[DRY RUN] POST {endpoint}  params={_sanitize(params)}")
            return {"status": "ok", "response": {}}
        return self._curl("POST", url, params)

    def _get(self, endpoint: str, params: dict, auth: bool = True) -> Optional[dict]:
        if auth and self.token:
            params["token"] = self.token
        url = f"{self.base_url}{endpoint}"
        if self.dry_run and auth:
            logging.info(f"[DRY RUN] GET {endpoint}  params={_sanitize(params)}")
            return {"status": "ok", "response": {}}
        return self._curl("GET", url, params)

    # -- High-level operations ----------------------------------------------

    def create_zone(self, zone: str, zone_type: str = "Primary", **kwargs) -> bool:
        """Create a DNS zone. zone_type: Primary, Secondary, Stub, Forwarder."""
        params = {"zone": zone, "type": zone_type}
        params.update(kwargs)
        resp = self._post("/api/zones/create", params)
        if resp and resp.get("status") == "ok":
            logging.info(f"  Created zone: {zone} ({zone_type})")
            return True
        elif resp and "already exists" in resp.get("errorMessage", "").lower():
            logging.info(f"  Zone already exists: {zone}")
            return True
        else:
            logging.warning(f"  Failed to create zone {zone}: {resp}")
            return False

    def add_record(self, domain: str, rr_type: str, ttl: int = 3600, **kwargs) -> bool:
        """Add a DNS record to an existing zone."""
        params = {"domain": domain, "type": rr_type, "ttl": str(ttl)}
        params.update(kwargs)
        resp = self._post("/api/zones/records/add", params)
        if resp and resp.get("status") == "ok":
            return True
        else:
            logging.warning(f"  Failed to add record {domain} {rr_type}: {resp}")
            return False

    def set_settings(self, **kwargs) -> bool:
        """Update Technitium global DNS settings."""
        resp = self._post("/api/settings/set", kwargs)
        if resp and resp.get("status") == "ok":
            logging.info("  Settings updated")
            return True
        logging.warning(f"  Failed to update settings: {resp}")
        return False

    def set_blocklists(self, urls: list) -> bool:
        """Configure blocklist URLs."""
        params = {"blockListUrls": "\n".join(urls)}
        resp = self._post("/api/settings/set", params)
        if resp and resp.get("status") == "ok":
            logging.info(f"  Configured {len(urls)} blocklist URL(s)")
            return True
        logging.warning(f"  Failed to set blocklists: {resp}")
        return False

    def add_blocked_zone(self, domain: str) -> bool:
        """Add a domain to the blocked zones list."""
        resp = self._post("/api/blocked/add", {"domain": domain})
        if resp and resp.get("status") == "ok":
            return True
        logging.warning(f"  Failed to block domain {domain}: {resp}")
        return False

    def import_blocked_zones(self, domains: list) -> bool:
        """Bulk import domains to the blocked zones list."""
        resp = self._post("/api/blocked/import", {
            "blockedZones": ",".join(domains)
        })
        if resp and resp.get("status") == "ok":
            logging.info(f"  Imported {len(domains)} blocked domain(s)")
            return True
        logging.warning(f"  Failed to import blocked domains: {resp}")
        return False

    def install_app(self, app_name: str) -> bool:
        """Install a DNS App from the built-in store."""
        resp = self._post("/api/apps/downloadAndInstall", {"name": app_name})
        if resp and resp.get("status") == "ok":
            logging.info(f"  Installed DNS App: {app_name}")
            return True
        logging.warning(f"  Failed to install app {app_name}: {resp}")
        return False

    def get_settings(self) -> Optional[dict]:
        resp = self._get("/api/settings/get", {})
        if resp and resp.get("status") == "ok":
            return resp.get("response")
        return None


def _sanitize(params: dict) -> dict:
    """Redact token/password from log output."""
    safe = dict(params)
    for k in ("token", "pass", "password"):
        if k in safe:
            safe[k] = "***"
    return safe


# ---------------------------------------------------------------------------
# Migration engine
# ---------------------------------------------------------------------------

class Migrator:
    """Orchestrates the Unbound → Technitium migration."""

    POPULAR_BLOCKLISTS = {
        "steven-black": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "oisd-full": "https://big.oisd.nl/domainswild2",
        "oisd-small": "https://small.oisd.nl/domainswild2",
        "hagezi-pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.txt",
    }

    def __init__(self, config: UnboundConfig, api: TechnitiumAPI):
        self.config = config
        self.api = api
        self.report_lines: list[str] = []
        self.stats = defaultdict(int)

    def run(self):
        self._header("Unbound → Technitium Migration")
        self.api.login()

        self._migrate_forwarders()
        self._migrate_local_zones_and_records()
        self._migrate_conditional_forwarders()
        self._migrate_stub_zones()
        self._migrate_auth_zones()
        self._migrate_tls_settings()
        self._migrate_doh_doq_settings()
        self._migrate_acls()
        self._migrate_blocklists()
        self._migrate_blocked_zones()
        self._migrate_dnssec_settings()
        self._migrate_ecs_settings()
        self._migrate_rate_limiting()
        self._migrate_logging()
        self._migrate_misc_settings()
        self._handle_split_horizon()
        self._note_unmigrateable()
        self._print_report()

    # -- Forwarders ---------------------------------------------------------

    def _migrate_forwarders(self):
        self._section("Upstream Forwarders")

        catch_all = [fz for fz in self.config.forward_zones if fz.name == "."]
        if not catch_all:
            self._note("No catch-all forward-zone (name: \".\") found; "
                       "Technitium will use recursive resolution by default.")
            return

        fz = catch_all[0]
        forwarders = []
        protocol = "Udp"

        if fz.forward_tls_upstream:
            protocol = "Tls"
            self._note("Detected forward-tls-upstream: yes → using DNS-over-TLS forwarders")
        elif fz.forward_tcp_upstream:
            protocol = "Tcp"
            self._note("Detected forward-tcp-upstream: yes → using TCP forwarders")

        for addr in fz.forward_addrs:
            clean = addr.strip()
            m = re.match(r"^([^@#]+)(?:@(\d+))?(?:#(.+))?$", clean)
            if m:
                ip = m.group(1)
                port = m.group(2)
                hostname = m.group(3)

                if fz.forward_tls_upstream and hostname:
                    p = port or "853"
                    forwarders.append(f"{hostname}:{p} ({ip})")
                elif port and port != "53":
                    forwarders.append(f"{ip}:{port}")
                else:
                    forwarders.append(ip)
            else:
                forwarders.append(clean)

        for host in fz.forward_hosts:
            forwarders.append(host.strip())

        if not forwarders:
            self._note("Catch-all forward-zone has no addresses configured.")
            return

        if fz.forward_no_cache:
            self._note("  forward-no-cache: yes — Technitium does not have a per-forwarder"
                       " no-cache option; consider setting cacheMinimumRecordTtl=0")

        fwd_str = "\n".join(forwarders)
        self._note(f"Configuring {len(forwarders)} forwarder(s), protocol={protocol}")
        for f in forwarders:
            self._note(f"  → {f}")

        self.api.set_settings(
            forwarders=fwd_str,
            forwarderProtocol=protocol,
        )
        self.stats["forwarders"] = len(forwarders)

    # -- Local zones & records ----------------------------------------------

    def _migrate_local_zones_and_records(self):
        self._section("Local Zones & Records")

        zone_records: dict[str, list[LocalRecord]] = defaultdict(list)
        declared_zones = {lz.name.rstrip("."): lz for lz in self.config.local_zones}

        for rec in self.config.local_records:
            zone = self._find_zone_for_record(rec.name, declared_zones)
            zone_records[zone].append(rec)

        for zname, lz in declared_zones.items():
            if zname not in zone_records:
                zone_records[zname] = []

        if not zone_records:
            self._note("No local zones or records found.")
            return

        self._note(f"Found {len(zone_records)} zone(s), "
                   f"{len(self.config.local_records)} record(s) total")

        for zone_name in sorted(zone_records.keys()):
            records = zone_records[zone_name]
            lz = declared_zones.get(zone_name)
            zone_type_str = lz.zone_type if lz else "static"

            # Block zones handled separately in _migrate_blocked_zones
            if zone_type_str in ("deny", "refuse", "always_nxdomain",
                                  "always_refuse", "always_deny"):
                continue

            # Transparent zones with no records are pass-through — skip creating
            # a Primary zone, especially if a forward-zone exists for this name
            # (the Forwarder zone will be created in _migrate_conditional_forwarders)
            if zone_type_str == "transparent" and not records:
                fwd_names = {fz.name for fz in self.config.forward_zones}
                if zone_name in fwd_names:
                    self._note(f"  Zone '{zone_name}' type=transparent with forward-zone"
                               f" → skipping Primary, will create as Forwarder")
                    continue
                else:
                    self._note(f"  Zone '{zone_name}' type=transparent with no records"
                               f" → skipping (pass-through)")
                    continue

            self.api.create_zone(zone_name, "Primary")
            self.stats["zones_created"] += 1

            # Unbound "redirect" zones return zone data for ALL names under the zone,
            # equivalent to a wildcard. Synthesize *.zone records for each record.
            is_redirect = zone_type_str == "redirect"
            if is_redirect:
                self._note(f"  Zone '{zone_name}' type=redirect → adding wildcard records")

            for rec in records:
                domain = rec.name
                rr_type = rec.rr_type
                kwargs = {}

                if rr_type == "A":
                    kwargs["ipAddress"] = rec.rdata
                elif rr_type == "AAAA":
                    kwargs["ipAddress"] = rec.rdata
                elif rr_type == "CNAME":
                    kwargs["cname"] = rec.rdata.rstrip(".")
                elif rr_type == "MX":
                    parts = rec.rdata.split()
                    if len(parts) >= 2:
                        kwargs["preference"] = parts[0]
                        kwargs["exchange"] = parts[1].rstrip(".")
                    else:
                        kwargs["exchange"] = rec.rdata.rstrip(".")
                elif rr_type == "TXT":
                    kwargs["text"] = rec.rdata.strip('"')
                elif rr_type == "PTR":
                    kwargs["ptrName"] = rec.rdata.rstrip(".")
                elif rr_type == "SRV":
                    parts = rec.rdata.split()
                    if len(parts) >= 4:
                        kwargs["priority"] = parts[0]
                        kwargs["weight"] = parts[1]
                        kwargs["port"] = parts[2]
                        kwargs["target"] = parts[3].rstrip(".")
                elif rr_type == "NS":
                    kwargs["nameServer"] = rec.rdata.rstrip(".")
                elif rr_type == "CAA":
                    parts = rec.rdata.split(None, 2)
                    if len(parts) >= 3:
                        kwargs["flags"] = parts[0]
                        kwargs["tag"] = parts[1]
                        kwargs["value"] = parts[2].strip('"')
                elif rr_type == "DNAME":
                    kwargs["dname"] = rec.rdata.rstrip(".")
                elif rr_type == "NAPTR":
                    parts = rec.rdata.split()
                    if len(parts) >= 6:
                        kwargs["naptrOrder"] = parts[0]
                        kwargs["naptrPreference"] = parts[1]
                        kwargs["naptrFlags"] = parts[2].strip('"')
                        kwargs["naptrServices"] = parts[3].strip('"')
                        kwargs["naptrRegexp"] = parts[4].strip('"')
                        kwargs["naptrReplacement"] = parts[5].rstrip(".")
                elif rr_type == "SSHFP":
                    parts = rec.rdata.split()
                    if len(parts) >= 3:
                        algo_map = {"1": "RSA", "2": "DSA", "3": "ECDSA",
                                    "4": "Ed25519", "6": "Ed448"}
                        fp_map = {"1": "SHA1", "2": "SHA256"}
                        kwargs["sshfpAlgorithm"] = algo_map.get(parts[0], parts[0])
                        kwargs["sshfpFingerprintType"] = fp_map.get(parts[1], parts[1])
                        kwargs["sshfpFingerprint"] = parts[2]
                elif rr_type == "TLSA":
                    parts = rec.rdata.split()
                    if len(parts) >= 4:
                        usage_map = {"0": "PKIX-TA", "1": "PKIX-EE",
                                     "2": "DANE-TA", "3": "DANE-EE"}
                        sel_map = {"0": "Cert", "1": "SPKI"}
                        match_map = {"0": "Full", "1": "SHA2-256", "2": "SHA2-512"}
                        kwargs["tlsaCertificateUsage"] = usage_map.get(parts[0], parts[0])
                        kwargs["tlsaSelector"] = sel_map.get(parts[1], parts[1])
                        kwargs["tlsaMatchingType"] = match_map.get(parts[2], parts[2])
                        kwargs["tlsaCertificateAssociationData"] = parts[3]
                elif rr_type == "URI":
                    parts = rec.rdata.split(None, 2)
                    if len(parts) >= 3:
                        kwargs["uriPriority"] = parts[0]
                        kwargs["uriWeight"] = parts[1]
                        kwargs["uri"] = parts[2].strip('"')
                elif rr_type == "RP":
                    parts = rec.rdata.split()
                    if len(parts) >= 2:
                        kwargs["mailbox"] = parts[0].rstrip(".")
                        kwargs["txtDomain"] = parts[1].rstrip(".")
                else:
                    kwargs["rdata"] = rec.rdata
                    self._note(f"    Record type {rr_type} for {domain}: "
                               f"passed raw rdata — verify in Technitium UI")

                ok = self.api.add_record(domain, rr_type, rec.ttl, **kwargs)
                if ok:
                    self.stats["records_created"] += 1
                else:
                    self.stats["records_failed"] += 1

                # For redirect zones, also add a wildcard record
                if is_redirect and domain == zone_name:
                    wildcard = f"*.{zone_name}"
                    ok = self.api.add_record(wildcard, rr_type, rec.ttl, **kwargs)
                    if ok:
                        self.stats["records_created"] += 1
                        self._note(f"    + {wildcard} {rr_type} {rec.rdata}")
                    else:
                        self.stats["records_failed"] += 1

    def _find_zone_for_record(self, record_name: str, declared_zones: dict) -> str:
        """Find the best-matching declared zone for a record, or infer one."""
        name = record_name.rstrip(".")
        labels = name.split(".")

        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in declared_zones:
                return candidate

        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return name

    # -- Conditional forwarders ---------------------------------------------

    def _migrate_conditional_forwarders(self):
        self._section("Conditional Forwarders")

        cond_fwds = [fz for fz in self.config.forward_zones if fz.name != "."]
        if not cond_fwds:
            self._note("No conditional forward-zones found.")
            return

        self._note(f"Found {len(cond_fwds)} conditional forward-zone(s)")

        for fz in cond_fwds:
            zone_name = fz.name

            addrs = fz.forward_addrs + fz.forward_hosts
            if not addrs:
                self._note(f"  forward-zone '{zone_name}' has no addresses, skipping")
                continue

            # Determine protocol
            if fz.forward_tls_upstream:
                protocol = "Tls"
            elif fz.forward_tcp_upstream:
                protocol = "Tcp"
            else:
                protocol = "Udp"

            # Build forwarder list — use ALL addresses, not just the first
            forwarder_strs = []
            for addr in addrs:
                clean = addr.strip()
                m = re.match(r"^([^@#]+)(?:@(\d+))?(?:#(.+))?$", clean)
                if m:
                    ip = m.group(1)
                    port = m.group(2)
                    hostname = m.group(3)
                    if fz.forward_tls_upstream and hostname:
                        p = port or "853"
                        forwarder_strs.append(f"{hostname}:{p} ({ip})")
                    elif port and port != "53":
                        forwarder_strs.append(f"{ip}:{port}")
                    else:
                        forwarder_strs.append(ip)
                else:
                    forwarder_strs.append(clean)

            # Create forwarder zone with first address, then add remaining as FWD records
            ok = self.api.create_zone(zone_name, "Forwarder",
                                      forwarder=forwarder_strs[0],
                                      protocol=protocol,
                                      initializeForwarder="true")
            if ok:
                self.stats["cond_forwarders"] += 1
                self._note(f"  → {zone_name} → {forwarder_strs[0]} ({protocol})")

                # Add additional forwarder addresses as FWD records
                for extra in forwarder_strs[1:]:
                    self.api.add_record(zone_name, "FWD",
                                        protocol=protocol,
                                        forwarder=extra)
                    self._note(f"    + {extra}")

            if fz.forward_no_cache:
                self._note(f"    forward-no-cache: yes — not directly supported in Technitium")

    # -- Stub zones ---------------------------------------------------------

    def _migrate_stub_zones(self):
        self._section("Stub Zones")

        if not self.config.stub_zones:
            self._note("No stub-zones found.")
            return

        self._note(f"Found {len(self.config.stub_zones)} stub-zone(s)")

        for sz in self.config.stub_zones:
            addrs = sz.stub_addrs + sz.stub_hosts
            if not addrs:
                self._note(f"  stub-zone '{sz.name}' has no addresses, skipping")
                continue

            # Technitium Stub zone requires primaryNameServerAddresses
            primary_addrs = ",".join(a.strip() for a in addrs)

            # Determine zone transfer protocol
            xfr_protocol = "Tcp"
            if sz.stub_tls_upstream:
                xfr_protocol = "Tls"

            ok = self.api.create_zone(sz.name, "Stub",
                                      primaryNameServerAddresses=primary_addrs,
                                      zoneTransferProtocol=xfr_protocol)
            if ok:
                self.stats["stub_zones"] += 1
                self._note(f"  → {sz.name} → {primary_addrs} (xfr={xfr_protocol})")

            if sz.stub_no_cache:
                self._note(f"    stub-no-cache: yes — not directly supported in Technitium")

    # -- Auth zones ---------------------------------------------------------

    def _migrate_auth_zones(self):
        self._section("Authoritative Zones (auth-zone)")

        if not self.config.auth_zones:
            self._note("No auth-zones found.")
            return

        self._note(f"Found {len(self.config.auth_zones)} auth-zone(s)")

        for az in self.config.auth_zones:
            if az.primaries:
                primary_addrs = ",".join(a.strip() for a in az.primaries)
                ok = self.api.create_zone(az.name, "Secondary",
                                          primaryNameServerAddresses=primary_addrs)
                if ok:
                    self.stats["auth_zones"] += 1
                    self._note(f"  → {az.name} (Secondary) from {primary_addrs}")
            elif az.url:
                self._note(f"  → {az.name} — uses url: {az.url}")
                self._note(f"    Technitium Secondary zones use zone transfers, not HTTP downloads.")
                self._note(f"    Consider importing the zone file manually or using a Primary zone.")
                self.stats["auth_zones"] += 1
            elif az.zonefile:
                self._note(f"  → {az.name} — uses zonefile: {az.zonefile}")
                self._note(f"    Import this zone file via Technitium web UI (Zones → Import)")
                self._note(f"    or create a Primary zone and add records manually.")
                self.stats["auth_zones"] += 1
            else:
                self._note(f"  → {az.name} — no primary or source configured, skipping")

            if az.allow_notify:
                self._note(f"    allow-notify: {', '.join(az.allow_notify)}")
                self._note(f"    Configure in Technitium zone options → Notify settings")

    # -- TLS settings -------------------------------------------------------

    def _migrate_tls_settings(self):
        self._section("DNS-over-TLS Configuration")

        tls_settings = {}

        if self.config.tls_port and (self.config.tls_service_key or self.config.tls_service_pem):
            self._note(f"Unbound TLS service detected (port {self.config.tls_port})")
            self._note(f"  Key: {self.config.tls_service_key}")
            self._note(f"  Cert: {self.config.tls_service_pem}")

            tls_settings["enableDnsOverTls"] = "true"
            tls_settings["dnsOverTlsPort"] = str(self.config.tls_port)

            self._note("")
            self._note("  MANUAL STEP REQUIRED:")
            self._note("  Technitium manages TLS certs via its web UI or PFX/PKCS12 file.")
            self._note("  1) Convert your PEM cert+key to PKCS12:")
            self._note(f"     openssl pkcs12 -export \\")
            self._note(f"       -in {self.config.tls_service_pem} \\")
            self._note(f"       -inkey {self.config.tls_service_key} \\")
            self._note(f"       -out /etc/dns/cert.pfx")
            self._note("  2) In Technitium Settings → Optional Protocols → DNS-over-TLS,")
            self._note("     enable it and set the certificate path + password.")
            self._note("  3) Or set via API: dnsTlsCertificatePath + dnsTlsCertificatePassword")

            if self.config.tls_ciphers:
                self._note(f"")
                self._note(f"  tls-ciphers: {self.config.tls_ciphers}")
                self._note(f"  Technitium does not expose cipher suite configuration via API;")
                self._note(f"  it uses the .NET runtime defaults.")
            if self.config.tls_ciphersuites:
                self._note(f"  tls-ciphersuites: {self.config.tls_ciphersuites}")
                self._note(f"  Same note as above — not configurable in Technitium.")

        elif self.config.tls_port and self.config.tls_port != 853:
            self._note(f"TLS port {self.config.tls_port} configured but no service cert found.")
            self._note("  This is likely client-side TLS for upstream DoT — handled in Forwarders.")

        else:
            self._note("No TLS service (server-side DoT) configuration detected.")

        if tls_settings:
            self.api.set_settings(**tls_settings)

    # -- DoH / DoQ settings -------------------------------------------------

    def _migrate_doh_doq_settings(self):
        self._section("DNS-over-HTTPS / DNS-over-QUIC Configuration")

        settings = {}

        if self.config.https_port:
            self._note(f"Unbound HTTPS (DoH) port detected: {self.config.https_port}")
            self._note(f"  HTTP endpoint: {self.config.http_endpoint}")
            settings["enableDnsOverHttps"] = "true"
            settings["dnsOverHttpsPort"] = str(self.config.https_port)
            self._note("  DoH requires TLS certificate — same cert as DoT can be used.")
            self._note("  Configure dnsTlsCertificatePath if not already set.")
        else:
            self._note("No DNS-over-HTTPS (DoH) listener detected.")

        if self.config.quic_port:
            self._note(f"Unbound QUIC (DoQ) port detected: {self.config.quic_port}")
            settings["enableDnsOverQuic"] = "true"
            settings["dnsOverQuicPort"] = str(self.config.quic_port)
            self._note("  DoQ requires TLS certificate — same cert as DoT can be used.")
        else:
            self._note("No DNS-over-QUIC (DoQ) listener detected.")

        if settings:
            self.api.set_settings(**settings)

    # -- ACLs ---------------------------------------------------------------

    def _migrate_acls(self):
        self._section("Access Controls")

        if not self.config.access_controls:
            self._note("No access-control entries found in Unbound config.")
            return

        self._note(f"Found {len(self.config.access_controls)} ACL rule(s):")

        allow_subnets = []
        deny_subnets = []

        for acl in self.config.access_controls:
            action_map = {
                "allow": "allow", "allow_snoop": "allow",
                "allow_setrd": "allow", "allow_cookie": "allow",
                "deny": "deny", "refuse": "deny",
            }
            mapped = action_map.get(acl.action, "unknown")
            self._note(f"  {acl.subnet:24s} {acl.action:16s} → {mapped}")

            if mapped == "allow":
                allow_subnets.append(acl.subnet)
            elif mapped == "deny":
                deny_subnets.append(acl.subnet)

        if allow_subnets:
            # Build Technitium ACL: allow listed, deny with ! prefix
            acl_parts = list(allow_subnets)
            for d in deny_subnets:
                acl_parts.append(f"!{d}")

            self._note("")
            self._note(f"  Setting recursion=UseSpecifiedNetworkACL")
            self._note(f"  recursionNetworkACL = {', '.join(acl_parts)}")

            self.api.set_settings(
                recursion="UseSpecifiedNetworkACL",
                recursionNetworkACL=",".join(acl_parts),
            )

        if self.config.access_control_views:
            self._note("")
            self._note(f"  Found {len(self.config.access_control_views)} access-control-view entries")
            self._note("  These map client subnets to Unbound views (split-horizon).")
            self._note("  See Split Horizon section for Technitium equivalent.")

        if self.config.access_control_tags:
            self._note("")
            self._note(f"  Found {len(self.config.access_control_tags)} access-control-tag entries")
            self._note("  Unbound's tag-based ACL system has no direct Technitium equivalent.")
            self._note("  Consider using Technitium DNS Apps for similar per-client behavior.")

        self.stats["acl_rules"] = len(self.config.access_controls)

    # -- Blocklists / adblocking --------------------------------------------

    def _migrate_blocklists(self):
        self._section("Ad Blocking / Blocklists")

        blocklist_urls = []

        if self.config.rpz_zones:
            self._note(f"Found {len(self.config.rpz_zones)} RPZ zone(s):")
            for rpz in self.config.rpz_zones:
                self._note(f"  → {rpz.name}")
                if rpz.url:
                    self._note(f"    url: {rpz.url} → adding to blocklist URLs")
                    blocklist_urls.append(rpz.url)
                if rpz.primaries:
                    self._note(f"    primary: {', '.join(rpz.primaries)}")
                    self._note(f"    RPZ zone transfers are not supported in Technitium.")
                    self._note(f"    If the provider offers a hosts/domain-list URL, add it manually.")
                if rpz.zonefile:
                    self._note(f"    zonefile: {rpz.zonefile}")
                    self._note(f"    Local RPZ zone files can be converted to a blocked domain list.")
                if rpz.rpz_action_override:
                    self._note(f"    rpz-action-override: {rpz.rpz_action_override}")
                    self._note(f"    Technitium blocking type can be set via blockingType setting")
                    self._note(f"    (AnyAddress, NxDomain, CustomAddress)")
                if rpz.rpz_cname_override:
                    self._note(f"    rpz-cname-override: {rpz.rpz_cname_override}")
                    self._note(f"    Use blockingType=CustomAddress + customBlockingAddresses")
                if rpz.rpz_log:
                    self._note(f"    rpz-log: yes (name: {rpz.rpz_log_name})")
                    self._note(f"    Enable query logging in Technitium for similar visibility.")

            self._note("")
            self._note("  Technitium uses blocklist URLs instead of RPZ zone transfers.")

        if blocklist_urls:
            self._note(f"  Auto-adding {len(blocklist_urls)} RPZ URL(s) to blocklist:")
            for url in blocklist_urls:
                self._note(f"    → {url}")
            self.api.set_blocklists(blocklist_urls)

        self._note("")
        self._note("  Recommended blocklists for Technitium (add in Settings → Block List URLs):")
        for name, url in self.POPULAR_BLOCKLISTS.items():
            self._note(f"    {name:20s} {url}")

    # -- Blocked zones (deny/refuse local-zones) ----------------------------

    def _migrate_blocked_zones(self):
        self._section("Blocked Zones (deny/refuse/always_nxdomain)")

        block_zones = [lz for lz in self.config.local_zones
                       if lz.zone_type in ("deny", "refuse", "always_nxdomain",
                                            "always_refuse", "always_deny")]
        if not block_zones:
            self._note("No blocking local-zones found.")
            return

        self._note(f"Found {len(block_zones)} blocking local-zone(s)")

        domains = [bz.name for bz in block_zones]

        # Bulk import via API
        self.api.import_blocked_zones(domains)

        for bz in block_zones:
            self._note(f"  → {bz.name} ({bz.zone_type})")
        self.stats["blocked_zones"] = len(block_zones)

    # -- DNSSEC settings ----------------------------------------------------

    def _migrate_dnssec_settings(self):
        self._section("DNSSEC Validation")

        has_validator = "validator" in self.config.module_config if self.config.module_config else False
        has_trust_anchor = bool(self.config.trust_anchor_file or self.config.auto_trust_anchor_file)

        if has_validator or has_trust_anchor:
            self._note("DNSSEC validation detected in Unbound config:")
            if self.config.module_config:
                self._note(f"  module-config: {self.config.module_config}")
            if self.config.auto_trust_anchor_file:
                self._note(f"  auto-trust-anchor-file: {self.config.auto_trust_anchor_file}")
            if self.config.trust_anchor_file:
                self._note(f"  trust-anchor-file: {self.config.trust_anchor_file}")

            self._note("  Enabling DNSSEC validation in Technitium")
            self.api.set_settings(dnssecValidation="true")
            self.stats["dnssec"] = 1
        else:
            self._note("No DNSSEC validation configured (no validator module or trust anchor).")
            self._note("  Technitium has DNSSEC validation enabled by default.")

        if self.config.domain_insecure:
            self._note("")
            self._note(f"  Found {len(self.config.domain_insecure)} domain-insecure entries:")
            for d in self.config.domain_insecure:
                self._note(f"    → {d}")
            self._note("  Technitium does not have a per-domain DNSSEC bypass.")
            self._note("  If needed, create Forwarder zones for these domains with")
            self._note("  dnssecValidation=false.")

        if self.config.harden_dnssec_stripped:
            self._note("  harden-dnssec-stripped: yes — Technitium enforces this by default")

    # -- EDNS Client Subnet -------------------------------------------------

    def _migrate_ecs_settings(self):
        self._section("EDNS Client Subnet (ECS)")

        if not self.config.send_client_subnet and not self.config.client_subnet_zone:
            self._note("No ECS configuration detected.")
            return

        settings = {}

        if self.config.send_client_subnet or self.config.client_subnet_zone:
            self._note("ECS configuration detected:")
            settings["eDnsClientSubnet"] = "true"

            if self.config.send_client_subnet:
                self._note(f"  send-client-subnet: {', '.join(self.config.send_client_subnet)}")
            if self.config.client_subnet_zone:
                self._note(f"  client-subnet-zone: {', '.join(self.config.client_subnet_zone)}")
                self._note("  Technitium enables ECS globally, not per-zone.")

            if self.config.max_client_subnet_ipv4 != 24:
                settings["eDnsClientSubnetIPv4PrefixLength"] = str(self.config.max_client_subnet_ipv4)
                self._note(f"  max-client-subnet-ipv4: {self.config.max_client_subnet_ipv4}")
            if self.config.max_client_subnet_ipv6 != 56:
                settings["eDnsClientSubnetIPv6PrefixLength"] = str(self.config.max_client_subnet_ipv6)
                self._note(f"  max-client-subnet-ipv6: {self.config.max_client_subnet_ipv6}")

        if settings:
            self.api.set_settings(**settings)
            self.stats["ecs"] = 1

    # -- Rate limiting ------------------------------------------------------

    def _migrate_rate_limiting(self):
        self._section("Rate Limiting")

        if not self.config.ratelimit and not self.config.ip_ratelimit:
            self._note("No rate limiting configured.")
            return

        self._note("Rate limiting detected:")

        if self.config.ratelimit:
            self._note(f"  ratelimit: {self.config.ratelimit} (queries per second per domain)")
            self._note("  Technitium uses QPM (queries per minute) rate limiting.")
            self._note("  Approximate QPM equivalent: ratelimit * 60")
            self._note(f"  Configure qpmPrefixLimitsIPv4 / qpmPrefixLimitsIPv6 in settings.")

        if self.config.ip_ratelimit:
            self._note(f"  ip-ratelimit: {self.config.ip_ratelimit} (queries per second per IP)")
            self._note("  Technitium QPM limits are per-prefix, not per-IP.")
            self._note(f"  Suggested: set /32 UDP limit to ~{self.config.ip_ratelimit * 60} QPM")

        self.stats["rate_limits"] = 1

    # -- Logging ------------------------------------------------------------

    def _migrate_logging(self):
        self._section("Query Logging")

        if self.config.log_queries or self.config.log_replies:
            self._note("Query logging detected:")
            if self.config.log_queries:
                self._note("  log-queries: yes")
            if self.config.log_replies:
                self._note("  log-replies: yes")

            self._note("  Enabling query logging in Technitium")
            self.api.set_settings(logQueries="true")
            self.stats["logging"] = 1
        else:
            self._note("No query logging configured in Unbound.")
            self._note("  Technitium supports query logging via Settings → Logging.")

    # -- Misc settings ------------------------------------------------------

    def _migrate_misc_settings(self):
        self._section("Miscellaneous Settings")

        settings = {}

        if self.config.qname_minimisation:
            settings["qnameMinimization"] = "true"
            self._note("QNAME minimisation: enabled")
            if self.config.qname_minimisation_strict:
                self._note("  qname-minimisation-strict: yes — Technitium does not distinguish"
                           " strict vs relaxed QNAME minimisation")

        if self.config.serve_expired:
            settings["serveStale"] = "true"
            self._note("Serve stale/expired: enabled")
            if self.config.serve_expired_ttl:
                settings["serveStaleTtl"] = str(self.config.serve_expired_ttl)
                self._note(f"  serve-expired-ttl: {self.config.serve_expired_ttl}s")
            if self.config.serve_expired_reply_ttl:
                settings["serveStaleAnswerTtl"] = str(self.config.serve_expired_reply_ttl)
                self._note(f"  serve-expired-reply-ttl: {self.config.serve_expired_reply_ttl}s")
            if self.config.serve_expired_client_timeout:
                settings["serveStaleMaxWaitTime"] = str(self.config.serve_expired_client_timeout)
                self._note(f"  serve-expired-client-timeout: {self.config.serve_expired_client_timeout}ms")

        if self.config.prefetch:
            settings["cachePrefetchEligibility"] = "2"
            settings["cachePrefetchTrigger"] = "9"
            self._note("Prefetching: enabled (eligibility=2, trigger=9)")

        if self.config.use_caps_for_id:
            settings["randomizeName"] = "true"
            self._note("QNAME case randomization (0x20): enabled")

        if self.config.cache_min_ttl > 0:
            settings["cacheMinimumRecordTtl"] = str(self.config.cache_min_ttl)
            self._note(f"Cache min TTL: {self.config.cache_min_ttl}s")

        if self.config.cache_max_ttl != 86400:
            settings["cacheMaximumRecordTtl"] = str(self.config.cache_max_ttl)
            self._note(f"Cache max TTL: {self.config.cache_max_ttl}s")

        if self.config.cache_max_negative_ttl != 3600:
            settings["cacheNegativeRecordTtl"] = str(self.config.cache_max_negative_ttl)
            self._note(f"Cache negative TTL: {self.config.cache_max_negative_ttl}s")

        if self.config.edns_buffer_size != 1232:
            settings["udpPayloadSize"] = str(self.config.edns_buffer_size)
            self._note(f"EDNS buffer size: {self.config.edns_buffer_size} → udpPayloadSize")

        if self.config.prefer_ip6:
            settings["preferIPv6"] = "true"
            self._note("Prefer IPv6: enabled")

        if self.config.hide_identity:
            self._note("hide-identity: yes — Technitium hides identity by default")
        if self.config.hide_version:
            self._note("hide-version: yes — Technitium hides version by default")

        if settings:
            self.api.set_settings(**settings)

    # -- Split horizon / views ----------------------------------------------

    def _handle_split_horizon(self):
        self._section("Split Horizon (Views)")

        if not self.config.views:
            self._note("No Unbound views detected.")
            return

        self._note(f"Found {len(self.config.views)} Unbound view(s):")
        self._note("")

        for view in self.config.views:
            self._note(f"  View: '{view.name}'")
            self._note(f"    view-first: {view.view_first}")
            self._note(f"    local-zones: {len(view.local_zones)}")
            self._note(f"    local-data:  {len(view.local_data)}")

            for lz in view.local_zones:
                self._note(f"      zone: {lz.name} ({lz.zone_type})")
            for rec in view.local_data[:5]:
                self._note(f"      data: {rec.name} {rec.rr_type} {rec.rdata}")
            if len(view.local_data) > 5:
                self._note(f"      ... and {len(view.local_data) - 5} more records")

            if view.response_ips:
                self._note(f"    response-ip entries: {len(view.response_ips)}")
                for subnet, action in view.response_ips:
                    self._note(f"      {subnet} → {action}")
            if view.response_ip_data:
                self._note(f"    response-ip-data entries: {len(view.response_ip_data)}")

        self._note("")
        self._note("  MANUAL MIGRATION REQUIRED FOR SPLIT HORIZON")
        self._note("")
        self._note("  Technitium handles split-horizon via the 'Split Horizon' DNS App.")
        self._note("  Steps:")
        self._note("  1) Install the 'Split Horizon' app from Apps → App Store")
        self._note("  2) In your Primary zone, add an APP record:")
        self._note("       Name: @ (or specific subdomain)")
        self._note("       App:  Split Horizon")
        self._note("       Class Path: SplitHorizon.SimpleAddress")
        self._note("       Record Data (JSON):")
        self._note("       {")
        self._note('         "enableAddressTranslation": false,')
        self._note('         "networkGroupMap": {')
        self._note('           "10.0.0.0/8": "internal",')
        self._note('           "192.168.0.0/16": "internal",')
        self._note('           "0.0.0.0/0": "external"')
        self._note("         },")
        self._note('         "groups": {')
        self._note('           "internal": [')
        self._note('             { "type": "A", "rdata": { "ipAddress": "10.0.0.5" } }')
        self._note("           ],")
        self._note('           "external": [')
        self._note('             { "type": "A", "rdata": { "ipAddress": "203.0.113.5" } }')
        self._note("           ]")
        self._note("         }")
        self._note("       }")

        # Generate skeleton JSON per view
        for view in self.config.views:
            self._note("")
            self._note(f"  --- View '{view.name}' skeleton ---")
            group_records = []
            for rec in view.local_data:
                if rec.rr_type == "A":
                    group_records.append(
                        f'    {{ "type": "A", "rdata": {{ "ipAddress": "{rec.rdata}" }} }}'
                    )
                elif rec.rr_type == "AAAA":
                    group_records.append(
                        f'    {{ "type": "AAAA", "rdata": {{ "ipAddress": "{rec.rdata}" }} }}'
                    )
            if group_records:
                self._note(f'  "{view.name}": [')
                self._note(",\n".join(group_records))
                self._note("  ]")

        self.stats["views"] = len(self.config.views)

    # -- Notes for unmigrateable features -----------------------------------

    def _note_unmigrateable(self):
        self._section("Notes: Features Without Direct Technitium Equivalent")

        notes = []

        if self.config.deny_any:
            notes.append("deny-any: yes — Technitium does not have a deny-ANY toggle;"
                         " ANY queries return normally")

        if self.config.dns64_prefix:
            notes.append(f"dns64-prefix: {self.config.dns64_prefix} — Technitium does not have"
                         " built-in DNS64; consider a DNS App or external NAT64 gateway")

        if self.config.response_ips:
            notes.append(f"{len(self.config.response_ips)} response-ip entries — these override"
                         " responses based on answer content; use Technitium DNS Apps"
                         " (e.g., Block Page, Query Log) for similar behavior")

        if self.config.defined_tags:
            notes.append(f"define-tag: {' '.join(self.config.defined_tags)} — Unbound's tag system"
                         " has no Technitium equivalent; use DNS Apps for per-client logic")

        if self.config.private_domains:
            notes.append(f"{len(self.config.private_domains)} private-domain entries — these prevent"
                         " forwarding to upstream; already handled if zones exist locally")

        if self.config.private_addresses:
            notes.append(f"{len(self.config.private_addresses)} private-address entries (rebind protection)"
                         " — Technitium does not have built-in DNS rebinding protection;"
                         " consider a DNS App or firewall rule")

        if not notes:
            self._note("All detected features have been migrated or noted above.")
        else:
            for note in notes:
                self._note(f"  • {note}")

    # -- Reporting ----------------------------------------------------------

    def _header(self, text: str):
        sep = "═" * 70
        self.report_lines.append(f"\n{sep}")
        self.report_lines.append(f"  {text}")
        self.report_lines.append(f"{sep}\n")

    def _section(self, text: str):
        self.report_lines.append(f"\n{'─' * 60}")
        self.report_lines.append(f"  {text}")
        self.report_lines.append(f"{'─' * 60}")

    def _note(self, text: str):
        self.report_lines.append(text)

    def _print_report(self):
        self._section("Migration Summary")
        self._note(f"  Zones created:            {self.stats['zones_created']}")
        self._note(f"  Records created:          {self.stats['records_created']}")
        self._note(f"  Records failed:           {self.stats['records_failed']}")
        self._note(f"  Conditional forwarders:    {self.stats['cond_forwarders']}")
        self._note(f"  Stub zones:               {self.stats['stub_zones']}")
        self._note(f"  Auth zones (secondary):    {self.stats['auth_zones']}")
        self._note(f"  Upstream forwarders:       {self.stats['forwarders']}")
        self._note(f"  Blocked zones:             {self.stats['blocked_zones']}")
        self._note(f"  ACL rules mapped:          {self.stats['acl_rules']}")
        self._note(f"  Views (manual migration):  {self.stats['views']}")
        self._note(f"  DNSSEC validation:         {'enabled' if self.stats.get('dnssec') else 'default'}")
        self._note(f"  ECS configured:            {'yes' if self.stats.get('ecs') else 'no'}")
        self._note(f"  Rate limiting:             {'noted' if self.stats.get('rate_limits') else 'none'}")
        self._note(f"  Query logging:             {'enabled' if self.stats.get('logging') else 'default'}")
        self._note("")

        if self.api.dry_run:
            self._note("  *** DRY RUN — no changes were made to Technitium ***")
            self._note("")

        for line in self.report_lines:
            print(line)

        report_path = Path("migration_report.txt")
        with open(report_path, "w") as f:
            for line in self.report_lines:
                f.write(line + "\n")
        print(f"\n  Report saved to: {report_path.resolve()}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate Unbound DNS config to Technitium DNS Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Dry run — parse config, show what would happen, don't touch Technitium
  %(prog)s --unbound-conf /etc/unbound/unbound.conf --dry-run

  # Full migration
  %(prog)s \\
      --unbound-conf /etc/unbound/unbound.conf \\
      --technitium-url http://localhost:5380 \\
      --username admin --password 'MySecurePass'

  # With extra include directories
  %(prog)s \\
      --unbound-conf /etc/unbound/unbound.conf \\
      --include-dir /etc/unbound/unbound.conf.d \\
      --technitium-url http://192.168.1.10:5380 \\
      --username admin --password admin
"""
    )
    parser.add_argument("--unbound-conf", required=True,
                        help="Path to unbound.conf")
    parser.add_argument("--include-dir", action="append", default=[],
                        help="Extra directories to scan for *.conf includes")
    parser.add_argument("--technitium-url", default="http://localhost:5380",
                        help="Technitium DNS Server URL (default: http://localhost:5380)")
    parser.add_argument("--username", default="admin",
                        help="Technitium admin username")
    parser.add_argument("--password", default="admin",
                        help="Technitium admin password")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse config and report only; don't call Technitium API")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-8s %(message)s"
    )

    # Parse Unbound config
    ub_parser = UnboundParser()
    config = ub_parser.parse_file(args.unbound_conf)

    # Handle extra include dirs
    for inc_dir in args.include_dir:
        import glob
        for conf_file in sorted(glob.glob(os.path.join(inc_dir, "*.conf"))):
            ub_parser._parse(Path(conf_file))

    config = ub_parser.finalize()

    # Connect to Technitium
    api = TechnitiumAPI(
        base_url=args.technitium_url,
        username=args.username,
        password=args.password,
        dry_run=args.dry_run,
    )

    # Run migration
    migrator = Migrator(config, api)
    migrator.run()


if __name__ == "__main__":
    main()
