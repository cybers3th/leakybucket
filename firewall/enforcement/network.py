"""Egress control — deterministic host/protocol/port allowlist."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field


BLOCKED_IPS = [
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918
    ipaddress.ip_network("0.0.0.0/8"),           # invalid
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal", "metadata.azure.com",
    "metadata", "instance-data", "kubernetes.default.svc",
}

DEFAULT_ALLOWED_PROTOCOLS = {"http", "https"}
DEFAULT_ALLOWED_PORTS = {80, 443}


@dataclass
class EgressPolicy:
    allowed_hosts: list[str] = field(default_factory=list)     # glob patterns
    allowed_protocols: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_PROTOCOLS))
    allowed_ports: set[int] = field(default_factory=lambda: set(DEFAULT_ALLOWED_PORTS))
    block_private_addresses: bool = True

    def merge(self, other: "EgressPolicy") -> "EgressPolicy":
        return EgressPolicy(
            allowed_hosts=self.allowed_hosts + other.allowed_hosts,
            allowed_protocols=self.allowed_protocols | other.allowed_protocols,
            allowed_ports=self.allowed_ports | other.allowed_ports,
            block_private_addresses=self.block_private_addresses and other.block_private_addresses,
        )


class EgressController:
    def __init__(self, policy: EgressPolicy):
        self.policy = policy

    def check(self, url: str) -> tuple[bool, str]:
        try:
            p = urllib.parse.urlparse(url)
        except Exception as e:
            return False, f"URL parse error: {e}"
        proto = (p.scheme or "").lower()
        if proto not in self.policy.allowed_protocols:
            return False, f"protocol '{proto}' not allowed"
        host = (p.hostname or "").lower()
        if not host:
            return False, "no host"
        # Explicit host blocklist
        if host in BLOCKED_HOSTNAMES:
            return False, f"host '{host}' blocked"
        # IP-literal checks
        ip_obj = _maybe_ip(host)
        if ip_obj is not None and self.policy.block_private_addresses:
            for net in BLOCKED_IPS:
                if ip_obj in net:
                    return False, f"IP '{host}' in blocked range {net}"
        # Port check
        port = p.port or (443 if proto == "https" else 80)
        if port not in self.policy.allowed_ports:
            return False, f"port {port} not allowed"
        # Host allowlist
        if not self.policy.allowed_hosts:
            return False, "no hosts allowlisted"
        if not any(fnmatch.fnmatch(host, pat) for pat in self.policy.allowed_hosts):
            return False, f"host '{host}' not in allowlist"
        return True, ""


def _maybe_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except Exception:
        return None
