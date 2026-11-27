import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple
from app.config import settings

class TargetValidationError(Exception):
    pass

RESTRICTED_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (AWS, GCP, Azure)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier Grade NAT
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast / This host
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]

def validate_and_normalize_target(raw_target: str, allow_local_override: bool = None) -> Tuple[str, str, str]:
    """
    Validates a target URL/domain against strict ethical and safety guardrails.
    Returns: (normalized_url, hostname, resolved_ip)
    Raises TargetValidationError if target is malformed or targets unauthorized internal IPs.
    """
    if not raw_target or not isinstance(raw_target, str):
        raise TargetValidationError("Target cannot be empty.")

    target = raw_target.strip()
    if not target.startswith(("http://", "https://")):
        # Default to https scheme
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.netloc:
        raise TargetValidationError(f"Invalid target URL structure: '{raw_target}'")

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError(f"Unable to parse hostname from '{raw_target}'")

    # Strip port if present in hostname
    hostname = hostname.lower()

    # Disallow dangerous pseudo-domains and local domains by default
    if hostname in ("localhost", "local", "ip6-localhost", "ip6-loopback", "metadata.google.internal"):
        effective_allow = allow_local_override if allow_local_override is not None else settings.allow_local_targets
        if not effective_allow:
            raise TargetValidationError(
                f"Scanning '{hostname}' is blocked: Local loopback and internal cloud metadata endpoints are disallowed by default. "
                "Set ALLOW_LOCAL_TARGETS=true in your environment to permit testing against local containers."
            )

    # Resolve IP address
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            raise TargetValidationError(f"Unable to resolve host: {hostname}")
        resolved_ip = addr_info[0][4][0]
    except socket.gaierror as e:
        raise TargetValidationError(f"DNS resolution failure for host '{hostname}': {str(e)}")

    # Check IP restrictions
    ip_obj = ipaddress.ip_address(resolved_ip)
    effective_allow_local = allow_local_override if allow_local_override is not None else settings.allow_local_targets

    if not effective_allow_local:
        for subnet in RESTRICTED_SUBNETS:
            if ip_obj in subnet:
                raise TargetValidationError(
                    f"Blocked SSRF/Private Target: '{hostname}' resolves to private/restricted IP {resolved_ip} ({subnet}). "
                    "HackerOps strictly blocks attacks against internal networks unless ALLOW_LOCAL_TARGETS=true is enabled."
                )

    scheme = parsed.scheme.lower()
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    path = parsed.path if parsed.path else ""
    normalized_url = f"{scheme}://{hostname}{port}{path}"

    return normalized_url, hostname, resolved_ip
