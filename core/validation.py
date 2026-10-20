"""
Centralized input validation for VX-LB (security hardening).

Every operator-supplied identifier that can reach a shell command, a file
path, or a config file MUST pass through these validators. Validating at a
single choke point (instead of per-caller) closes the injection chain even
when a new caller forgets to validate.
"""
import re
import shlex

_POOL_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_TUNNEL_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,80}")


def validate_pool_name(name) -> str:
    """Normalize and whitelist-validate a pool name.

    Returns the canonical name (spaces -> underscores, lowercased).
    Raises ValueError on anything outside [a-z0-9_-].
    """
    clean = str(name).strip().replace(" ", "_").lower()
    if not _POOL_NAME_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid pool name {str(name)!r}: use 1-64 chars of a-z, 0-9, '-' or '_'"
        )
    return clean


def validate_tunnel_name(name) -> str:
    """Whitelist-validate a tunnel/systemd unit name fragment."""
    clean = str(name).strip()
    if not _TUNNEL_NAME_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid tunnel name {str(name)!r}: use 1-81 chars of a-z, 0-9, '-' or '_'"
        )
    return clean


def validate_port(port) -> str:
    """Validate a TCP/UDP port number. Returns the canonical string form."""
    s = str(port).strip()
    if not s.isdigit():
        raise ValueError(f"Invalid port {str(port)!r}: must be numeric")
    n = int(s)
    if not 1 <= n <= 65535:
        raise ValueError(f"Invalid port {str(port)!r}: must be in range 1-65535")
    return str(n)


def validate_ports(ports) -> list:
    """Validate a list of ports, de-duplicated. Raises ValueError if empty/invalid."""
    seen = []
    for p in ports or []:
        v = validate_port(p)
        if v not in seen:
            seen.append(v)
    if not seen:
        raise ValueError("At least one valid client port is required")
    return seen


def validate_transport(transport, supported: dict) -> str:
    """Validate a transport name against SUPPORTED_TRANSPORTS values."""
    t = str(transport).strip()
    valid_values = {v[0] for v in supported.values()}
    if t not in valid_values:
        raise ValueError(f"Unsupported transport {str(transport)!r}")
    return t


def shquote(s) -> str:
    """Shell-quote a single argument (defense in depth; use with validated input)."""
    return shlex.quote(str(s))


def toml_basic_string(s: str) -> str:
    """Escape a value for embedding inside a TOML basic string ("...")."""
    return (
        str(s)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
