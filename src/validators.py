"""
Input validation for all API endpoints.
All validators return (value, error_string).
If error_string is not None, the input is invalid.
"""

import re
import os
import time
import threading
import ipaddress
from pathlib import Path
from typing import Optional, Tuple, Any

# ── Constants ──────────────────────────────────────────────

MAX_DOMAIN_LENGTH = 253
MAX_DOMAIN_LABEL_LENGTH = 63
MAX_DESCRIPTION_LENGTH = 200
MAX_RULE_ID_LENGTH = 64
MAX_PATH_LENGTH = 260          # Windows MAX_PATH
PATH_CACHE_TTL  = 30           # seconds before a cached path result expires
PATH_CACHE_MAX  = 256          # max entries — prevents unbounded memory growth

VALID_DIRECTIONS = {"inbound", "outbound", "both"}


# ── Path resolution cache ──────────────────────────────────

class _PathCache:
    """
    Thread-safe TTL cache for resolved executable paths.

    Stores (resolved_path, error, expiry_timestamp) keyed on the raw
    input string.  Two outcomes are cached:
      - Valid path  → (resolved_str, None, expiry)
      - Invalid path → (None, error_msg, expiry)

    Caching failures avoids hammering the filesystem with repeated
    stat() calls for the same bad input (e.g. a flood of API requests
    with a non-existent path).
    """

    def __init__(self, ttl: float = PATH_CACHE_TTL, maxsize: int = PATH_CACHE_MAX):
        self._ttl = ttl
        self._maxsize = maxsize
        self._store: dict[str, tuple] = {}   # raw_path -> (resolved, error, expires_at)
        self._lock = threading.Lock()

    def get(self, raw: str) -> Optional[tuple]:
        """Return (resolved, error) if cached and not expired, else None."""
        with self._lock:
            entry = self._store.get(raw)
            if entry is None:
                return None
            resolved, error, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[raw]
                return None
            return resolved, error

    def set(self, raw: str, resolved: Optional[str], error: Optional[str]) -> None:
        """Cache a validation result."""
        with self._lock:
            # Evict oldest entry when full — simple but effective for this
            # use-case where the working set of app paths is small
            if len(self._store) >= self._maxsize and raw not in self._store:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[raw] = (resolved, error, time.monotonic() + self._ttl)

    def invalidate(self, raw: str) -> None:
        """Explicitly evict one entry (e.g. after a file is deleted)."""
        with self._lock:
            self._store.pop(raw, None)

    def clear(self) -> None:
        """Flush all entries."""
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)


# Module-level singleton — one cache for the process lifetime
_path_cache = _PathCache()

# RFC 1123 label: starts/ends with alnum, hyphens allowed in middle
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

# Rule IDs are short hex strings (uuid4 sliced to 8 chars) or full UUIDs
_RULE_ID_RE = re.compile(r'^[a-f0-9\-]{1,36}$', re.IGNORECASE)


# ── JSON body ─────────────────────────────────────────────

def require_json(data: Any) -> Tuple[Optional[dict], Optional[str]]:
    """Ensure request.json is a dict, not None or another type."""
    if data is None:
        return None, "Request body must be JSON"
    if not isinstance(data, dict):
        return None, "Request body must be a JSON object"
    return data, None


# ── Domain ────────────────────────────────────────────────

def validate_domain(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate a domain name against RFC 1123.
    Returns (normalised_domain, error) — error is None if valid.
    """
    if not isinstance(value, str):
        return None, "Domain must be a string"

    domain = value.strip().lower().rstrip(".")

    if not domain:
        return None, "Domain cannot be empty"

    if len(domain) > MAX_DOMAIN_LENGTH:
        return None, f"Domain exceeds {MAX_DOMAIN_LENGTH} characters"

    # Must have at least one dot (rejects bare hostnames and junk)
    if "." not in domain:
        return None, "Domain must contain at least one dot"

    labels = domain.split(".")
    for label in labels:
        if not label:
            return None, "Domain contains empty label (double dot)"
        if len(label) > MAX_DOMAIN_LABEL_LENGTH:
            return None, f"Domain label '{label}' exceeds {MAX_DOMAIN_LABEL_LENGTH} characters"
        if not _LABEL_RE.match(label):
            return None, f"Domain label '{label}' contains invalid characters"

    return domain, None


# ── IP Address ────────────────────────────────────────────

def validate_ip(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate an IPv4 or IPv6 address."""
    if not isinstance(value, str):
        return None, "IP must be a string"

    ip = value.strip()
    if not ip:
        return None, "IP cannot be empty"

    try:
        parsed = ipaddress.ip_address(ip)
        return str(parsed), None
    except ValueError:
        return None, f"'{ip}' is not a valid IPv4 or IPv6 address"


# ── App path ──────────────────────────────────────────────

def validate_app_path(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate a Windows executable path.
    - Must be a string
    - Must end in .exe
    - Must be absolute after resolution (no traversal tricks)
    - Must actually exist on disk
    - Must not exceed MAX_PATH

    Results are cached for PATH_CACHE_TTL seconds so repeated calls
    with the same path do not hit the filesystem every time.
    Both valid and invalid outcomes are cached so a flood of bad
    inputs cannot turn into a stat() storm.
    """
    if not isinstance(value, str):
        return None, "app_path must be a string"

    raw = value.strip()
    if not raw:
        return None, "app_path cannot be empty"

    if len(raw) > MAX_PATH_LENGTH:
        return None, f"app_path exceeds {MAX_PATH_LENGTH} characters"

    # ── Cache hit ──────────────────────────────────────────
    cached = _path_cache.get(raw)
    if cached is not None:
        return cached   # (resolved, None) or (None, error_msg)

    # ── Cache miss: do the real filesystem work ────────────
    resolved, error = _resolve_app_path(raw)
    _path_cache.set(raw, resolved, error)
    return resolved, error


def _resolve_app_path(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Perform the actual filesystem checks for validate_app_path.
    Called only on a cache miss — never call this directly.
    """
    # Resolve and normalise — collapses ../ traversal before any check
    try:
        resolved = str(Path(raw).resolve())
    except (ValueError, OSError) as e:
        return None, f"Invalid path: {e}"

    if not os.path.isabs(resolved):
        return None, "app_path must be an absolute path"

    if not resolved.lower().endswith(".exe"):
        return None, "app_path must point to an .exe file"

    if not os.path.isfile(resolved):
        return None, f"Executable not found: {resolved}"

    return resolved, None


def invalidate_path_cache(path: str = None) -> None:
    """
    Manually evict a path from the cache.

    Call this if you delete or move an executable and want the next
    validate_app_path() call to re-check the filesystem immediately
    rather than returning a stale cached result.

    Pass path=None to flush the entire cache.
    """
    if path is None:
        _path_cache.clear()
    else:
        _path_cache.invalidate(path.strip())


def path_cache_stats() -> dict:
    """Return current cache size — useful for health checks / debugging."""
    return {"path_cache_size": _path_cache.size, "path_cache_ttl": PATH_CACHE_TTL}


# ── Direction ─────────────────────────────────────────────

def validate_direction(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate WFP rule direction."""
    if not isinstance(value, str):
        return None, "direction must be a string"
    v = value.strip().lower()
    if v not in VALID_DIRECTIONS:
        return None, f"direction must be one of: {', '.join(sorted(VALID_DIRECTIONS))}"
    return v, None


# ── Port ──────────────────────────────────────────────────

def validate_port(value: Any, allow_zero: bool = True) -> Tuple[Optional[int], Optional[str]]:
    """Validate a TCP/UDP port number (0–65535)."""
    if value is None:
        return 0, None  # Optional field — default to 0 (any)

    if not isinstance(value, int) or isinstance(value, bool):
        return None, "dst_port must be an integer"

    if allow_zero and value == 0:
        return 0, None

    if not (1 <= value <= 65535):
        return None, "dst_port must be between 1 and 65535"

    return value, None


# ── Expiry ────────────────────────────────────────────────

def validate_expiry(value: Any) -> Tuple[Optional[int], Optional[str]]:
    """
    Validate expiry_minutes.
    None means 'use default'. 0 means permanent. Positive = minutes.
    """
    if value is None:
        return None, None  # Use default

    if not isinstance(value, int) or isinstance(value, bool):
        return None, "expiry_minutes must be an integer"

    if value < 0:
        return None, "expiry_minutes cannot be negative"

    if value > 10080:  # 1 week cap — prevents accidental permanent locks
        return None, "expiry_minutes cannot exceed 10080 (1 week)"

    return value, None


# ── Description ───────────────────────────────────────────

def validate_description(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate a human-readable description string."""
    if value is None:
        return "", None

    if not isinstance(value, str):
        return None, "description must be a string"

    value = value.strip()
    if len(value) > MAX_DESCRIPTION_LENGTH:
        return None, f"description exceeds {MAX_DESCRIPTION_LENGTH} characters"

    return value, None


# ── Rule ID ───────────────────────────────────────────────

def validate_rule_id(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate a rule ID (short hex or UUID format)."""
    if not isinstance(value, str):
        return None, "rule_id must be a string"

    value = value.strip()
    if not value:
        return None, "rule_id cannot be empty"

    if len(value) > MAX_RULE_ID_LENGTH:
        return None, "rule_id is too long"

    if not _RULE_ID_RE.match(value):
        return None, "rule_id contains invalid characters"

    return value, None


# ── Destination IP (optional) ─────────────────────────────

def validate_optional_ip(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate an optional destination IP — empty string is allowed."""
    if value is None or value == "":
        return "", None
    return validate_ip(value)
