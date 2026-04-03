"""
DNS Blocklist Manager.
Downloads, parses, and manages domain blocklists from multiple sources.
Supports hosts-file format and plain domain lists.
"""

import os
import re
import time
import logging
import threading
import requests
from pathlib import Path
from typing import Set

logger = logging.getLogger("sentinel.dns.blocklist")

# Regex to parse hosts file lines: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
HOSTS_LINE_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)\s*$"
)
PLAIN_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


class BlocklistManager:
    """Manages domain blocklists: download, parse, cache, lookup."""

    def __init__(self, data_dir: str, blocklists: list, custom_blocked: list = None,
                 whitelist: list = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.blocklist_configs = blocklists or []
        self.custom_blocked = set(custom_blocked or [])
        self.whitelist = set(whitelist or [])
        self._blocked_domains: Set[str] = set()
        self._lock = threading.Lock()
        self._last_update = 0

    @property
    def blocked_count(self) -> int:
        return len(self._blocked_domains)

    def initialize(self):
        """Load blocklists from cache or download fresh."""
        logger.info("Initializing blocklists...")
        for bl_config in self.blocklist_configs:
            if not bl_config.get("enabled", True):
                continue
            name = bl_config["name"]
            url = bl_config["url"]
            cache_file = self.data_dir / f"{self._safe_filename(name)}.txt"

            # Use cached if less than 24 hours old
            if cache_file.exists():
                age = time.time() - cache_file.stat().st_mtime
                if age < 86400:  # 24 hours
                    domains = self._parse_file(cache_file)
                    with self._lock:
                        self._blocked_domains.update(domains)
                    logger.info(f"Loaded {len(domains)} domains from cache: {name}")
                    continue

            # Download fresh
            domains = self._download_and_parse(name, url, cache_file)
            with self._lock:
                self._blocked_domains.update(domains)

        # Add custom blocked domains
        with self._lock:
            self._blocked_domains.update(self.custom_blocked)
            # Remove whitelisted
            self._blocked_domains -= self.whitelist

        self._last_update = time.time()
        logger.info(f"Blocklist initialized: {self.blocked_count} domains blocked")

    def is_blocked(self, domain: str) -> bool:
        """Check if a domain is blocked. Checks exact match and parent domains."""
        domain = domain.lower().strip().rstrip(".")
        if domain in self.whitelist:
            return False
        with self._lock:
            # Check exact match
            if domain in self._blocked_domains:
                return True
            # Check parent domains (e.g., sub.tracking.com checks tracking.com)
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._blocked_domains:
                    return True
        return False

    def add_blocked(self, domain: str):
        """Add a domain to the block list at runtime."""
        domain = domain.lower().strip()
        with self._lock:
            self._blocked_domains.add(domain)
        logger.info(f"Added to blocklist: {domain}")

    def remove_blocked(self, domain: str):
        """Remove a domain from the block list."""
        domain = domain.lower().strip()
        with self._lock:
            self._blocked_domains.discard(domain)
        self.whitelist.add(domain)
        logger.info(f"Removed from blocklist / whitelisted: {domain}")

    def _download_and_parse(self, name: str, url: str, cache_file: Path) -> Set[str]:
        """Download a blocklist and parse it."""
        try:
            logger.info(f"Downloading blocklist: {name} from {url}")
            resp = requests.get(url, timeout=30, headers={
                "User-Agent": "Sentinel-Firewall/1.0"
            })
            resp.raise_for_status()
            content = resp.text

            # Save to cache
            cache_file.write_text(content, encoding="utf-8")

            domains = self._parse_content(content)
            logger.info(f"Downloaded {len(domains)} domains from: {name}")
            return domains

        except Exception as e:
            logger.error(f"Failed to download {name}: {e}")
            # Try cached version even if stale
            if cache_file.exists():
                return self._parse_file(cache_file)
            return set()

    def _parse_file(self, filepath: Path) -> Set[str]:
        """Parse a cached blocklist file."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            return self._parse_content(content)
        except Exception as e:
            logger.error(f"Failed to parse {filepath}: {e}")
            return set()

    def _parse_content(self, content: str) -> Set[str]:
        """Parse blocklist content (hosts format or plain domain list)."""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Try hosts file format first
            match = HOSTS_LINE_RE.match(line)
            if match:
                domain = match.group(1).lower()
                if domain not in ("localhost", "localhost.localdomain",
                                  "local", "broadcasthost", "ip6-localhost",
                                  "ip6-loopback"):
                    domains.add(domain)
                continue

            # Try plain domain format
            candidate = line.split("#")[0].strip().lower()
            if PLAIN_DOMAIN_RE.match(candidate):
                domains.add(candidate)

        return domains

    @staticmethod
    def _safe_filename(name: str) -> str:
        """Convert blocklist name to safe filename."""
        return re.sub(r"[^\w\-]", "_", name.lower())

    def get_stats(self) -> dict:
        return {
            "total_blocked_domains": self.blocked_count,
            "blocklists_loaded": sum(
                1 for b in self.blocklist_configs if b.get("enabled", True)
            ),
            "custom_blocked": len(self.custom_blocked),
            "whitelisted": len(self.whitelist),
            "last_update": self._last_update,
        }
