"""
Threat Intelligence Feed Manager.
Downloads, parses, and indexes threat indicators from multiple
free intelligence sources. Supports IP blocklists, domain IOCs,
and hash-based file indicators.

Supported feeds:
  - Emerging Threats (Proofpoint) — IP blocklist
  - AbuseIPDB — Reported malicious IPs (requires free API key)
  - AlienVault OTX — Pulse-based indicators (requires free API key)
  - Feodo Tracker (abuse.ch) — Botnet C2 IPs
  - URLhaus (abuse.ch) — Malicious URLs/domains
  - ThreatFox (abuse.ch) — IOCs (IPs, domains, hashes)
  - Spamhaus DROP — Known hijacked IP ranges
  - SANS DShield — Top attacking IPs
"""

import os
import re
import time
import json
import ipaddress
import logging
import threading
from pathlib import Path
from typing import Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

import requests

from src.event_bus import event_bus, Event, EventType, Severity

logger = logging.getLogger("sentinel.threat_intel")


class IndicatorType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA256 = "sha256"


@dataclass
class Indicator:
    """A single threat indicator."""
    value: str
    indicator_type: IndicatorType
    source: str
    confidence: int = 50        # 0-100
    description: str = ""
    tags: list = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self):
        d = asdict(self)
        d["indicator_type"] = self.indicator_type.value
        return d


@dataclass
class FeedConfig:
    """Configuration for a single threat feed."""
    name: str
    url: str
    feed_type: str              # "ip_list", "domain_list", "stix", "json", "csv"
    enabled: bool = True
    api_key: str = ""
    update_interval: int = 3600  # seconds
    confidence: int = 70
    parser: str = "auto"         # "auto", "plain_ip", "plain_domain", "et_compromised", "abuse_ch", "otx_json"


# ──────────────────────────────────────────────────────────
# Built-in free feeds (no API key required)
# ──────────────────────────────────────────────────────────
BUILTIN_FEEDS = [
    FeedConfig(
        name="Emerging Threats Compromised IPs",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        feed_type="ip_list",
        parser="plain_ip",
        confidence=75,
    ),
    FeedConfig(
        name="Feodo Tracker Botnet C2",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        feed_type="ip_list",
        parser="plain_ip",
        confidence=90,
    ),
    FeedConfig(
        name="URLhaus Malicious Domains",
        url="https://urlhaus.abuse.ch/downloads/text_online/",
        feed_type="domain_list",
        parser="urlhaus",
        confidence=85,
    ),
    FeedConfig(
        name="Spamhaus DROP",
        url="https://www.spamhaus.org/drop/drop.txt",
        feed_type="ip_list",
        parser="spamhaus_drop",
        confidence=95,
    ),
    FeedConfig(
        name="Spamhaus EDROP",
        url="https://www.spamhaus.org/drop/edrop.txt",
        feed_type="ip_list",
        parser="spamhaus_drop",
        confidence=95,
    ),
    FeedConfig(
        name="SANS DShield Top Attackers",
        url="https://feeds.dshield.org/top10-2.txt",
        feed_type="ip_list",
        parser="dshield",
        confidence=70,
    ),
    FeedConfig(
        name="ThreatFox IOCs (Recent)",
        url="https://threatfox.abuse.ch/export/json/recent/",
        feed_type="json",
        parser="threatfox",
        confidence=80,
    ),
]

# IPv4 regex
IPV4_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


class ThreatIntelManager:
    """
    Central manager for all threat intelligence feeds.
    Maintains indexed sets for O(1) lookups during packet analysis.
    """

    def __init__(self, data_dir: str, feeds: list = None,
                 api_keys: dict = None, update_interval: int = 3600):
        self.data_dir = Path(data_dir) / "threat_intel"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.api_keys = api_keys or {}
        self.update_interval = update_interval
        self._lock = threading.RLock()

        # Build feed list from builtins + custom
        self.feeds: list[FeedConfig] = list(BUILTIN_FEEDS)
        if feeds:
            for fc in feeds:
                if isinstance(fc, dict):
                    fc = FeedConfig(**fc)
                self.feeds.append(fc)

        # Add API-key feeds if keys provided
        if self.api_keys.get("abuseipdb"):
            self.feeds.append(FeedConfig(
                name="AbuseIPDB Blacklist",
                url="https://api.abuseipdb.com/api/v2/blacklist",
                feed_type="json",
                parser="abuseipdb",
                api_key=self.api_keys["abuseipdb"],
                confidence=80,
            ))

        if self.api_keys.get("otx"):
            self.feeds.append(FeedConfig(
                name="AlienVault OTX Pulses",
                url="https://otx.alienvault.com/api/v1/indicators/export",
                feed_type="json",
                parser="otx",
                api_key=self.api_keys["otx"],
                confidence=75,
            ))

        # Indexed lookups — the core performance data structures
        self._malicious_ips: Set[str] = set()
        self._malicious_cidrs: list = []          # list of ipaddress networks
        self._malicious_domains: Set[str] = set()
        self._malicious_urls: Set[str] = set()
        self._malicious_hashes: Set[str] = set()
        self._all_indicators: list[Indicator] = []

        # Stats
        self._stats = {
            "total_indicators": 0,
            "malicious_ips": 0,
            "malicious_cidrs": 0,
            "malicious_domains": 0,
            "malicious_urls": 0,
            "malicious_hashes": 0,
            "feeds_loaded": 0,
            "feeds_failed": 0,
            "last_update": 0,
            "lookups_performed": 0,
            "hits": 0,
        }

        self._update_thread: Optional[threading.Thread] = None
        self._running = False

    def initialize(self):
        """Load all feeds — from cache first, then download."""
        logger.info("Initializing threat intelligence feeds...")
        self._load_all_feeds()
        self._index_indicators()
        self._running = True

        # Start background update thread
        self._update_thread = threading.Thread(
            target=self._update_loop, daemon=True, name="threat-intel-updater"
        )
        self._update_thread.start()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_START,
            severity=Severity.INFO,
            source="threat_intel",
            message=f"Threat intel loaded: {self._stats['total_indicators']} indicators from {self._stats['feeds_loaded']} feeds",
        ))
        logger.info(
            f"Threat intel ready: {self._stats['total_indicators']} indicators "
            f"({self._stats['malicious_ips']} IPs, {self._stats['malicious_cidrs']} CIDRs, "
            f"{self._stats['malicious_domains']} domains)"
        )

    def stop(self):
        self._running = False
        logger.info("Threat intel manager stopped")

    # ──────────────────────────────────────────────────────
    # Lookup methods — called from IDS for every packet
    # ──────────────────────────────────────────────────────

    def check_ip(self, ip: str) -> Optional[Indicator]:
        """Check if an IP is in threat feeds. O(1) for exact, O(n) for CIDR."""
        with self._lock:
            self._stats["lookups_performed"] += 1

            # Exact match
            if ip in self._malicious_ips:
                self._stats["hits"] += 1
                return self._find_indicator(ip, IndicatorType.IPV4)

            # CIDR match
            try:
                addr = ipaddress.ip_address(ip)
                for network in self._malicious_cidrs:
                    if addr in network:
                        self._stats["hits"] += 1
                        return Indicator(
                            value=str(network),
                            indicator_type=IndicatorType.CIDR,
                            source="threat_intel",
                            confidence=90,
                            description=f"IP {ip} falls within malicious range {network}",
                        )
            except ValueError:
                pass

        return None

    def check_domain(self, domain: str) -> Optional[Indicator]:
        """Check if a domain or any parent domain is in threat feeds."""
        domain = domain.lower().strip().rstrip(".")
        with self._lock:
            self._stats["lookups_performed"] += 1

            if domain in self._malicious_domains:
                self._stats["hits"] += 1
                return self._find_indicator(domain, IndicatorType.DOMAIN)

            # Check parent domains
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._malicious_domains:
                    self._stats["hits"] += 1
                    return Indicator(
                        value=parent,
                        indicator_type=IndicatorType.DOMAIN,
                        source="threat_intel",
                        confidence=70,
                        description=f"Parent domain {parent} is flagged (queried: {domain})",
                    )

        return None

    def check_hash(self, file_hash: str) -> Optional[Indicator]:
        """Check if a file hash is in threat feeds."""
        file_hash = file_hash.lower().strip()
        with self._lock:
            self._stats["lookups_performed"] += 1
            if file_hash in self._malicious_hashes:
                self._stats["hits"] += 1
                return self._find_indicator(file_hash, IndicatorType.MD5) or \
                       self._find_indicator(file_hash, IndicatorType.SHA256)
        return None

    def _find_indicator(self, value: str, itype: IndicatorType) -> Optional[Indicator]:
        """Find the full indicator record for a matched value."""
        for ind in self._all_indicators:
            if ind.value == value and ind.indicator_type == itype:
                return ind
        # Return a basic one if not found in detail list
        return Indicator(value=value, indicator_type=itype, source="threat_intel")

    # ──────────────────────────────────────────────────────
    # Feed loading and parsing
    # ──────────────────────────────────────────────────────

    def _load_all_feeds(self):
        """Load all enabled feeds."""
        for feed in self.feeds:
            if not feed.enabled:
                continue
            try:
                indicators = self._load_feed(feed)
                self._all_indicators.extend(indicators)
                self._stats["feeds_loaded"] += 1
                logger.info(f"Loaded {len(indicators)} indicators from: {feed.name}")
            except Exception as e:
                self._stats["feeds_failed"] += 1
                logger.error(f"Failed to load feed {feed.name}: {e}")

    def _load_feed(self, feed: FeedConfig) -> list[Indicator]:
        """Load a single feed — cache or download."""
        cache_file = self.data_dir / f"{self._safe_name(feed.name)}.json"

        # Use cache if fresh
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < feed.update_interval:
                return self._load_cache(cache_file)

        # Download
        content = self._download_feed(feed)
        if content is None:
            # Fall back to stale cache
            if cache_file.exists():
                return self._load_cache(cache_file)
            return []

        # Parse
        indicators = self._parse_feed(feed, content)

        # Cache
        self._save_cache(cache_file, indicators)

        return indicators

    # Maximum bytes to accept from any single feed download (50 MB)
    MAX_FEED_BYTES = 50 * 1024 * 1024

    def _download_feed(self, feed: FeedConfig) -> Optional[str]:
        """Download feed content with a hard size cap to prevent memory exhaustion."""
        headers = {"User-Agent": "Sentinel-Firewall/1.0"}
        kwargs = dict(headers=headers, timeout=30, stream=True)

        if feed.parser == "abuseipdb" and feed.api_key:
            headers["Key"] = feed.api_key
            headers["Accept"] = "application/json"
            kwargs["params"] = {"confidenceMinimum": 75, "limit": 10000}
        elif feed.parser == "otx" and feed.api_key:
            headers["X-OTX-API-KEY"] = feed.api_key

        try:
            resp = requests.get(feed.url, **kwargs)
        except requests.RequestException as e:
            logger.error(f"Feed {feed.name} request failed: {e}")
            return None

        if resp.status_code != 200:
            logger.warning(f"Feed {feed.name} returned HTTP {resp.status_code}")
            return None

        # Stream the response and enforce the size cap
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > self.MAX_FEED_BYTES:
                logger.warning(
                    f"Feed {feed.name} exceeded {self.MAX_FEED_BYTES // (1024*1024)} MB — "
                    "truncating. The feed URL may be compromised or misconfigured."
                )
                break
            chunks.append(chunk)

        return b"".join(chunks).decode("utf-8", errors="ignore")

    def _parse_feed(self, feed: FeedConfig, content: str) -> list[Indicator]:
        """Route to the appropriate parser."""
        parser_map = {
            "plain_ip": self._parse_plain_ip,
            "plain_domain": self._parse_plain_domain,
            "spamhaus_drop": self._parse_spamhaus_drop,
            "dshield": self._parse_dshield,
            "urlhaus": self._parse_urlhaus,
            "threatfox": self._parse_threatfox,
            "abuseipdb": self._parse_abuseipdb,
            "otx": self._parse_otx,
        }

        parser_fn = parser_map.get(feed.parser)
        if parser_fn:
            return parser_fn(content, feed)

        # Auto-detect
        return self._parse_auto(content, feed)

    def _parse_plain_ip(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse plain text IP list (one per line, comments with #)."""
        indicators = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Extract just the IP (some feeds have extra columns)
            parts = line.split()
            candidate = parts[0] if parts else line
            match = IPV4_RE.match(candidate)
            if match:
                ip = match.group(1)
                cidr = match.group(2)
                if cidr:
                    indicators.append(Indicator(
                        value=f"{ip}/{cidr}",
                        indicator_type=IndicatorType.CIDR,
                        source=feed.name,
                        confidence=feed.confidence,
                    ))
                else:
                    try:
                        ipaddress.ip_address(ip)
                        indicators.append(Indicator(
                            value=ip,
                            indicator_type=IndicatorType.IPV4,
                            source=feed.name,
                            confidence=feed.confidence,
                        ))
                    except ValueError:
                        pass
        return indicators

    def _parse_plain_domain(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse plain text domain list."""
        indicators = []
        for line in content.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            domain = line.split()[0] if " " in line else line
            if DOMAIN_RE.match(domain):
                indicators.append(Indicator(
                    value=domain,
                    indicator_type=IndicatorType.DOMAIN,
                    source=feed.name,
                    confidence=feed.confidence,
                ))
        return indicators

    def _parse_spamhaus_drop(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse Spamhaus DROP/EDROP format: CIDR ; SBL_ID"""
        indicators = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(";")
            cidr = parts[0].strip()
            sbl_id = parts[1].strip() if len(parts) > 1 else ""
            try:
                ipaddress.ip_network(cidr, strict=False)
                indicators.append(Indicator(
                    value=cidr,
                    indicator_type=IndicatorType.CIDR,
                    source=feed.name,
                    confidence=feed.confidence,
                    description=f"Spamhaus {sbl_id}".strip(),
                ))
            except ValueError:
                pass
        return indicators

    def _parse_dshield(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse SANS DShield top attackers format."""
        indicators = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 1:
                ip = parts[0].strip()
                match = IPV4_RE.match(ip)
                if match:
                    indicators.append(Indicator(
                        value=match.group(1),
                        indicator_type=IndicatorType.IPV4,
                        source=feed.name,
                        confidence=feed.confidence,
                        description="SANS DShield Top Attacker",
                    ))
        return indicators

    def _parse_urlhaus(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse URLhaus online URLs list."""
        indicators = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(line)
                host = parsed.hostname
                if host:
                    if IPV4_RE.match(host):
                        indicators.append(Indicator(
                            value=host,
                            indicator_type=IndicatorType.IPV4,
                            source=feed.name,
                            confidence=feed.confidence,
                            description="URLhaus malicious URL host",
                        ))
                    elif DOMAIN_RE.match(host):
                        indicators.append(Indicator(
                            value=host,
                            indicator_type=IndicatorType.DOMAIN,
                            source=feed.name,
                            confidence=feed.confidence,
                            description="URLhaus malicious URL host",
                        ))
                # Also store the full URL
                indicators.append(Indicator(
                    value=line,
                    indicator_type=IndicatorType.URL,
                    source=feed.name,
                    confidence=feed.confidence,
                ))
            except Exception:
                pass
        return indicators

    def _parse_threatfox(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse ThreatFox JSON export."""
        indicators = []
        try:
            data = json.loads(content)
            if data.get("query_status") != "ok":
                return indicators
            for item in data.get("data", []):
                if isinstance(item, dict):
                    items_list = [item]
                elif isinstance(item, list):
                    items_list = item
                else:
                    continue
                for entry in items_list:
                    ioc = entry.get("ioc", "")
                    ioc_type = entry.get("ioc_type", "")
                    malware = entry.get("malware_printable", "")
                    confidence_level = entry.get("confidence_level", 50)

                    if "ip" in ioc_type.lower():
                        # Format: "ip:port"
                        ip = ioc.split(":")[0]
                        if IPV4_RE.match(ip):
                            indicators.append(Indicator(
                                value=ip,
                                indicator_type=IndicatorType.IPV4,
                                source=feed.name,
                                confidence=min(confidence_level, 100),
                                description=f"ThreatFox: {malware}",
                                tags=[malware] if malware else [],
                            ))
                    elif "domain" in ioc_type.lower():
                        indicators.append(Indicator(
                            value=ioc.lower(),
                            indicator_type=IndicatorType.DOMAIN,
                            source=feed.name,
                            confidence=min(confidence_level, 100),
                            description=f"ThreatFox: {malware}",
                        ))
                    elif "md5" in ioc_type.lower():
                        indicators.append(Indicator(
                            value=ioc.lower(),
                            indicator_type=IndicatorType.MD5,
                            source=feed.name,
                            confidence=min(confidence_level, 100),
                            description=f"ThreatFox: {malware}",
                        ))
                    elif "sha256" in ioc_type.lower():
                        indicators.append(Indicator(
                            value=ioc.lower(),
                            indicator_type=IndicatorType.SHA256,
                            source=feed.name,
                            confidence=min(confidence_level, 100),
                            description=f"ThreatFox: {malware}",
                        ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"ThreatFox parse error: {e}")
        return indicators

    def _parse_abuseipdb(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse AbuseIPDB blacklist JSON response."""
        indicators = []
        try:
            data = json.loads(content)
            for entry in data.get("data", []):
                ip = entry.get("ipAddress", "")
                abuse_score = entry.get("abuseConfidenceScore", 0)
                if ip:
                    indicators.append(Indicator(
                        value=ip,
                        indicator_type=IndicatorType.IPV4,
                        source=feed.name,
                        confidence=min(abuse_score, 100),
                        description=f"AbuseIPDB score: {abuse_score}%",
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"AbuseIPDB parse error: {e}")
        return indicators

    def _parse_otx(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Parse AlienVault OTX indicator export."""
        indicators = []
        try:
            data = json.loads(content)
            results = data.get("results", data) if isinstance(data, dict) else data
            if not isinstance(results, list):
                results = [results]
            for entry in results:
                indicator = entry.get("indicator", "")
                ind_type = entry.get("type", "").lower()
                description = entry.get("description", "")

                if ind_type in ("ipv4", "ip"):
                    indicators.append(Indicator(
                        value=indicator,
                        indicator_type=IndicatorType.IPV4,
                        source=feed.name,
                        confidence=feed.confidence,
                        description=description or "AlienVault OTX",
                    ))
                elif ind_type in ("domain", "hostname"):
                    indicators.append(Indicator(
                        value=indicator.lower(),
                        indicator_type=IndicatorType.DOMAIN,
                        source=feed.name,
                        confidence=feed.confidence,
                        description=description or "AlienVault OTX",
                    ))
                elif ind_type == "url":
                    indicators.append(Indicator(
                        value=indicator,
                        indicator_type=IndicatorType.URL,
                        source=feed.name,
                        confidence=feed.confidence,
                    ))
                elif "md5" in ind_type or "filehash-md5" in ind_type:
                    indicators.append(Indicator(
                        value=indicator.lower(),
                        indicator_type=IndicatorType.MD5,
                        source=feed.name,
                        confidence=feed.confidence,
                    ))
                elif "sha256" in ind_type:
                    indicators.append(Indicator(
                        value=indicator.lower(),
                        indicator_type=IndicatorType.SHA256,
                        source=feed.name,
                        confidence=feed.confidence,
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"OTX parse error: {e}")
        return indicators

    def _parse_auto(self, content: str, feed: FeedConfig) -> list[Indicator]:
        """Auto-detect format and parse."""
        # Try JSON first
        try:
            json.loads(content)
            return self._parse_threatfox(content, feed)
        except json.JSONDecodeError:
            pass
        # Fall back to plain IP/domain parsing
        indicators = self._parse_plain_ip(content, feed)
        if not indicators:
            indicators = self._parse_plain_domain(content, feed)
        return indicators

    # ──────────────────────────────────────────────────────
    # Indexing
    # ──────────────────────────────────────────────────────

    def _index_indicators(self):
        """Build indexed sets for fast lookups."""
        with self._lock:
            self._malicious_ips.clear()
            self._malicious_cidrs.clear()
            self._malicious_domains.clear()
            self._malicious_urls.clear()
            self._malicious_hashes.clear()

            for ind in self._all_indicators:
                if ind.indicator_type == IndicatorType.IPV4:
                    self._malicious_ips.add(ind.value)
                elif ind.indicator_type == IndicatorType.IPV6:
                    self._malicious_ips.add(ind.value)
                elif ind.indicator_type == IndicatorType.CIDR:
                    try:
                        self._malicious_cidrs.append(
                            ipaddress.ip_network(ind.value, strict=False)
                        )
                    except ValueError:
                        pass
                elif ind.indicator_type == IndicatorType.DOMAIN:
                    self._malicious_domains.add(ind.value)
                elif ind.indicator_type == IndicatorType.URL:
                    self._malicious_urls.add(ind.value)
                elif ind.indicator_type in (IndicatorType.MD5, IndicatorType.SHA256):
                    self._malicious_hashes.add(ind.value)

            self._stats.update({
                "total_indicators": len(self._all_indicators),
                "malicious_ips": len(self._malicious_ips),
                "malicious_cidrs": len(self._malicious_cidrs),
                "malicious_domains": len(self._malicious_domains),
                "malicious_urls": len(self._malicious_urls),
                "malicious_hashes": len(self._malicious_hashes),
                "last_update": time.time(),
            })

    # ──────────────────────────────────────────────────────
    # Caching
    # ──────────────────────────────────────────────────────

    def _save_cache(self, path: Path, indicators: list[Indicator]):
        try:
            data = [ind.to_dict() for ind in indicators]
            path.write_text(json.dumps(data), encoding="utf-8")
        except Exception as e:
            logger.error(f"Cache save error: {e}")

    # Fields required in every cached indicator record
    _REQUIRED_INDICATOR_FIELDS = {"value", "indicator_type", "source", "confidence"}
    # All valid field names on the Indicator dataclass
    _VALID_INDICATOR_FIELDS = {
        "value", "indicator_type", "source", "confidence",
        "description", "tags", "first_seen", "last_seen",
    }

    def _load_cache(self, path: Path) -> list[Indicator]:
        """
        Load cached indicators from disk with schema validation.
        Validates each record before constructing Indicator objects so a
        tampered or corrupted cache file cannot inject unexpected data.
        """
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)

            if not isinstance(data, list):
                logger.error(f"Cache file {path} is not a list — discarding")
                path.unlink(missing_ok=True)
                return []

            indicators = []
            for i, d in enumerate(data):
                if not isinstance(d, dict):
                    continue

                # Must have all required fields
                missing = self._REQUIRED_INDICATOR_FIELDS - d.keys()
                if missing:
                    logger.debug(f"Cache record {i} missing fields {missing} — skipped")
                    continue

                # Strip any unexpected fields (no **d injection)
                clean = {k: v for k, v in d.items() if k in self._VALID_INDICATOR_FIELDS}

                # Validate types
                if not isinstance(clean.get("value"), str) or not clean["value"]:
                    continue
                if not isinstance(clean.get("source"), str):
                    continue
                confidence = clean.get("confidence", 50)
                if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
                    clean["confidence"] = 50

                try:
                    clean["indicator_type"] = IndicatorType(clean["indicator_type"])
                    indicators.append(Indicator(**clean))
                except (ValueError, TypeError) as e:
                    logger.debug(f"Cache record {i} invalid: {e} — skipped")

            return indicators
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Cache load error ({path}): {e}")
            return []

    # ──────────────────────────────────────────────────────
    # Background update loop
    # ──────────────────────────────────────────────────────

    def _update_loop(self):
        """Periodically refresh threat feeds."""
        while self._running:
            time.sleep(self.update_interval)
            if not self._running:
                break
            logger.info("Refreshing threat intelligence feeds...")
            try:
                new_indicators = []
                for feed in self.feeds:
                    if not feed.enabled:
                        continue
                    try:
                        indicators = self._load_feed(feed)
                        new_indicators.extend(indicators)
                    except Exception as e:
                        logger.error(f"Feed refresh error ({feed.name}): {e}")

                with self._lock:
                    self._all_indicators = new_indicators
                self._index_indicators()
                logger.info(f"Threat intel refreshed: {self._stats['total_indicators']} indicators")

                event_bus.publish(Event(
                    event_type=EventType.CONFIG_RELOAD,
                    severity=Severity.INFO,
                    source="threat_intel",
                    message=f"Threat intel refreshed: {self._stats['total_indicators']} indicators",
                    data=self.get_stats(),
                ))
            except Exception as e:
                logger.error(f"Threat intel refresh cycle error: {e}")

    @staticmethod
    def _safe_name(name: str) -> str:
        return re.sub(r"[^\w\-]", "_", name.lower())

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def get_feed_status(self) -> list[dict]:
        """Get status of all feeds."""
        result = []
        for feed in self.feeds:
            cache_file = self.data_dir / f"{self._safe_name(feed.name)}.json"
            cache_age = None
            cache_count = 0
            if cache_file.exists():
                cache_age = time.time() - cache_file.stat().st_mtime
                try:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    cache_count = len(data)
                except Exception:
                    pass
            result.append({
                "name": feed.name,
                "enabled": feed.enabled,
                "confidence": feed.confidence,
                "indicators": cache_count,
                "cache_age_seconds": round(cache_age) if cache_age else None,
                "requires_api_key": feed.parser in ("abuseipdb", "otx") and not feed.api_key,
            })
        return result
