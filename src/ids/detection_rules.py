"""
Intrusion Detection Rules Engine.
Implements pattern matching, anomaly detection, and signature-based
detection rules that analyze parsed packets from the packet engine.
"""

import re
import time
import logging
import threading
from collections import defaultdict, deque
from typing import Optional

from src.event_bus import event_bus, Event, EventType, Severity
from src.ids.packet_engine import ParsedPacket

# Max milliseconds any single regex match is allowed to run.
# Prevents ReDoS from catastrophically backtracking patterns in
# community rule files or user-supplied configs.
_REGEX_TIMEOUT_SECONDS = 0.05   # 50ms — more than enough for legit patterns


def _safe_regex_search(pattern, data: bytes):
    """
    Run a regex search with a hard timeout.
    Returns the match object or None.
    Logs a warning and returns None if the timeout is exceeded.
    """
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(pattern.search, data)
        try:
            return future.result(timeout=_REGEX_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            logger.warning(
                f"Regex pattern timed out after {_REGEX_TIMEOUT_SECONDS*1000:.0f}ms — "
                "possible ReDoS. Pattern may be catastrophically backtracking. "
                f"Pattern: {pattern.pattern[:80]!r}"
            )
            return None

logger = logging.getLogger("sentinel.ids.rules")


class DetectionContext:
    """
    Sliding window state for time-based detection rules.

    Uses a collections.deque so pruning expired entries is O(1) amortized —
    we pop from the left until we find an entry within the window, then stop.
    The previous list rebuild on every add() was O(n) and degraded badly
    under sustained heavy traffic.
    """

    def __init__(self, window_seconds: int = 60, max_events: int = 100_000):
        self.window = window_seconds
        self._max_events = max_events
        self._events: deque = deque()   # deque of (key, timestamp)
        self._lock = threading.Lock()

    def add(self, key: str, timestamp: float = None):
        ts = timestamp or time.time()
        with self._lock:
            self._events.append((key, ts))
            # Hard cap: drop oldest if we exceed max (prevents unbounded growth
            # under sustained flood with many unique source IPs)
            if len(self._events) > self._max_events:
                self._events.popleft()
            self._prune(ts)

    def count(self, key: str = None, since: float = None) -> int:
        now = time.time()
        cutoff = since or (now - self.window)
        with self._lock:
            self._prune(now)
            if key:
                return sum(1 for k, t in self._events if k == key and t >= cutoff)
            return len(self._events)   # all remaining are within window after prune

    def unique_keys(self, since: float = None) -> set:
        now = time.time()
        with self._lock:
            self._prune(now)
            return {k for k, t in self._events}

    def total_value(self, since: float = None) -> float:
        """Sum of keys interpreted as float values."""
        with self._lock:
            self._prune(time.time())
            total = 0.0
            for k, _ in self._events:
                try:
                    total += float(k)
                except ValueError:
                    pass
            return total

    def _prune(self, now: float):
        """Pop expired entries from the left — O(1) amortized vs O(n) list rebuild."""
        cutoff = now - self.window
        while self._events and self._events[0][1] < cutoff:
            self._events.popleft()


class BaseRule:
    """Base class for all detection rules."""

    def __init__(self, config: dict):
        self.name = config.get("name", "Unnamed Rule")
        self.enabled = config.get("enabled", True)
        self.description = config.get("description", "")
        self.threshold = config.get("threshold", 10)
        self.window_seconds = config.get("window_seconds", 60)
        self._context = DetectionContext(self.window_seconds)
        self._last_alert_time = 0
        self._alert_cooldown = 10  # seconds between alerts for same rule

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        raise NotImplementedError

    def _can_alert(self) -> bool:
        now = time.time()
        if now - self._last_alert_time > self._alert_cooldown:
            self._last_alert_time = now
            return True
        return False


class PortScanRule(BaseRule):
    """Detects port scanning: many connections to distinct ports from one source."""

    def __init__(self, config: dict):
        super().__init__(config)
        # Track per-source unique destination ports
        self._source_ports: dict[str, DetectionContext] = defaultdict(
            lambda: DetectionContext(self.window_seconds)
        )

    # Max unique source IPs to track — prevents unbounded memory under
    # a spoofed-source flood (each entry holds a DetectionContext deque)
    MAX_TRACKED_SOURCES = 10_000

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if packet.protocol not in ("TCP", "UDP"):
            return None
        if not packet.dst_port:
            return None

        src = packet.src_ip
        # Evict oldest source if we are at capacity
        if src not in self._source_ports and len(self._source_ports) >= self.MAX_TRACKED_SOURCES:
            oldest = next(iter(self._source_ports))
            del self._source_ports[oldest]

        ctx = self._source_ports[src]
        ctx.add(str(packet.dst_port))

        unique_ports = len(ctx.unique_keys())
        if unique_ports >= self.threshold and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.HIGH,
                source="ids",
                message=f"Port scan detected from {src}: {unique_ports} unique ports in {self.window_seconds}s",
                data={
                    "rule": self.name,
                    "attacker_ip": src,
                    "unique_ports": unique_ports,
                    "threshold": self.threshold,
                    "detection_type": "port_scan",
                },
            )
        return None


class SynFloodRule(BaseRule):
    """Detects SYN flood attacks: excessive SYN packets without completion."""

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if packet.protocol != "TCP" or "S" not in packet.flags:
            return None
        # Only count SYN without ACK (initial SYN)
        if "A" in packet.flags:
            return None

        self._context.add(packet.src_ip)
        count = self._context.count()

        if count >= self.threshold and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.CRITICAL,
                source="ids",
                message=f"SYN flood detected: {count} SYN packets in {self.window_seconds}s",
                data={
                    "rule": self.name,
                    "syn_count": count,
                    "threshold": self.threshold,
                    "detection_type": "syn_flood",
                },
            )
        return None


class DNSTunnelRule(BaseRule):
    """Detects DNS tunneling: unusually long or frequent DNS queries."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.query_length_threshold = config.get("query_length_threshold", 50)
        self.frequency_threshold = config.get("frequency_threshold", 30)
        self._domain_queries: dict[str, DetectionContext] = defaultdict(
            lambda: DetectionContext(60)
        )

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if not packet.dns_query:
            return None

        query = packet.dns_query
        # Check for unusually long subdomain (data exfil via DNS)
        labels = query.split(".")
        if labels and len(labels[0]) > self.query_length_threshold and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.HIGH,
                source="ids",
                message=f"Possible DNS tunneling: unusually long query ({len(labels[0])} chars) to {query}",
                data={
                    "rule": self.name,
                    "domain": query,
                    "label_length": len(labels[0]),
                    "detection_type": "dns_tunnel",
                },
            )

        # Check for high frequency to same base domain
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else query
        ctx = self._domain_queries[base_domain]
        ctx.add(query)
        freq = ctx.count()

        if freq >= self.frequency_threshold and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.MEDIUM,
                source="ids",
                message=f"High DNS query frequency to {base_domain}: {freq} queries/min",
                data={
                    "rule": self.name,
                    "domain": base_domain,
                    "query_count": freq,
                    "detection_type": "dns_tunnel_frequency",
                },
            )
        return None


class SignatureRule(BaseRule):
    """Detects known attack patterns by port and connection frequency."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.protocol = config.get("protocol", "tcp").upper()
        self.dst_port = config.get("dst_port", 0)

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if packet.protocol != self.protocol:
            return None
        if self.dst_port and packet.dst_port != self.dst_port:
            return None

        self._context.add(packet.src_ip)
        count = self._context.count(packet.src_ip)

        if count >= self.threshold and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.MEDIUM,
                source="ids",
                message=f"{self.name}: {count} attempts from {packet.src_ip} to port {packet.dst_port}",
                data={
                    "rule": self.name,
                    "attacker_ip": packet.src_ip,
                    "target_port": packet.dst_port,
                    "attempt_count": count,
                    "detection_type": "signature",
                },
            )
        return None


class PayloadMatchRule(BaseRule):
    """Detects suspicious content in packet payloads using regex."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.protocol = config.get("protocol", "tcp").upper()
        pattern_str = config.get("pattern", "")

        if not pattern_str:
            logger.warning(
                f"PayloadMatchRule '{self.name}' has an empty pattern — rule disabled. "
                "An empty regex matches every packet and would flood the event bus."
            )
            self.enabled = False
            self._pattern = None
            return

        try:
            raw = pattern_str.encode() if isinstance(pattern_str, str) else pattern_str
            self._pattern = re.compile(raw)
        except re.error as e:
            logger.error(
                f"PayloadMatchRule '{self.name}' has an invalid regex pattern: {e} — rule disabled."
            )
            self.enabled = False
            self._pattern = None

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if not self._pattern:
            return None
        if packet.protocol != self.protocol:
            return None
        if not packet.payload:
            return None

        match = _safe_regex_search(self._pattern, packet.payload)
        if match and self._can_alert():
            matched_text = match.group(0).decode("utf-8", errors="replace")
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.HIGH,
                source="ids",
                message=f"Suspicious payload detected: '{matched_text}' from {packet.src_ip}",
                data={
                    "rule": self.name,
                    "matched": matched_text,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "dst_port": packet.dst_port,
                    "detection_type": "payload_match",
                },
            )
        return None


class ARPSpoofRule(BaseRule):
    """Detects ARP spoofing / cache poisoning attempts."""

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if packet.protocol != "ARP":
            return None
        if packet.flags == "SPOOF_SUSPECT" and self._can_alert():
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.CRITICAL,
                source="ids",
                message=f"ARP spoofing detected: {packet.src_ip} changed MAC from cache to {packet.src_mac}",
                data={
                    "rule": self.name,
                    "ip": packet.src_ip,
                    "new_mac": packet.src_mac,
                    "detection_type": "arp_spoof",
                },
            )
        return None


class DataExfilRule(BaseRule):
    """Detects unusually large outbound data transfers."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.threshold_bytes = config.get("threshold_mb", 100) * 1024 * 1024
        self._context = DetectionContext(config.get("window_seconds", 300))

    def analyze(self, packet: ParsedPacket) -> Optional[Event]:
        if not packet.is_outbound:
            return None

        self._context.add(str(packet.size))
        total_bytes = self._context.total_value()

        if total_bytes >= self.threshold_bytes and self._can_alert():
            mb = round(total_bytes / (1024 * 1024), 1)
            return Event(
                event_type=EventType.IDS_ALERT,
                severity=Severity.HIGH,
                source="ids",
                message=f"Large outbound transfer: {mb} MB in {self.window_seconds}s",
                data={
                    "rule": self.name,
                    "total_mb": mb,
                    "threshold_mb": round(self.threshold_bytes / (1024 * 1024), 1),
                    "detection_type": "data_exfil",
                },
            )
        return None


# Rule factory
RULE_TYPES = {
    "port_scan": PortScanRule,
    "syn_flood": SynFloodRule,
    "dns_tunnel": DNSTunnelRule,
    "signature": SignatureRule,
    "payload_match": PayloadMatchRule,
    "arp_spoof": ARPSpoofRule,
    "data_exfil": DataExfilRule,
}


class RulesEngine:
    """Manages and executes all detection rules against captured packets."""

    def __init__(self, rule_configs: list):
        self.rules: list[BaseRule] = []
        self._alert_count = 0
        self._lock = threading.Lock()

        for config in rule_configs:
            rule_type = config.get("type", "")
            if rule_type in RULE_TYPES and config.get("enabled", True):
                try:
                    rule = RULE_TYPES[rule_type](config)
                    self.rules.append(rule)
                    logger.info(f"Loaded IDS rule: {rule.name} ({rule_type})")
                except Exception as e:
                    logger.error(f"Failed to load rule {config.get('name')}: {e}")

        logger.info(f"Rules engine initialized with {len(self.rules)} rules")

    def analyze_packet(self, packet: ParsedPacket):
        """Run all rules against a single packet."""
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                alert = rule.analyze(packet)
                if alert:
                    with self._lock:
                        self._alert_count += 1
                    event_bus.publish(alert)
            except Exception as e:
                logger.error(f"Rule {rule.name} error: {e}")

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_rules": len(self.rules),
                "active_rules": sum(1 for r in self.rules if r.enabled),
                "total_alerts": self._alert_count,
                "rules": [
                    {"name": r.name, "type": type(r).__name__, "enabled": r.enabled}
                    for r in self.rules
                ],
            }
