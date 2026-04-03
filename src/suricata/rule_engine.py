"""
Suricata Rule Evaluation Engine.
Takes parsed SuricataRule objects and evaluates them against
captured packets from the packet engine.

This is the bridge between the Suricata rule format and
Sentinel's packet analysis pipeline.
"""

import re
import time
import logging
import ipaddress
import threading
import concurrent.futures
from collections import defaultdict
from typing import Optional

from src.event_bus import event_bus, Event, EventType, Severity
from src.ids.packet_engine import ParsedPacket
from src.suricata.rule_parser import (
    SuricataRule, RuleAction, RuleProtocol, ContentMatch, ThresholdConfig
)

_REGEX_TIMEOUT_SECONDS = 0.05  # 50ms hard cap per regex evaluation

logger = logging.getLogger("sentinel.suricata.engine")


class SuricataRuleEngine:
    """
    Evaluates Suricata rules against live packets.
    Registers as a packet callback in the packet engine.
    """

    def __init__(self, rules: list[SuricataRule] = None, variables: dict = None):
        self.rules: list[SuricataRule] = rules or []
        self.variables = variables or {}
        self._lock = threading.Lock()

        # Threshold tracking: sid -> {track_key -> (count, window_start)}
        self._threshold_state: dict[int, dict[str, list]] = defaultdict(
            lambda: defaultdict(lambda: [0, 0.0])
        )

        # Pre-compiled PCRE patterns cache
        self._pcre_cache: dict[str, re.Pattern] = {}

        # Stats
        self._stats = {
            "total_rules": 0,
            "enabled_rules": 0,
            "rules_by_action": {},
            "rules_by_protocol": {},
            "evaluations": 0,
            "matches": 0,
            "dropped": 0,
        }
        self._update_stats()

    def add_rules(self, rules: list[SuricataRule]):
        """Add rules to the engine."""
        with self._lock:
            self.rules.extend(rules)
        self._update_stats()
        logger.info(f"Added {len(rules)} Suricata rules (total: {len(self.rules)})")

    def analyze_packet(self, packet: ParsedPacket):
        """
        Evaluate all rules against a single packet.
        Called as a packet engine callback.
        """
        self._stats["evaluations"] += 1

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                if self._evaluate_rule(rule, packet):
                    self._stats["matches"] += 1
                    self._handle_match(rule, packet)
            except Exception as e:
                logger.debug(f"Rule evaluation error (sid:{rule.sid}): {e}")

    def _evaluate_rule(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Evaluate a single rule against a packet. Returns True if matched."""

        # 1. Protocol check
        if not self._match_protocol(rule, packet):
            return False

        # 2. IP address check
        if not self._match_addresses(rule, packet):
            return False

        # 3. Port check
        if not self._match_ports(rule, packet):
            return False

        # 4. Flow check
        if rule.flow and not self._match_flow(rule, packet):
            return False

        # 5. Content matching
        if rule.content_matches and not self._match_content(rule, packet):
            return False

        # 6. Threshold check
        if rule.threshold and not self._check_threshold(rule, packet):
            return False

        return True

    def _match_protocol(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Check if packet protocol matches rule protocol."""
        proto_map = {
            RuleProtocol.TCP: "TCP",
            RuleProtocol.UDP: "UDP",
            RuleProtocol.ICMP: "ICMP",
            RuleProtocol.IP: None,  # matches any IP
        }

        # Application-layer protocols map to transport
        app_proto_map = {
            RuleProtocol.HTTP: "TCP",
            RuleProtocol.DNS: "UDP",  # also TCP, but primarily UDP
            RuleProtocol.TLS: "TCP",
            RuleProtocol.SSH: "TCP",
            RuleProtocol.FTP: "TCP",
            RuleProtocol.SMTP: "TCP",
        }

        expected = proto_map.get(rule.protocol)
        if expected is None:
            expected = app_proto_map.get(rule.protocol)
        if expected is None:
            return True  # "ip" protocol matches everything

        return packet.protocol == expected

    def _match_addresses(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Check if src/dst IPs match the rule."""
        # Forward direction
        forward = (
            self._ip_matches(packet.src_ip, rule.src_ip) and
            self._ip_matches(packet.dst_ip, rule.dst_ip)
        )

        if forward:
            return True

        # Bidirectional: also check reverse
        if rule.bidirectional:
            reverse = (
                self._ip_matches(packet.src_ip, rule.dst_ip) and
                self._ip_matches(packet.dst_ip, rule.src_ip)
            )
            return reverse

        return False

    def _match_ports(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Check if ports match."""
        if not packet.src_port and not packet.dst_port:
            return rule.src_port == "any" and rule.dst_port == "any"

        # Forward direction
        forward = (
            self._port_matches(packet.src_port, rule.src_port) and
            self._port_matches(packet.dst_port, rule.dst_port)
        )

        if forward:
            return True

        if rule.bidirectional:
            reverse = (
                self._port_matches(packet.src_port, rule.dst_port) and
                self._port_matches(packet.dst_port, rule.src_port)
            )
            return reverse

        return False

    def _match_flow(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Check flow directives."""
        for directive in rule.flow:
            if directive == "established":
                # Simplification: check for ACK flag in TCP
                if packet.protocol == "TCP" and "A" not in packet.flags:
                    return False
            elif directive == "to_server":
                if not packet.is_outbound:
                    return False
            elif directive == "to_client":
                if packet.is_outbound:
                    return False
            elif directive == "from_server":
                if packet.is_outbound:
                    return False
            elif directive == "from_client":
                if not packet.is_outbound:
                    return False
        return True

    def _match_content(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Evaluate content matching rules against packet payload."""
        for cm in rule.content_matches:
            if cm.is_pcre:
                if not self._match_pcre(cm, packet):
                    return False
            else:
                if not self._match_single_content(cm, packet):
                    return False
        return True

    def _match_single_content(self, cm: ContentMatch, packet: ParsedPacket) -> bool:
        """Match a single content directive."""
        # Select the data to search based on buffer
        data = self._get_buffer_data(cm.buffer, packet)
        if not data:
            return cm.negated  # No data + negated = match

        pattern = cm.pattern
        if cm.nocase:
            data = data.lower()
            pattern = pattern.lower()

        # Apply offset/depth
        search_data = data
        if cm.offset is not None:
            search_data = data[cm.offset:]
        if cm.depth is not None:
            end = (cm.offset or 0) + cm.depth
            search_data = data[cm.offset or 0:end]

        found = pattern in search_data

        if cm.negated:
            return not found
        return found

    def _match_pcre(self, cm: ContentMatch, packet: ParsedPacket) -> bool:
        """Match a PCRE pattern."""
        data = self._get_buffer_data(cm.buffer, packet)
        if not data:
            return False

        pcre_str = cm.pcre_pattern
        # Parse Suricata PCRE format: /pattern/flags
        if pcre_str.startswith("/"):
            # Find the last /
            last_slash = pcre_str.rfind("/")
            if last_slash > 0:
                pattern = pcre_str[1:last_slash]
                flags_str = pcre_str[last_slash + 1:]
                flags = 0
                if "i" in flags_str:
                    flags |= re.IGNORECASE
                if "s" in flags_str:
                    flags |= re.DOTALL
                if "m" in flags_str:
                    flags |= re.MULTILINE

                # Cache compiled pattern
                cache_key = pcre_str
                if cache_key not in self._pcre_cache:
                    try:
                        self._pcre_cache[cache_key] = re.compile(
                            pattern.encode() if isinstance(pattern, str) else pattern,
                            flags
                        )
                    except re.error:
                        return False

                compiled = self._pcre_cache[cache_key]
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    future = ex.submit(compiled.search, data)
                    try:
                        return bool(future.result(timeout=_REGEX_TIMEOUT_SECONDS))
                    except concurrent.futures.TimeoutError:
                        logger.warning(
                            f"Suricata PCRE timed out (sid:{getattr(cm, 'sid', '?')}) — "
                            f"possible ReDoS: {pcre_str[:80]!r}"
                        )
                        return False

        return False

    def _get_buffer_data(self, buffer: str, packet: ParsedPacket) -> bytes:
        """Get the appropriate data buffer for content matching."""
        if buffer == "dns.query":
            return packet.dns_query.encode("utf-8", errors="ignore") if packet.dns_query else b""
        elif buffer in ("http.uri", "http.header", "http.method",
                        "http.host", "http.user_agent"):
            # For HTTP buffers, search the full payload
            # (a real implementation would parse HTTP headers)
            return packet.payload
        elif buffer == "pkt_data":
            return packet.payload
        else:
            # Default: search payload
            return packet.payload

    def _check_threshold(self, rule: SuricataRule, packet: ParsedPacket) -> bool:
        """Check if the threshold condition is met."""
        th = rule.threshold
        now = time.time()

        if th.track == "by_src":
            track_key = packet.src_ip
        elif th.track == "by_dst":
            track_key = packet.dst_ip
        else:
            track_key = "global"

        state = self._threshold_state[rule.sid][track_key]

        # Reset window if expired
        if now - state[1] > th.seconds:
            state[0] = 0
            state[1] = now

        state[0] += 1

        if th.threshold_type == "threshold":
            # Alert every Nth match
            return state[0] >= th.count and state[0] % th.count == 0
        elif th.threshold_type == "limit":
            # Alert at most N times per window
            return state[0] <= th.count
        elif th.threshold_type == "both":
            # Alert once when count reached
            return state[0] == th.count

        return True

    # ──────────────────────────────────────────────────────
    # IP/Port matching helpers
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _ip_matches(actual_ip: str, rule_spec: str) -> bool:
        """Check if an IP matches a rule specification (any, IP, CIDR, group, negation)."""
        if rule_spec == "any" or not rule_spec:
            return True

        negated = rule_spec.startswith("!")
        spec = rule_spec.lstrip("!")

        # Handle groups: [ip1,ip2,ip3]
        if spec.startswith("[") and spec.endswith("]"):
            inner = spec[1:-1]
            parts = [p.strip() for p in inner.split(",")]
            matched = any(SuricataRuleEngine._ip_matches(actual_ip, p) for p in parts)
            return not matched if negated else matched

        # CIDR match
        if "/" in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
                addr = ipaddress.ip_address(actual_ip)
                matched = addr in network
                return not matched if negated else matched
            except ValueError:
                return False

        # Exact match
        matched = actual_ip == spec
        return not matched if negated else matched

    @staticmethod
    def _port_matches(actual_port: int, rule_spec: str) -> bool:
        """Check if a port matches a rule specification."""
        if rule_spec == "any" or not rule_spec:
            return True

        negated = rule_spec.startswith("!")
        spec = rule_spec.lstrip("!")

        # Handle groups: [80,443,8080]
        if spec.startswith("[") and spec.endswith("]"):
            inner = spec[1:-1]
            parts = [p.strip() for p in inner.split(",")]
            matched = any(SuricataRuleEngine._port_matches(actual_port, p) for p in parts)
            return not matched if negated else matched

        # Range: 1024:65535
        if ":" in spec:
            parts = spec.split(":")
            low = int(parts[0]) if parts[0] else 0
            high = int(parts[1]) if parts[1] else 65535
            matched = low <= actual_port <= high
            return not matched if negated else matched

        # Exact
        try:
            matched = actual_port == int(spec)
            return not matched if negated else matched
        except ValueError:
            return False

    # ──────────────────────────────────────────────────────
    # Alert handling
    # ──────────────────────────────────────────────────────

    def _handle_match(self, rule: SuricataRule, packet: ParsedPacket):
        """Handle a rule match — publish alert or take action."""
        # Map priority to severity
        if rule.priority <= 1:
            severity = Severity.CRITICAL
        elif rule.priority == 2:
            severity = Severity.HIGH
        elif rule.priority == 3:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Map action
        if rule.action == RuleAction.DROP:
            self._stats["dropped"] += 1
            # Note: actual dropping requires WFP integration
            action_text = "[DROP] "
        elif rule.action == RuleAction.REJECT:
            action_text = "[REJECT] "
        else:
            action_text = ""

        message = (
            f"{action_text}Suricata rule match: {rule.msg} "
            f"({packet.src_ip}:{packet.src_port} → {packet.dst_ip}:{packet.dst_port})"
        )

        event_bus.publish(Event(
            event_type=EventType.IDS_ALERT,
            severity=severity,
            source="suricata",
            message=message,
            data={
                "rule": f"SID:{rule.sid} {rule.msg}",
                "sid": rule.sid,
                "rev": rule.rev,
                "classtype": rule.classtype,
                "priority": rule.priority,
                "action": rule.action.value,
                "src_ip": packet.src_ip,
                "src_port": packet.src_port,
                "dst_ip": packet.dst_ip,
                "dst_port": packet.dst_port,
                "protocol": packet.protocol,
                "detection_type": "suricata",
                "references": rule.reference,
            },
        ))

    def _update_stats(self):
        with self._lock:
            self._stats["total_rules"] = len(self.rules)
            self._stats["enabled_rules"] = sum(1 for r in self.rules if r.enabled)
            self._stats["rules_by_action"] = {}
            self._stats["rules_by_protocol"] = {}
            for r in self.rules:
                action = r.action.value
                self._stats["rules_by_action"][action] = \
                    self._stats["rules_by_action"].get(action, 0) + 1
                proto = r.protocol.value
                self._stats["rules_by_protocol"][proto] = \
                    self._stats["rules_by_protocol"].get(proto, 0) + 1

    def get_stats(self) -> dict:
        return dict(self._stats)
