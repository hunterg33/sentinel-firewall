"""
Threat Intelligence ↔ IDS Integration.
Registers as a packet callback alongside existing detection rules,
checking every packet's source/dest IP and DNS queries against
threat intelligence feeds.
"""

import logging
from typing import Optional

from src.event_bus import event_bus, Event, EventType, Severity
from src.ids.packet_engine import ParsedPacket
from src.threat_intel.feed_manager import ThreatIntelManager, Indicator

logger = logging.getLogger("sentinel.threat_intel.ids")


class ThreatIntelDetector:
    """
    Packet analysis callback that checks IPs and domains against
    threat intelligence feeds and fires IDS alerts on matches.
    """

    def __init__(self, threat_intel: ThreatIntelManager):
        self.threat_intel = threat_intel
        self._alert_cooldown: dict[str, float] = {}  # key -> last_alert_time
        self._cooldown_seconds = 30  # Don't re-alert on same indicator within 30s

    def analyze_packet(self, packet: ParsedPacket):
        """Called for every captured packet — check against threat intel."""
        import time

        # Check source IP
        if packet.src_ip:
            indicator = self.threat_intel.check_ip(packet.src_ip)
            if indicator:
                self._fire_alert(packet, indicator, direction="inbound")

        # Check destination IP
        if packet.dst_ip:
            indicator = self.threat_intel.check_ip(packet.dst_ip)
            if indicator:
                self._fire_alert(packet, indicator, direction="outbound")

        # Check DNS queries
        if packet.dns_query:
            indicator = self.threat_intel.check_domain(packet.dns_query)
            if indicator:
                self._fire_alert(packet, indicator, direction="dns")

    def _fire_alert(self, packet: ParsedPacket, indicator: Indicator, direction: str):
        """Publish an IDS alert for a threat intel match."""
        import time

        # Cooldown: don't spam alerts for the same indicator
        key = f"{indicator.value}:{direction}"
        now = time.time()
        last = self._alert_cooldown.get(key, 0)
        if now - last < self._cooldown_seconds:
            return
        self._alert_cooldown[key] = now

        # Map confidence to severity
        if indicator.confidence >= 90:
            severity = Severity.CRITICAL
        elif indicator.confidence >= 75:
            severity = Severity.HIGH
        elif indicator.confidence >= 50:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        if direction == "dns":
            message = (
                f"Threat intel match: DNS query to known malicious domain "
                f"{indicator.value} (source: {indicator.source}, "
                f"confidence: {indicator.confidence}%)"
            )
        elif direction == "inbound":
            message = (
                f"Threat intel match: inbound traffic from known malicious IP "
                f"{indicator.value} → {packet.dst_ip}:{packet.dst_port} "
                f"(source: {indicator.source}, confidence: {indicator.confidence}%)"
            )
        else:
            message = (
                f"Threat intel match: outbound traffic to known malicious IP "
                f"{packet.src_ip} → {indicator.value}:{packet.dst_port} "
                f"(source: {indicator.source}, confidence: {indicator.confidence}%)"
            )

        event_bus.publish(Event(
            event_type=EventType.IDS_ALERT,
            severity=severity,
            source="threat_intel",
            message=message,
            data={
                "rule": "Threat Intelligence Match",
                "indicator": indicator.value,
                "indicator_type": indicator.indicator_type.value,
                "source_feed": indicator.source,
                "confidence": indicator.confidence,
                "description": indicator.description,
                "direction": direction,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "dst_port": packet.dst_port,
                "protocol": packet.protocol,
                "detection_type": "threat_intel",
            },
        ))
