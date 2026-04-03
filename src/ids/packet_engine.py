"""
Packet Capture & Analysis Engine.
Uses Scapy for packet sniffing and provides parsed packet data
to the detection rules engine.
"""

import time
import threading
import logging
from collections import defaultdict
from typing import Optional, Callable

logger = logging.getLogger("sentinel.ids.engine")

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — IDS packet capture disabled")

from src.event_bus import event_bus, Event, EventType, Severity


class ParsedPacket:
    """Structured representation of a captured packet."""

    __slots__ = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "size", "flags", "payload", "raw_packet",
        "src_mac", "dst_mac", "dns_query", "is_outbound"
    ]

    def __init__(self):
        self.timestamp: float = 0.0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.protocol: str = ""
        self.size: int = 0
        self.flags: str = ""
        self.payload: bytes = b""
        self.raw_packet = None
        self.src_mac: str = ""
        self.dst_mac: str = ""
        self.dns_query: str = ""
        self.is_outbound: bool = False

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "flags": self.flags,
            "dns_query": self.dns_query,
            "is_outbound": self.is_outbound,
        }


class PacketEngine:
    """
    Captures packets using Scapy and dispatches parsed packets
    to registered analysis callbacks.
    """

    def __init__(self, interface: Optional[str] = None,
                 capture_filter: str = "ip",
                 max_packet_size: int = 65535):
        self.interface = interface
        self.capture_filter = capture_filter
        self.max_packet_size = max_packet_size
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []
        self._local_ips: set = set()
        self._arp_table: dict = {}  # IP -> MAC for ARP spoof detection

        # Traffic statistics
        self._stats_lock = threading.Lock()
        self._stats = {
            "packets_captured": 0,
            "bytes_captured": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "protocol_counts": defaultdict(int),
            "top_talkers": defaultdict(int),
        }
        self._window_packets = 0
        self._window_bytes = 0
        self._last_stats_time = time.time()

    def register_callback(self, callback: Callable):
        """Register a callback to receive parsed packets."""
        self._callbacks.append(callback)

    def start(self):
        """Start packet capture in a background thread."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not installed — cannot start packet engine")
            event_bus.publish(Event(
                event_type=EventType.SYSTEM_ERROR,
                severity=Severity.HIGH,
                source="packet_engine",
                message="Scapy not installed. Install with: pip install scapy",
            ))
            return

        self._detect_local_ips()
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True,
                                        name="packet-engine")
        self._thread.start()

        # Stats update thread
        threading.Thread(target=self._stats_loop, daemon=True,
                         name="packet-stats").start()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_START,
            severity=Severity.INFO,
            source="packet_engine",
            message=f"Packet engine started on interface: {self.interface or 'default'}",
        ))
        logger.info(f"Packet engine started (interface={self.interface})")

    def stop(self):
        """Stop packet capture."""
        self._running = False
        logger.info("Packet engine stopped")

    def _detect_local_ips(self):
        """Detect local IP addresses for outbound traffic classification."""
        try:
            import psutil
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in (2, 23):  # AF_INET, AF_INET6
                        self._local_ips.add(addr.address)
        except Exception:
            self._local_ips = {"127.0.0.1", "::1"}
        # Common private ranges
        self._local_ips.update(["127.0.0.1", "::1"])
        logger.debug(f"Local IPs detected: {self._local_ips}")

    def _capture_loop(self):
        """Main packet capture loop using Scapy."""
        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error(
                "Permission denied for packet capture. "
                "Run as administrator: python -m sentinel --admin"
            )
            event_bus.publish(Event(
                event_type=EventType.SYSTEM_ERROR,
                severity=Severity.CRITICAL,
                source="packet_engine",
                message="Packet capture requires administrator privileges",
            ))
        except Exception as e:
            logger.error(f"Packet capture error: {e}")

    def _process_packet(self, raw_pkt):
        """Parse a raw Scapy packet and dispatch to callbacks."""
        try:
            parsed = self._parse_packet(raw_pkt)
            if parsed is None:
                return

            # Update stats
            with self._stats_lock:
                self._stats["packets_captured"] += 1
                self._stats["bytes_captured"] += parsed.size
                self._stats["protocol_counts"][parsed.protocol] += 1
                self._stats["top_talkers"][parsed.dst_ip if parsed.is_outbound else parsed.src_ip] += 1
                self._window_packets += 1
                self._window_bytes += parsed.size

            # Dispatch to all registered callbacks
            for cb in self._callbacks:
                try:
                    cb(parsed)
                except Exception as e:
                    logger.error(f"Packet callback error: {e}")

            # Publish traffic flow event (sampled: every 100th packet)
            if self._stats["packets_captured"] % 100 == 0:
                event_bus.publish(Event(
                    event_type=EventType.TRAFFIC_FLOW,
                    severity=Severity.INFO,
                    source="packet_engine",
                    message=f"Traffic: {parsed.protocol} {parsed.src_ip}:{parsed.src_port} → {parsed.dst_ip}:{parsed.dst_port}",
                    data=parsed.to_dict(),
                ))

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def _parse_packet(self, raw_pkt) -> Optional[ParsedPacket]:
        """Parse a Scapy packet into a ParsedPacket."""
        if not raw_pkt.haslayer(IP):
            # Check for ARP
            if raw_pkt.haslayer(ARP):
                return self._parse_arp(raw_pkt)
            return None

        pkt = ParsedPacket()
        pkt.timestamp = time.time()
        pkt.raw_packet = raw_pkt

        ip_layer = raw_pkt[IP]
        pkt.src_ip = ip_layer.src
        pkt.dst_ip = ip_layer.dst
        pkt.size = len(raw_pkt)

        # Determine direction
        pkt.is_outbound = pkt.src_ip in self._local_ips

        # MAC addresses
        if raw_pkt.haslayer(Ether):
            pkt.src_mac = raw_pkt[Ether].src
            pkt.dst_mac = raw_pkt[Ether].dst

        # Protocol-specific parsing
        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            pkt.protocol = "TCP"
            pkt.src_port = tcp.sport
            pkt.dst_port = tcp.dport
            pkt.flags = str(tcp.flags)
            if raw_pkt.haslayer(Raw):
                pkt.payload = bytes(raw_pkt[Raw].load[:2048])  # Cap payload

        elif raw_pkt.haslayer(UDP):
            udp = raw_pkt[UDP]
            pkt.protocol = "UDP"
            pkt.src_port = udp.sport
            pkt.dst_port = udp.dport
            if raw_pkt.haslayer(Raw):
                pkt.payload = bytes(raw_pkt[Raw].load[:2048])

        elif raw_pkt.haslayer(ICMP):
            pkt.protocol = "ICMP"

        else:
            pkt.protocol = str(ip_layer.proto)

        # DNS query extraction
        if raw_pkt.haslayer(DNS) and raw_pkt[DNS].qr == 0:  # Query
            try:
                pkt.dns_query = raw_pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                pass

        return pkt

    def _parse_arp(self, raw_pkt) -> ParsedPacket:
        """Parse ARP packets for spoof detection."""
        arp = raw_pkt[ARP]
        pkt = ParsedPacket()
        pkt.timestamp = time.time()
        pkt.protocol = "ARP"
        pkt.src_ip = arp.psrc
        pkt.dst_ip = arp.pdst
        pkt.src_mac = arp.hwsrc
        pkt.dst_mac = arp.hwdst
        pkt.raw_packet = raw_pkt

        # Track ARP table for spoof detection
        if arp.op == 2:  # ARP reply
            existing_mac = self._arp_table.get(arp.psrc)
            if existing_mac and existing_mac != arp.hwsrc:
                pkt.flags = "SPOOF_SUSPECT"
            self._arp_table[arp.psrc] = arp.hwsrc

        return pkt

    def _stats_loop(self):
        """Periodically compute rates and publish stats."""
        while self._running:
            time.sleep(2)
            now = time.time()
            elapsed = now - self._last_stats_time
            if elapsed > 0:
                # Update rates and capture snapshot — all under lock
                with self._stats_lock:
                    self._stats["packets_per_second"] = round(self._window_packets / elapsed, 1)
                    self._stats["bytes_per_second"] = round(self._window_bytes / elapsed, 1)
                    self._window_packets = 0
                    self._window_bytes = 0
                    self._last_stats_time = now
                    # Take snapshot while we hold the lock, but DON'T call
                    # get_stats() here — it tries to re-acquire the same lock
                    snapshot = {
                        "packets_captured": self._stats["packets_captured"],
                        "bytes_captured": self._stats["bytes_captured"],
                        "packets_per_second": self._stats["packets_per_second"],
                        "bytes_per_second": self._stats["bytes_per_second"],
                        "protocol_counts": dict(self._stats["protocol_counts"]),
                        "top_talkers": dict(
                            sorted(self._stats["top_talkers"].items(),
                                   key=lambda x: x[1], reverse=True)[:20]
                        ),
                    }

                # Publish OUTSIDE the lock — event_bus callbacks (including
                # SocketIO emit) must not run while _stats_lock is held
                event_bus.publish(Event(
                    event_type=EventType.TRAFFIC_STATS,
                    severity=Severity.INFO,
                    source="packet_engine",
                    message="Traffic statistics update",
                    data=snapshot,
                ))

    def get_stats(self) -> dict:
        with self._stats_lock:
            return {
                "packets_captured": self._stats["packets_captured"],
                "bytes_captured": self._stats["bytes_captured"],
                "packets_per_second": self._stats["packets_per_second"],
                "bytes_per_second": self._stats["bytes_per_second"],
                "protocol_counts": dict(self._stats["protocol_counts"]),
                "top_talkers": dict(
                    sorted(self._stats["top_talkers"].items(),
                           key=lambda x: x[1], reverse=True)[:20]
                ),
            }
