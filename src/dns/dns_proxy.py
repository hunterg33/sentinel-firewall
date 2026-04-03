"""
DNS Filtering Proxy.
Intercepts DNS queries on a local port, checks against blocklists,
and either blocks (returns NXDOMAIN) or forwards to upstream DNS.
"""

import socket
import struct
import threading
import logging
import time
from typing import Optional

from src.event_bus import event_bus, Event, EventType, Severity
from src.dns.blocklist import BlocklistManager

logger = logging.getLogger("sentinel.dns.proxy")


class DNSPacket:
    """Minimal DNS packet parser/builder for proxying."""

    def __init__(self, raw_data: bytes):
        self.raw = raw_data
        self.id = struct.unpack("!H", raw_data[:2])[0]
        self.flags = struct.unpack("!H", raw_data[2:4])[0]
        self.qd_count = struct.unpack("!H", raw_data[4:6])[0]
        self.domain = self._extract_domain()

    def _extract_domain(self) -> str:
        domain_parts = []
        offset = 12
        try:
            while offset < len(self.raw):
                length = self.raw[offset]
                if length == 0:
                    break
                offset += 1
                domain_parts.append(self.raw[offset:offset + length].decode("ascii", errors="ignore"))
                offset += length
            return ".".join(domain_parts).lower()
        except (IndexError, UnicodeDecodeError):
            return ""

    def get_query_type(self) -> str:
        try:
            offset = 12
            while offset < len(self.raw) and self.raw[offset] != 0:
                offset += self.raw[offset] + 1
            offset += 1
            qtype = struct.unpack("!H", self.raw[offset:offset + 2])[0]
            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 16: "TXT"}
            return type_map.get(qtype, str(qtype))
        except (IndexError, struct.error):
            return "?"

    @staticmethod
    def build_blocked_response(query_data: bytes) -> bytes:
        response = bytearray(query_data[:2])
        response += struct.pack("!H", 0x8180)
        response += struct.pack("!HHHH", 1, 1, 0, 0)

        offset = 12
        while offset < len(query_data) and query_data[offset] != 0:
            offset += query_data[offset] + 1
        offset += 5

        response += query_data[12:offset]
        response += b"\xc0\x0c"
        response += struct.pack("!HH", 1, 1)
        response += struct.pack("!I", 60)
        response += struct.pack("!H", 4)
        response += socket.inet_aton("0.0.0.0")

        return bytes(response)


class DNSProxy:
    """UDP DNS proxy server with blocklist filtering."""

    def __init__(self, blocklist_manager: BlocklistManager,
                 listen_addr: str = "127.0.0.1",
                 listen_port: int = 5353,
                 upstream_dns: str = "8.8.8.8",
                 upstream_port: int = 53):
        self.blocklist = blocklist_manager
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "forwarded_queries": 0,
            "cache_hits": 0,
            "errors": 0,
        }
        self._cache: dict = {}
        self._cache_ttl = 300

    def start(self):
        """Start the DNS proxy server."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._socket.bind((self.listen_addr, self.listen_port))
        except PermissionError:
            logger.error(
                f"Cannot bind to {self.listen_addr}:{self.listen_port}. "
                "Run as administrator or use port > 1024."
            )
            return
        except OSError as e:
            logger.error(f"Socket error: {e}")
            return

        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True, name="dns-proxy")
        self._thread.start()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_START,
            severity=Severity.INFO,
            source="dns_proxy",
            message=f"DNS proxy listening on {self.listen_addr}:{self.listen_port}",
        ))
        logger.info(f"DNS proxy started on {self.listen_addr}:{self.listen_port}")

    def stop(self):
        self._running = False
        if self._socket:
            self._socket.close()
        logger.info("DNS proxy stopped")

    def _serve(self):
        """Main server loop."""
        self._socket.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                self._handle_query(data, addr)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                if self._running:
                    logger.error("Socket error in DNS proxy")
                break

    def _handle_query(self, data: bytes, client_addr: tuple):
        try:
            packet = DNSPacket(data)
            domain = packet.domain
            query_type = packet.get_query_type()
            self._stats["total_queries"] += 1

            if not domain:
                return

            if self.blocklist.is_blocked(domain):
                self._stats["blocked_queries"] += 1
                response = DNSPacket.build_blocked_response(data)
                self._socket.sendto(response, client_addr)

                event_bus.publish(Event(
                    event_type=EventType.DNS_BLOCKED,
                    severity=Severity.LOW,
                    source="dns_proxy",
                    message=f"Blocked: {domain} ({query_type})",
                    data={"domain": domain, "query_type": query_type, "client": client_addr[0]}
                ))
                return

            cache_key = f"{domain}:{query_type}"
            cached = self._cache.get(cache_key)
            if cached and (time.time() - cached["time"]) < self._cache_ttl:
                response = bytearray(cached["data"])
                response[0:2] = data[0:2]
                self._socket.sendto(bytes(response), client_addr)
                self._stats["cache_hits"] += 1
                return

            self._stats["forwarded_queries"] += 1
            response = self._forward_query(data)
            if response:
                self._socket.sendto(response, client_addr)
                self._cache[cache_key] = {"data": response, "time": time.time()}

                event_bus.publish(Event(
                    event_type=EventType.DNS_RESOLVED,
                    severity=Severity.INFO,
                    source="dns_proxy",
                    message=f"Resolved: {domain} ({query_type})",
                    data={"domain": domain, "query_type": query_type, "client": client_addr[0]}
                ))

        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"DNS query handling error: {e}")

    def _forward_query(self, data: bytes) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(data, (self.upstream_dns, self.upstream_port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
        except Exception as e:
            logger.error(f"Upstream DNS query failed: {e}")
            return None

    def get_stats(self) -> dict:
        return dict(self._stats)
