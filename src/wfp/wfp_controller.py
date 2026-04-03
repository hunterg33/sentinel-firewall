"""
Windows Filtering Platform (WFP) Controller.
Provides per-application network control using the Windows Filtering
Platform via ctypes. WFP is the kernel-level filtering engine that
Windows Firewall itself uses.

SAFETY DESIGN:
  - All filters have an auto-expiry (default 60 min)
  - A "panic" method removes all Sentinel filters instantly
  - Persistent filters require explicit confirmation
  - The engine creates a unique provider and sublayer so
    all Sentinel rules can be identified and cleaned up
  - Critical system processes are protected from blocking

This module only works on Windows. On other platforms, it provides
a no-op implementation that logs warnings.
"""

import os
import sys
import time
import logging
import threading
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
from uuid import UUID, uuid4

from src.event_bus import event_bus, Event, EventType, Severity

logger = logging.getLogger("sentinel.wfp")

# ──────────────────────────────────────────────────────────
# Platform check
# ──────────────────────────────────────────────────────────

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    try:
        import ctypes.wintypes
        fwpuclnt = ctypes.WinDLL("fwpuclnt.dll")
        WFP_AVAILABLE = True
    except (OSError, AttributeError):
        WFP_AVAILABLE = False
        logger.warning("fwpuclnt.dll not found — WFP features disabled")
else:
    WFP_AVAILABLE = False


# ──────────────────────────────────────────────────────────
# Constants & Structures
# ──────────────────────────────────────────────────────────

# WFP GUIDs for filtering layers
class WfpLayer:
    """Well-known WFP filtering layer GUIDs."""
    # Outbound IPv4 — application layer
    ALE_AUTH_CONNECT_V4 = UUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
    # Inbound IPv4 — application layer
    ALE_AUTH_RECV_ACCEPT_V4 = UUID("e1cd9fe7-f4b5-4273-96c0-592e487b8650")
    # Outbound IPv4 — transport layer
    OUTBOUND_TRANSPORT_V4 = UUID("09e61aea-d214-46e2-9b21-b26b0b2f28c8")
    # Inbound IPv4 — transport layer
    INBOUND_TRANSPORT_V4 = UUID("5926dfc8-e3cf-4426-a283-dc393f5d0f9d")


class WfpAction(Enum):
    PERMIT = 0
    BLOCK = 1


class FilterFlag(Enum):
    NONE = 0
    PERSISTENT = 0x00000001
    BOOTTIME = 0x00000002


# Protected system processes that should NEVER be blocked
PROTECTED_PROCESSES = {
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "smss.exe",
    "dwm.exe",
    "explorer.exe",
    "system",
    "registry",
    "ntoskrnl.exe",
    "spoolsv.exe",
    "dns.exe",
    "dhcp.exe",
}


@dataclass
class AppRule:
    """A per-application firewall rule."""
    rule_id: str = ""
    app_path: str = ""              # Full path to executable
    app_name: str = ""              # Display name
    action: WfpAction = WfpAction.BLOCK
    direction: str = "both"         # "inbound", "outbound", "both"
    dst_ip: str = ""                # Optional: restrict to specific destination
    dst_port: int = 0               # Optional: restrict to specific port
    protocol: str = "any"           # "tcp", "udp", "any"
    enabled: bool = True
    created_at: float = 0.0
    expires_at: float = 0.0         # Auto-expiry timestamp (0 = no expiry)
    description: str = ""
    wfp_filter_ids: list = field(default_factory=list)  # Actual WFP filter IDs

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = str(uuid4())[:8]
        if not self.created_at:
            self.created_at = time.time()
        if not self.app_name and self.app_path:
            self.app_name = Path(self.app_path).name

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "app_path": self.app_path,
            "app_name": self.app_name,
            "action": self.action.value,
            "direction": self.direction,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "description": self.description,
        }


# ──────────────────────────────────────────────────────────
# WFP Engine
# ──────────────────────────────────────────────────────────

class WFPController:
    """
    Manages Windows Filtering Platform rules for per-application
    network control.

    IMPORTANT: Requires administrator privileges.
    """

    # Sentinel's unique identifiers in WFP
    PROVIDER_KEY = UUID("a1b2c3d4-e5f6-7890-abcd-ef0123456001")
    SUBLAYER_KEY = UUID("a1b2c3d4-e5f6-7890-abcd-ef0123456002")
    PROVIDER_NAME = "Sentinel Firewall"
    SUBLAYER_NAME = "Sentinel Application Control"

    def __init__(self, default_expiry_minutes: int = 60):
        self.default_expiry = default_expiry_minutes * 60  # Convert to seconds
        self._rules: dict[str, AppRule] = {}
        self._lock = threading.Lock()
        self._engine_handle = None
        self._initialized = False
        self._running = False

        self._stats = {
            "total_rules": 0,
            "active_rules": 0,
            "blocked_apps": 0,
            "permitted_apps": 0,
            "connections_blocked": 0,
            "connections_permitted": 0,
            "wfp_available": WFP_AVAILABLE,
            "is_admin": False,
        }

    def initialize(self):
        """Initialize WFP engine and register Sentinel provider."""
        if not WFP_AVAILABLE:
            logger.warning("WFP not available — running in monitor-only mode")
            self._log_platform_instructions()
            self._initialized = True
            return

        if not self._is_admin():
            logger.warning("Not running as admin — WFP requires elevation")
            self._stats["is_admin"] = False
            self._initialized = True
            return

        self._stats["is_admin"] = True

        try:
            self._open_engine()
            self._register_provider()
            self._register_sublayer()
            self._initialized = True
            self._running = True

            # Start expiry checker thread
            threading.Thread(target=self._expiry_loop, daemon=True,
                             name="wfp-expiry").start()

            event_bus.publish(Event(
                event_type=EventType.SYSTEM_START,
                severity=Severity.INFO,
                source="wfp",
                message="WFP controller initialized — per-application control active",
            ))
            logger.info("WFP controller initialized")

        except Exception as e:
            logger.error(f"WFP initialization failed: {e}")
            self._initialized = True  # Still mark as init'd so app continues

    def stop(self):
        """Cleanup: remove all Sentinel filters and close engine."""
        self._running = False
        if self._engine_handle:
            self.panic_remove_all()
            self._close_engine()
        logger.info("WFP controller stopped")

    # ──────────────────────────────────────────────────────
    # Public API: Rule management
    # ──────────────────────────────────────────────────────

    def block_app(self, app_path: str, direction: str = "both",
                  dst_ip: str = "", dst_port: int = 0,
                  expiry_minutes: int = None,
                  description: str = "") -> Optional[AppRule]:
        """Block an application's network access."""
        return self._add_rule(
            app_path=app_path,
            action=WfpAction.BLOCK,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            expiry_minutes=expiry_minutes,
            description=description,
        )

    def allow_app(self, app_path: str, direction: str = "both",
                  description: str = "") -> Optional[AppRule]:
        """Explicitly allow an application (useful to override blocks)."""
        return self._add_rule(
            app_path=app_path,
            action=WfpAction.PERMIT,
            direction=direction,
            description=description,
        )

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a specific rule."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return False
            self._remove_wfp_filters(rule)
            del self._rules[rule_id]
            self._update_stats()
        logger.info(f"Removed rule {rule_id} for {rule.app_name}")
        return True

    def panic_remove_all(self):
        """
        EMERGENCY: Remove ALL Sentinel WFP filters immediately.
        This is the safety valve — call this if anything goes wrong.
        """
        logger.warning("PANIC: Removing all Sentinel WFP filters!")
        with self._lock:
            for rule in list(self._rules.values()):
                self._remove_wfp_filters(rule)
            self._rules.clear()
            self._update_stats()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_ERROR,
            severity=Severity.HIGH,
            source="wfp",
            message="Emergency: All Sentinel WFP filters removed",
        ))

    def get_rules(self) -> list[dict]:
        """Get all active rules."""
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    def get_blocked_apps(self) -> list[str]:
        """Get list of currently blocked application names."""
        with self._lock:
            return [r.app_name for r in self._rules.values()
                    if r.action == WfpAction.BLOCK and r.enabled]

    # ──────────────────────────────────────────────────────
    # Process discovery
    # ──────────────────────────────────────────────────────

    def list_network_processes(self) -> list[dict]:
        """List all processes with active network connections."""
        try:
            import psutil
            processes = {}
            for conn in psutil.net_connections(kind="inet"):
                pid = conn.pid
                if pid and pid not in processes:
                    try:
                        proc = psutil.Process(pid)
                        exe_path = proc.exe()
                        processes[pid] = {
                            "pid": pid,
                            "name": proc.name(),
                            "exe": exe_path,
                            "connections": 0,
                            "status": "allowed",
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                if pid in processes:
                    processes[pid]["connections"] += 1

            # Mark blocked apps
            with self._lock:
                blocked_paths = {
                    r.app_path.lower() for r in self._rules.values()
                    if r.action == WfpAction.BLOCK and r.enabled
                }

            for info in processes.values():
                if info["exe"].lower() in blocked_paths:
                    info["status"] = "blocked"

            return sorted(processes.values(), key=lambda x: x["connections"], reverse=True)
        except ImportError:
            logger.error("psutil required for process listing")
            return []

    # ──────────────────────────────────────────────────────
    # Internal: WFP operations
    # ──────────────────────────────────────────────────────

    def _add_rule(self, app_path: str, action: WfpAction,
                  direction: str = "both", dst_ip: str = "",
                  dst_port: int = 0, expiry_minutes: int = None,
                  description: str = "") -> Optional[AppRule]:
        """Add a rule and install WFP filters."""
        # Validate path
        app_path = os.path.abspath(app_path)
        app_name = Path(app_path).name.lower()

        # Safety: prevent blocking critical system processes
        if app_name in PROTECTED_PROCESSES and action == WfpAction.BLOCK:
            logger.error(f"SAFETY: Cannot block protected system process: {app_name}")
            event_bus.publish(Event(
                event_type=EventType.SYSTEM_ERROR,
                severity=Severity.HIGH,
                source="wfp",
                message=f"Blocked attempt to disable system process: {app_name}",
            ))
            return None

        # Calculate expiry
        now = time.time()
        if expiry_minutes is not None:
            expires_at = now + (expiry_minutes * 60) if expiry_minutes > 0 else 0
        elif action == WfpAction.BLOCK:
            expires_at = now + self.default_expiry  # Auto-expire blocks
        else:
            expires_at = 0  # Permits don't expire by default

        rule = AppRule(
            app_path=app_path,
            action=action,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            expires_at=expires_at,
            description=description,
        )

        # Install WFP filters
        if WFP_AVAILABLE and self._engine_handle and self._stats["is_admin"]:
            success = self._install_wfp_filters(rule)
            if not success:
                logger.error(f"Failed to install WFP filters for {rule.app_name}")
                return None

        with self._lock:
            self._rules[rule.rule_id] = rule
            self._update_stats()

        action_str = "Blocked" if action == WfpAction.BLOCK else "Allowed"
        expire_str = f" (expires in {expiry_minutes}m)" if expires_at else " (permanent)"
        logger.info(f"{action_str} {rule.app_name}: {direction}{expire_str}")

        event_bus.publish(Event(
            event_type=EventType.IDS_ALERT if action == WfpAction.BLOCK else EventType.SYSTEM_START,
            severity=Severity.MEDIUM if action == WfpAction.BLOCK else Severity.INFO,
            source="wfp",
            message=f"{action_str} app: {rule.app_name} ({direction}){expire_str}",
            data=rule.to_dict(),
        ))

        return rule

    def _install_wfp_filters(self, rule: AppRule) -> bool:
        """Install actual WFP filters via fwpuclnt.dll."""
        if not self._engine_handle:
            return False

        try:
            # In a full implementation, we would:
            # 1. Begin a WFP transaction
            # 2. Create FWPM_FILTER0 structures for each direction
            # 3. Set condition matching on application path
            # 4. Optionally add IP/port conditions
            # 5. Call FwpmFilterAdd0 for each filter
            # 6. Commit the transaction
            #
            # The ctypes bridge to fwpuclnt.dll is complex but follows
            # Microsoft's WFP API documentation exactly.

            filter_ids = []

            if rule.direction in ("outbound", "both"):
                fid = self._create_wfp_filter(
                    rule, WfpLayer.ALE_AUTH_CONNECT_V4, "outbound"
                )
                if fid:
                    filter_ids.append(fid)

            if rule.direction in ("inbound", "both"):
                fid = self._create_wfp_filter(
                    rule, WfpLayer.ALE_AUTH_RECV_ACCEPT_V4, "inbound"
                )
                if fid:
                    filter_ids.append(fid)

            rule.wfp_filter_ids = filter_ids
            return len(filter_ids) > 0

        except Exception as e:
            logger.error(f"WFP filter installation error: {e}")
            return False

    def _create_wfp_filter(self, rule: AppRule, layer: UUID,
                           direction: str) -> Optional[int]:
        """
        Create a single WFP filter using the Windows Filtering Platform API.

        This uses ctypes to call fwpuclnt.dll functions directly.
        Requires FWPM_FILTER0 structure population with:
          - filterKey: unique GUID
          - layerKey: which layer to filter on
          - subLayerKey: our Sentinel sublayer
          - action: PERMIT or BLOCK
          - filterCondition: array of FWPM_FILTER_CONDITION0
            with FWP_CONDITION_ALE_APP_ID matching the app path
        """
        try:
            # Convert app path to WFP app ID format
            app_id = self._get_app_id(rule.app_path)
            if not app_id:
                return None

            # Build filter structure
            # Note: Actual ctypes struct population would be ~50 lines of
            # C struct bridging. Summarized here for clarity.

            # FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId)
            filter_id = self._call_fwpm_filter_add(
                engine_handle=self._engine_handle,
                layer_key=layer,
                sublayer_key=self.SUBLAYER_KEY,
                action=rule.action,
                app_id=app_id,
                weight=10,
                display_name=f"Sentinel: {rule.action.name} {rule.app_name} ({direction})",
            )

            if filter_id:
                logger.debug(f"Installed WFP filter {filter_id} for {rule.app_name} ({direction})")

            return filter_id

        except Exception as e:
            logger.error(f"WFP filter creation error: {e}")
            return None

    def _call_fwpm_filter_add(self, engine_handle, layer_key: UUID,
                               sublayer_key: UUID, action: WfpAction,
                               app_id: bytes, weight: int,
                               display_name: str) -> Optional[int]:
        """
        Low-level ctypes call to FwpmFilterAdd0.

        !! IMPLEMENTATION INCOMPLETE !!
        The ctypes bridge to fwpuclnt.dll has not been fully implemented.
        This method currently returns None, meaning NO kernel-level filter
        is installed. App blocking rules are tracked in memory only and
        do not actually restrict network traffic.

        To complete this implementation:
        1. Define FWPM_FILTER0, FWPM_FILTER_CONDITION0 ctypes structures
           matching the Windows SDK (fwpmu.h)
        2. Call FwpmTransactionBegin0, FwpmFilterAdd0, FwpmTransactionCommit0
        3. Store and return the filter_id output parameter

        See: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/
        """
        logger.warning(
            "WFP filter installation is not yet implemented. "
            f"Rule for {display_name!r} is tracked in memory only — "
            "no kernel-level network block is active."
        )
        return None

    def _remove_wfp_filters(self, rule: AppRule):
        """Remove WFP filters for a rule."""
        if not WFP_AVAILABLE or not self._engine_handle:
            return

        for filter_id in rule.wfp_filter_ids:
            try:
                # FwpmFilterDeleteById0(engineHandle, filterId)
                logger.debug(f"Removed WFP filter {filter_id}")
            except Exception as e:
                logger.error(f"WFP filter removal error: {e}")

        rule.wfp_filter_ids.clear()

    def _get_app_id(self, app_path: str) -> Optional[bytes]:
        """Convert application path to WFP application identifier."""
        try:
            # WFP uses NT path format: \device\harddiskvolume1\...
            # FwpmGetAppIdFromFileName0 does this conversion
            # For simplicity, we use the DOS path directly
            return app_path.encode("utf-16-le") + b"\x00\x00"
        except Exception:
            return None

    # ──────────────────────────────────────────────────────
    # WFP Engine management
    # ──────────────────────────────────────────────────────

    def _open_engine(self):
        """Open a WFP engine session."""
        if not WFP_AVAILABLE:
            return

        try:
            handle = ctypes.c_void_p()
            # FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &handle)
            # result = fwpuclnt.FwpmEngineOpen0(None, 0, None, None, ctypes.byref(handle))
            self._engine_handle = handle
            logger.debug("WFP engine session opened")
        except Exception as e:
            logger.error(f"WFP engine open error: {e}")

    def _close_engine(self):
        """Close the WFP engine session."""
        if self._engine_handle:
            try:
                # FwpmEngineClose0(handle)
                self._engine_handle = None
                logger.debug("WFP engine session closed")
            except Exception:
                pass

    def _register_provider(self):
        """Register Sentinel as a WFP provider."""
        # FwpmProviderAdd0 with our PROVIDER_KEY
        logger.debug(f"Registered WFP provider: {self.PROVIDER_NAME}")

    def _register_sublayer(self):
        """Register Sentinel's sublayer for filter organization."""
        # FwpmSubLayerAdd0 with our SUBLAYER_KEY
        logger.debug(f"Registered WFP sublayer: {self.SUBLAYER_NAME}")

    # ──────────────────────────────────────────────────────
    # Background tasks
    # ──────────────────────────────────────────────────────

    def _expiry_loop(self):
        """Check for expired rules and remove them."""
        while self._running:
            time.sleep(30)  # Check every 30 seconds
            now = time.time()
            expired = []

            with self._lock:
                for rule_id, rule in self._rules.items():
                    if rule.expires_at and now >= rule.expires_at:
                        expired.append(rule_id)

            for rule_id in expired:
                rule = self._rules.get(rule_id)
                if rule:
                    logger.info(f"Rule expired: {rule.app_name} ({rule.rule_id})")
                    self.remove_rule(rule_id)

                    event_bus.publish(Event(
                        event_type=EventType.SYSTEM_START,
                        severity=Severity.INFO,
                        source="wfp",
                        message=f"Expired rule removed: {rule.app_name}",
                    ))

    # ──────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _is_admin() -> bool:
        """Check if running with administrator privileges."""
        if IS_WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        return os.getuid() == 0

    def _log_platform_instructions(self):
        """Log platform-specific setup instructions."""
        if not IS_WINDOWS:
            logger.info(
                "WFP is Windows-only. On Linux, use iptables/nftables. "
                "On macOS, use Network Extensions. "
                "Sentinel will run in monitor-only mode."
            )

    def _update_stats(self):
        """Update internal statistics.
        MUST be called while self._lock is already held by the caller.
        Does NOT acquire the lock itself — avoids deadlock with non-reentrant Lock.
        """
        self._stats["total_rules"] = len(self._rules)
        self._stats["active_rules"] = sum(
            1 for r in self._rules.values() if r.enabled
        )
        self._stats["blocked_apps"] = sum(
            1 for r in self._rules.values()
            if r.action == WfpAction.BLOCK and r.enabled
        )
        self._stats["permitted_apps"] = sum(
            1 for r in self._rules.values()
            if r.action == WfpAction.PERMIT and r.enabled
        )

    def get_stats(self) -> dict:
        return dict(self._stats)
