"""
Central event bus for inter-module communication.
All modules publish events here; the dashboard subscribes to display them.
"""

import time
import threading
import logging
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger("sentinel.events")


class EventType(Enum):
    # DNS events
    DNS_QUERY = "dns_query"
    DNS_BLOCKED = "dns_blocked"
    DNS_RESOLVED = "dns_resolved"

    # IDS events
    IDS_ALERT = "ids_alert"
    IDS_PACKET = "ids_packet"

    # Traffic events
    TRAFFIC_FLOW = "traffic_flow"
    TRAFFIC_STATS = "traffic_stats"

    # System events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    SYSTEM_ERROR = "system_error"
    CONFIG_RELOAD = "config_reload"


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Event:
    event_type: EventType
    severity: Severity
    source: str          # module that generated the event
    message: str
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default="")

    def __post_init__(self):
        if not self.id:
            self.id = f"{self.event_type.value}_{int(self.timestamp * 1000)}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"] = self.severity.value
        return d


class EventBus:
    """Thread-safe publish/subscribe event bus."""

    def __init__(self, max_events: int = 10000):
        self._subscribers: dict[str, list[Callable]] = {}
        self._global_subscribers: list[Callable] = []
        self._events: deque = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._stats = {
            "total_events": 0,
            "events_by_type": {},
            "events_by_severity": {},
        }

    def subscribe(self, event_type: Optional[EventType], callback: Callable):
        """Subscribe to a specific event type, or all events if type is None."""
        with self._lock:
            if event_type is None:
                self._global_subscribers.append(callback)
            else:
                key = event_type.value
                if key not in self._subscribers:
                    self._subscribers[key] = []
                self._subscribers[key].append(callback)

    def publish(self, event: Event):
        """Publish an event to all matching subscribers."""
        with self._lock:
            self._events.append(event)
            self._stats["total_events"] += 1
            et = event.event_type.value
            self._stats["events_by_type"][et] = self._stats["events_by_type"].get(et, 0) + 1
            sv = event.severity.value
            self._stats["events_by_severity"][sv] = self._stats["events_by_severity"].get(sv, 0) + 1

            # Notify specific subscribers
            callbacks = list(self._subscribers.get(event.event_type.value, []))
            # Notify global subscribers
            callbacks.extend(self._global_subscribers)

        # Call outside lock to prevent deadlocks
        for cb in callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    def get_recent(self, count: int = 100, event_type: Optional[EventType] = None) -> list:
        """Get recent events, optionally filtered by type."""
        with self._lock:
            events = list(self._events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-count:]

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def clear(self):
        with self._lock:
            self._events.clear()
            self._stats = {
                "total_events": 0,
                "events_by_type": {},
                "events_by_severity": {},
            }


# Global singleton
event_bus = EventBus()
