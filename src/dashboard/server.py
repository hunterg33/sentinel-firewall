"""
Dashboard Web Server.
Flask + SocketIO for real-time traffic monitoring, IDS alerts,
DNS filtering stats, threat intel, Suricata rules, and app control.
"""

import os
import time
import json
import logging
import secrets
import threading
import functools
from flask import Flask, render_template, jsonify, request, g
from flask_socketio import SocketIO

from src.event_bus import event_bus, Event, EventType, Severity
from src.validators import (
    require_json, validate_domain, validate_ip, validate_optional_ip,
    validate_app_path, validate_direction, validate_port,
    validate_expiry, validate_description, validate_rule_id,
    invalidate_path_cache, path_cache_stats,
)

logger = logging.getLogger("sentinel.dashboard")


class Dashboard:
    """Real-time web dashboard for Sentinel Firewall."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 update_interval: float = 1.0):
        self.host = host
        self.port = port
        self.update_interval = update_interval

        self.app = Flask(
            __name__,
            template_folder="templates",
            static_folder="static",
        )
        # Pull secret key from environment — never use the hardcoded fallback
        # in production. Set SENTINEL_SECRET_KEY in your environment before starting.
        secret = os.environ.get("SENTINEL_SECRET_KEY")
        if not secret:
            secret = secrets.token_hex(32)
            logger.warning(
                "SENTINEL_SECRET_KEY not set in environment. "
                "Generated a random key — sessions will not survive restarts. "
                "Set the env var to a strong random value for persistent sessions."
            )
        self.app.config["SECRET_KEY"] = secret
        self._csrf_token = secrets.token_hex(32)  # per-process CSRF token
        self.socketio = SocketIO(self.app, async_mode="threading",
                                 cors_allowed_origins="*")

        # State
        self._recent_alerts: list = []
        self._recent_dns: list = []
        self._recent_connections: list = []
        self._bandwidth_history: list = []
        self._start_time = time.time()

        # Module references (set by main.py)
        self.dns_proxy = None
        self.packet_engine = None
        self.rules_engine = None
        self.blocklist_manager = None
        self.threat_intel = None
        self.suricata_engine = None
        self.wfp_controller = None

        # Auth config
        auth_cfg = {}  # set by start() after config is known
        self._auth_enabled = False
        self._auth_username = "admin"
        self._auth_password = ""

        self._setup_routes()
        self._setup_socketio()
        self._subscribe_events()

    def _require_auth(self, f):
        """Decorator: enforce HTTP Basic Auth if auth is enabled."""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not self._auth_enabled:
                return f(*args, **kwargs)
            auth = request.authorization
            if (not auth
                    or auth.username != self._auth_username
                    or not secrets.compare_digest(
                        auth.password.encode(), self._auth_password.encode())):
                return (
                    jsonify({"error": "Authentication required"}),
                    401,
                    {"WWW-Authenticate": 'Basic realm="Sentinel"'},
                )
            return f(*args, **kwargs)
        return decorated

    def _require_csrf(self, f):
        """Decorator: validate X-CSRF-Token header on state-mutating requests."""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(token, self._csrf_token):
                return jsonify({"error": "Invalid or missing CSRF token"}), 403
            return f(*args, **kwargs)
        return decorated

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            # Expose CSRF token to the frontend via template
            return render_template("index.html", csrf_token=self._csrf_token)

        @self.app.route("/api/csrf-token")
        def csrf_token_endpoint():
            """Allows JS to fetch the CSRF token on load."""
            return jsonify({"csrf_token": self._csrf_token})

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(self._build_full_stats())

        @self.app.route("/api/alerts")
        def api_alerts():
            return jsonify(self._recent_alerts[-200:])

        @self.app.route("/api/dns")
        def api_dns():
            dns_stats = self.dns_proxy.get_stats() if self.dns_proxy else {}
            bl_stats = self.blocklist_manager.get_stats() if self.blocklist_manager else {}
            return jsonify({
                "recent": self._recent_dns[-200:],
                "stats": dns_stats,
                "blocklist": bl_stats,
            })

        @self.app.route("/api/traffic")
        def api_traffic():
            traffic = self.packet_engine.get_stats() if self.packet_engine else {}
            return jsonify({
                "stats": traffic,
                "bandwidth_history": self._bandwidth_history[-120:],
                "recent_connections": self._recent_connections[-100:],
            })

        @self.app.route("/api/dns/block", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def block_domain():
            body, err = require_json(request.json)
            if err:
                return jsonify({"status": "error", "message": err}), 400
            domain, err = validate_domain(body.get("domain", ""))
            if err:
                return jsonify({"status": "error", "message": err}), 400
            if self.blocklist_manager:
                self.blocklist_manager.add_blocked(domain)
                return jsonify({"status": "ok", "blocked": domain})
            return jsonify({"status": "error", "message": "Blocklist manager not available"}), 503

        @self.app.route("/api/dns/unblock", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def unblock_domain():
            body, err = require_json(request.json)
            if err:
                return jsonify({"status": "error", "message": err}), 400
            domain, err = validate_domain(body.get("domain", ""))
            if err:
                return jsonify({"status": "error", "message": err}), 400
            if self.blocklist_manager:
                self.blocklist_manager.remove_blocked(domain)
                return jsonify({"status": "ok", "unblocked": domain})
            return jsonify({"status": "error", "message": "Blocklist manager not available"}), 503

        # ── Threat Intel API ──
        @self.app.route("/api/threat_intel")
        def api_threat_intel():
            if not self.threat_intel:
                return jsonify({"enabled": False})
            return jsonify({
                "enabled": True,
                "stats": self.threat_intel.get_stats(),
                "feeds": self.threat_intel.get_feed_status(),
            })

        @self.app.route("/api/threat_intel/check_ip", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def check_ip():
            body, err = require_json(request.json)
            if err:
                return jsonify({"error": err}), 400
            ip, err = validate_ip(body.get("ip", ""))
            if err:
                return jsonify({"error": err}), 400
            if self.threat_intel:
                indicator = self.threat_intel.check_ip(ip)
                if indicator:
                    return jsonify({"malicious": True, "indicator": indicator.to_dict()})
                return jsonify({"malicious": False})
            return jsonify({"error": "Threat intel not available"}), 503

        @self.app.route("/api/threat_intel/check_domain", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def check_domain():
            body, err = require_json(request.json)
            if err:
                return jsonify({"error": err}), 400
            domain, err = validate_domain(body.get("domain", ""))
            if err:
                return jsonify({"error": err}), 400
            if self.threat_intel:
                indicator = self.threat_intel.check_domain(domain)
                if indicator:
                    return jsonify({"malicious": True, "indicator": indicator.to_dict()})
                return jsonify({"malicious": False})
            return jsonify({"error": "Threat intel not available"}), 503

        # ── Suricata API ──
        @self.app.route("/api/suricata")
        def api_suricata():
            if not self.suricata_engine:
                return jsonify({"enabled": False})
            return jsonify({
                "enabled": True,
                "stats": self.suricata_engine.get_stats(),
            })

        # ── WFP / App Control API ──
        @self.app.route("/api/apps")
        def api_apps():
            if not self.wfp_controller:
                return jsonify({"enabled": False})
            return jsonify({
                "enabled": True,
                "stats": self.wfp_controller.get_stats(),
                "rules": self.wfp_controller.get_rules(),
                "processes": self.wfp_controller.list_network_processes(),
            })

        @self.app.route("/api/apps/block", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def block_app():
            body, err = require_json(request.json)
            if err:
                return jsonify({"error": err}), 400

            app_path, err = validate_app_path(body.get("app_path", ""))
            if err:
                return jsonify({"error": err}), 400

            direction, err = validate_direction(body.get("direction", "both"))
            if err:
                return jsonify({"error": err}), 400

            dst_ip, err = validate_optional_ip(body.get("dst_ip", ""))
            if err:
                return jsonify({"error": err}), 400

            dst_port, err = validate_port(body.get("dst_port", 0))
            if err:
                return jsonify({"error": err}), 400

            expiry, err = validate_expiry(body.get("expiry_minutes"))
            if err:
                return jsonify({"error": err}), 400

            description, err = validate_description(body.get("description", ""))
            if err:
                return jsonify({"error": err}), 400

            if not self.wfp_controller:
                return jsonify({"error": "App control not available"}), 503

            rule = self.wfp_controller.block_app(
                app_path=app_path,
                direction=direction,
                dst_ip=dst_ip,
                dst_port=dst_port,
                expiry_minutes=expiry,
                description=description,
            )
            if rule:
                return jsonify({"status": "ok", "rule": rule.to_dict()})
            return jsonify({"error": "Failed to block (may be a protected process)"}), 400

        @self.app.route("/api/apps/unblock", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def unblock_app():
            body, err = require_json(request.json)
            if err:
                return jsonify({"error": err}), 400
            rule_id, err = validate_rule_id(body.get("rule_id", ""))
            if err:
                return jsonify({"error": err}), 400
            if self.wfp_controller:
                success = self.wfp_controller.remove_rule(rule_id)
                return jsonify({"status": "ok" if success else "not_found"})
            return jsonify({"error": "App control not available"}), 503

        @self.app.route("/api/apps/cache/invalidate", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def invalidate_cache():
            body, err = require_json(request.json)
            if err:
                return jsonify({"error": err}), 400
            path = body.get("path")   # None = flush entire cache
            invalidate_path_cache(path)
            return jsonify({"status": "ok", "flushed": path or "all"})

        @self.app.route("/api/apps/cache/stats")
        def cache_stats():
            return jsonify(path_cache_stats())

        @self.app.route("/api/apps/panic", methods=["POST"])
        @self._require_auth
        @self._require_csrf
        def panic():
            if self.wfp_controller:
                self.wfp_controller.panic_remove_all()
                return jsonify({"status": "ok", "message": "All WFP filters removed"})
            return jsonify({"error": "WFP not available"}), 400

    def _setup_socketio(self):
        @self.socketio.on("connect")
        def on_connect():
            logger.debug("Dashboard client connected")
            self.socketio.emit("full_state", self._build_full_stats())

    def _subscribe_events(self):
        def on_event(event: Event):
            data = event.to_dict()

            if event.event_type == EventType.IDS_ALERT:
                self._recent_alerts.append(data)
                self._recent_alerts = self._recent_alerts[-500:]
                self.socketio.emit("ids_alert", data)

            elif event.event_type in (EventType.DNS_BLOCKED, EventType.DNS_RESOLVED):
                self._recent_dns.append(data)
                self._recent_dns = self._recent_dns[-500:]
                self.socketio.emit("dns_event", data)

            elif event.event_type == EventType.TRAFFIC_STATS:
                self._bandwidth_history.append({
                    "time": event.timestamp,
                    "pps": event.data.get("packets_per_second", 0),
                    "bps": event.data.get("bytes_per_second", 0),
                })
                self._bandwidth_history = self._bandwidth_history[-300:]
                self.socketio.emit("traffic_stats", event.data)

            elif event.event_type == EventType.TRAFFIC_FLOW:
                self._recent_connections.append(data)
                self._recent_connections = self._recent_connections[-200:]

        event_bus.subscribe(None, on_event)

    def _build_full_stats(self) -> dict:
        uptime = time.time() - self._start_time
        dns = self.dns_proxy.get_stats() if self.dns_proxy else {}
        traffic = self.packet_engine.get_stats() if self.packet_engine else {}
        ids = self.rules_engine.get_stats() if self.rules_engine else {}
        blocklist = self.blocklist_manager.get_stats() if self.blocklist_manager else {}
        threat = self.threat_intel.get_stats() if self.threat_intel else {}
        suricata = self.suricata_engine.get_stats() if self.suricata_engine else {}
        wfp = self.wfp_controller.get_stats() if self.wfp_controller else {}

        return {
            "uptime": uptime,
            "dns": dns,
            "traffic": traffic,
            "ids": ids,
            "blocklist": blocklist,
            "threat_intel": threat,
            "suricata": suricata,
            "app_control": wfp,
            "recent_alerts": self._recent_alerts[-50:],
            "recent_dns": self._recent_dns[-50:],
            "bandwidth_history": self._bandwidth_history[-120:],
            "module_status": {
                "packet_engine": self.packet_engine is not None,
                "dns_proxy": self.dns_proxy is not None,
                "rules_engine": self.rules_engine is not None,
                "blocklist_manager": self.blocklist_manager is not None,
                "threat_intel": self.threat_intel is not None,
                "suricata_engine": self.suricata_engine is not None,
                "wfp_controller": self.wfp_controller is not None,
            },
        }

    def start(self):
        def run():
            self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                log_output=False,
            )

        thread = threading.Thread(target=run, daemon=True, name="dashboard")
        thread.start()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_START,
            severity=Severity.INFO,
            source="dashboard",
            message=f"Dashboard running at http://{self.host}:{self.port}",
        ))
        logger.info(f"Dashboard started at http://{self.host}:{self.port}")

    def stop(self):
        logger.info("Dashboard stopped")
