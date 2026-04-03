"""
Sentinel Firewall — Main Orchestrator
Initializes and coordinates all modules:
  1. DNS Proxy + Blocklist filtering
  2. Packet Engine + IDS Rules
  3. Threat Intelligence Feeds
  4. Suricata Rule Engine
  5. WFP Application Control
  6. Real-time Web Dashboard
"""

import os
import sys
import time
import signal
import logging
import argparse
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config_loader import Config
from src.event_bus import event_bus, Event, EventType, Severity
from src.dns.blocklist import BlocklistManager
from src.dns.dns_proxy import DNSProxy
from src.ids.packet_engine import PacketEngine
from src.ids.detection_rules import RulesEngine
from src.threat_intel.feed_manager import ThreatIntelManager
from src.threat_intel.ids_integration import ThreatIntelDetector
from src.suricata.rule_parser import load_rules_file, load_rules_from_url
from src.suricata.rule_engine import SuricataRuleEngine
from src.wfp.wfp_controller import WFPController
from src.dashboard.server import Dashboard


def setup_logging(config: Config):
    """Configure logging based on config."""
    log_level = getattr(logging, config.get("general", "log_level", default="INFO"))
    log_file = config.get("general", "log_file", default="logs/sentinel.log")
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(log_level)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console)
    root_logger.addHandler(file_handler)


def print_banner():
    banner = r"""
    ╔══════════════════════════════════════════════╗
    ║                                              ║
    ║   ███████╗███████╗███╗   ██╗████████╗██╗     ║
    ║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║     ║
    ║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║     ║
    ║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║     ║
    ║   ███████║███████╗██║ ╚████║   ██║   ██║     ║
    ║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ║
    ║           N  E  L                              ║
    ║                                              ║
    ║   Personal Firewall & IDS  v2.0.0            ║
    ║   DNS Filter · IDS · Threat Intel            ║
    ║   Suricata Rules · App Control · Dashboard   ║
    ║                                              ║
    ╚══════════════════════════════════════════════╝
    """
    print(banner)


class SentinelFirewall:
    """Main application class that orchestrates all modules."""

    def __init__(self, config_path: str = None):
        self.config = Config()
        self.config.load(config_path)
        setup_logging(self.config)
        self.logger = logging.getLogger("sentinel.main")

        # Module instances
        self.blocklist_manager = None
        self.dns_proxy = None
        self.packet_engine = None
        self.rules_engine = None
        self.threat_intel = None
        self.threat_detector = None
        self.suricata_engine = None
        self.wfp_controller = None
        self.dashboard = None
        self._running = False

    def start(self):
        """Start all enabled modules."""
        print_banner()
        self.logger.info("=" * 60)
        self.logger.info("Sentinel Firewall v2.0.0 starting...")
        self.logger.info("=" * 60)
        self._running = True

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_START,
            severity=Severity.INFO,
            source="main",
            message="Sentinel Firewall initializing",
        ))

        total_steps = 6
        step = 0

        # ── 1. DNS Filtering ──
        step += 1
        if self.config.get("dns_filter", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing DNS filtering...")
            data_dir = self.config.get("general", "data_dir", default="data")

            self.blocklist_manager = BlocklistManager(
                data_dir=data_dir,
                blocklists=self.config.get("dns_filter", "blocklists", default=[]),
                custom_blocked=self.config.get("dns_filter", "custom_blocked_domains", default=[]),
                whitelist=self.config.get("dns_filter", "whitelist", default=[]),
            )
            self.blocklist_manager.initialize()

            self.dns_proxy = DNSProxy(
                blocklist_manager=self.blocklist_manager,
                listen_addr=self.config.get("dns_filter", "listen_address", default="127.0.0.1"),
                listen_port=self.config.get("dns_filter", "listen_port", default=5353),
                upstream_dns=self.config.get("dns_filter", "upstream_dns", default="8.8.8.8"),
                upstream_port=self.config.get("dns_filter", "upstream_port", default=53),
            )
            self.dns_proxy.start()
            self.logger.info(f"   DNS proxy: {self.config.get('dns_filter', 'listen_address')}:{self.config.get('dns_filter', 'listen_port')}")
            self.logger.info(f"   Blocked domains: {self.blocklist_manager.blocked_count:,}")
        else:
            self.logger.info(f"[{step}/{total_steps}] DNS filtering — DISABLED")

        # ── 2. Intrusion Detection (built-in rules) ──
        step += 1
        if self.config.get("ids", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing intrusion detection...")

            rule_configs = self.config.get("ids", "rules", default=[])
            self.rules_engine = RulesEngine(rule_configs)

            self.packet_engine = PacketEngine(
                interface=self.config.get("ids", "interface"),
                capture_filter=self.config.get("ids", "capture_filter", default="ip"),
                max_packet_size=self.config.get("ids", "max_packet_size", default=65535),
            )
            self.packet_engine.register_callback(self.rules_engine.analyze_packet)
            self.logger.info(f"   Built-in detection rules: {len(self.rules_engine.rules)}")
        else:
            self.logger.info(f"[{step}/{total_steps}] Intrusion detection — DISABLED")

        # ── 3. Threat Intelligence ──
        step += 1
        if self.config.get("threat_intel", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing threat intelligence feeds...")
            data_dir = self.config.get("general", "data_dir", default="data")
            api_keys = self.config.get("threat_intel", "api_keys", default={})
            custom_feeds = self.config.get("threat_intel", "custom_feeds", default=[])
            update_interval = self.config.get("threat_intel", "update_interval", default=3600)

            self.threat_intel = ThreatIntelManager(
                data_dir=data_dir,
                feeds=custom_feeds,
                api_keys={k: v for k, v in api_keys.items() if v},  # Filter empty keys
                update_interval=update_interval,
            )
            self.threat_intel.initialize()

            # Wire threat intel into packet analysis
            if self.packet_engine:
                self.threat_detector = ThreatIntelDetector(self.threat_intel)
                self.packet_engine.register_callback(self.threat_detector.analyze_packet)
                self.logger.info(f"   Threat intel → packet analysis pipeline connected")

            stats = self.threat_intel.get_stats()
            self.logger.info(f"   Indicators: {stats['total_indicators']:,} "
                             f"(IPs: {stats['malicious_ips']:,}, "
                             f"CIDRs: {stats['malicious_cidrs']:,}, "
                             f"Domains: {stats['malicious_domains']:,})")
        else:
            self.logger.info(f"[{step}/{total_steps}] Threat intelligence — DISABLED")

        # ── 4. Suricata Rules ──
        step += 1
        if self.config.get("suricata", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing Suricata rule engine...")

            # Build variables from config
            suri_vars = {}
            raw_vars = self.config.get("suricata", "variables", default={})
            for key, val in raw_vars.items():
                suri_vars[f"${key}"] = str(val)

            self.suricata_engine = SuricataRuleEngine(variables=suri_vars)

            # Load local rule files
            rule_files = self.config.get("suricata", "rule_files", default=[])
            for filepath in rule_files:
                if os.path.exists(filepath):
                    rules = load_rules_file(filepath, suri_vars)
                    self.suricata_engine.add_rules(rules)

            # Download rule URLs
            data_dir = self.config.get("general", "data_dir", default="data")
            rule_urls = self.config.get("suricata", "rule_urls", default=[])
            for rule_config in rule_urls:
                if not rule_config.get("enabled", True):
                    continue
                url = rule_config.get("url", "")
                name = rule_config.get("name", url)
                if url:
                    self.logger.info(f"   Downloading: {name}...")
                    rules = load_rules_from_url(url, suri_vars, cache_dir=data_dir)
                    self.suricata_engine.add_rules(rules)

            # Register as packet callback
            if self.packet_engine:
                self.packet_engine.register_callback(self.suricata_engine.analyze_packet)

            stats = self.suricata_engine.get_stats()
            self.logger.info(f"   Suricata rules loaded: {stats['total_rules']:,} "
                             f"(enabled: {stats['enabled_rules']:,})")
        else:
            self.logger.info(f"[{step}/{total_steps}] Suricata rules — DISABLED")

        # Start packet engine (after all callbacks registered)
        if self.packet_engine:
            self.packet_engine.start()

        # ── 5. Application Control (WFP) ──
        step += 1
        if self.config.get("app_control", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing application control (WFP)...")

            expiry = self.config.get("app_control", "default_expiry_minutes", default=60)
            self.wfp_controller = WFPController(default_expiry_minutes=expiry)
            self.wfp_controller.initialize()

            # Apply pre-configured blocked apps
            blocked_apps = self.config.get("app_control", "blocked_apps", default=[])
            for app_config in blocked_apps:
                if isinstance(app_config, dict):
                    self.wfp_controller.block_app(
                        app_path=app_config.get("path", ""),
                        direction=app_config.get("direction", "both"),
                        description=app_config.get("description", ""),
                        expiry_minutes=0,  # Pre-configured = permanent
                    )

            self.logger.info(f"   WFP: {self.wfp_controller.get_stats()['active_rules']} active rules")
        else:
            self.logger.info(f"[{step}/{total_steps}] Application control — DISABLED")

        # ── 6. Dashboard ──
        step += 1
        if self.config.get("dashboard", "enabled", default=True):
            self.logger.info(f"[{step}/{total_steps}] Initializing dashboard...")

            self.dashboard = Dashboard(
                host=self.config.get("dashboard", "host", default="127.0.0.1"),
                port=self.config.get("dashboard", "port", default=8080),
                update_interval=self.config.get("dashboard", "update_interval", default=1),
            )
            # Wire auth config
            auth_cfg = self.config.get('dashboard', 'auth', default={})
            self.dashboard._auth_enabled = auth_cfg.get('enabled', False)
            self.dashboard._auth_username = auth_cfg.get('username', 'admin')
            self.dashboard._auth_password = auth_cfg.get('password', '')
            if self.dashboard._auth_enabled and not self.dashboard._auth_password:
                self.logger.warning('Dashboard auth enabled but no password set in config!')

            # Wire up all module references
            self.dashboard.dns_proxy = self.dns_proxy
            self.dashboard.packet_engine = self.packet_engine
            self.dashboard.rules_engine = self.rules_engine
            self.dashboard.blocklist_manager = self.blocklist_manager
            self.dashboard.threat_intel = self.threat_intel
            self.dashboard.suricata_engine = self.suricata_engine
            self.dashboard.wfp_controller = self.wfp_controller
            self.dashboard.start()

            dash_host = self.config.get("dashboard", "host", default="127.0.0.1")
            dash_port = self.config.get("dashboard", "port", default=8080)
            self.logger.info(f"   Dashboard: http://{dash_host}:{dash_port}")
        else:
            self.logger.info(f"[{step}/{total_steps}] Dashboard — DISABLED")

        # ── Summary ──
        self.logger.info("=" * 60)
        self.logger.info("Sentinel Firewall v2.0.0 is now active.")
        self._print_summary()
        self.logger.info("Press Ctrl+C to stop.")
        self.logger.info("=" * 60)

        if self.dns_proxy:
            dns_port = self.config.get("dns_filter", "listen_port", default=5353)
            print(f"\n  DNS filtering: nslookup example.com 127.0.0.1 -port={dns_port}")
        if self.dashboard:
            print(f"  Dashboard:     http://127.0.0.1:{self.config.get('dashboard', 'port', default=8080)}")
        print()

    def _print_summary(self):
        """Print a summary of all active modules."""
        modules = []
        if self.dns_proxy:
            modules.append(f"DNS ({self.blocklist_manager.blocked_count:,} blocked domains)")
        if self.rules_engine:
            modules.append(f"IDS ({len(self.rules_engine.rules)} rules)")
        if self.threat_intel:
            stats = self.threat_intel.get_stats()
            modules.append(f"Threat Intel ({stats['total_indicators']:,} indicators)")
        if self.suricata_engine:
            stats = self.suricata_engine.get_stats()
            modules.append(f"Suricata ({stats['enabled_rules']:,} rules)")
        if self.wfp_controller:
            modules.append("WFP App Control")
        if self.dashboard:
            modules.append("Dashboard")

        for m in modules:
            self.logger.info(f"   ✓ {m}")

    def stop(self):
        """Gracefully stop all modules."""
        self.logger.info("Shutting down Sentinel Firewall...")
        self._running = False

        if self.wfp_controller:
            self.wfp_controller.stop()
        if self.threat_intel:
            self.threat_intel.stop()
        if self.dns_proxy:
            self.dns_proxy.stop()
        if self.packet_engine:
            self.packet_engine.stop()
        if self.dashboard:
            self.dashboard.stop()

        event_bus.publish(Event(
            event_type=EventType.SYSTEM_STOP,
            severity=Severity.INFO,
            source="main",
            message="Sentinel Firewall stopped",
        ))
        self.logger.info("Sentinel Firewall stopped.")

    def run_forever(self):
        """Block the main thread until interrupted."""
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def main():
    parser = argparse.ArgumentParser(description="Sentinel Firewall v2.0 — Personal IDS, DNS Filter & App Control")
    parser.add_argument("-c", "--config", help="Path to custom config YAML", default=None)
    parser.add_argument("--dns-only", action="store_true", help="Run DNS filtering only")
    parser.add_argument("--ids-only", action="store_true", help="Run IDS only")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable web dashboard")
    parser.add_argument("--no-threat-intel", action="store_true", help="Disable threat intelligence")
    parser.add_argument("--no-suricata", action="store_true", help="Disable Suricata rules")
    parser.add_argument("--no-wfp", action="store_true", help="Disable WFP app control")
    parser.add_argument("--port", type=int, help="Dashboard port override")
    parser.add_argument("--panic", action="store_true", help="Remove all WFP filters and exit")
    args = parser.parse_args()

    firewall = SentinelFirewall(config_path=args.config)

    # Panic mode: remove all WFP filters and exit
    if args.panic:
        print("PANIC MODE: Removing all Sentinel WFP filters...")
        wfp = WFPController()
        wfp.initialize()
        wfp.panic_remove_all()
        wfp.stop()
        print("Done. All Sentinel filters removed.")
        sys.exit(0)

    # Apply CLI overrides
    if args.dns_only:
        firewall.config._config["ids"]["enabled"] = False
        firewall.config._config["threat_intel"]["enabled"] = False
        firewall.config._config["suricata"]["enabled"] = False
        firewall.config._config["app_control"]["enabled"] = False
    if args.ids_only:
        firewall.config._config["dns_filter"]["enabled"] = False
    if args.no_dashboard:
        firewall.config._config["dashboard"]["enabled"] = False
    if args.no_threat_intel:
        firewall.config._config["threat_intel"]["enabled"] = False
    if args.no_suricata:
        firewall.config._config["suricata"]["enabled"] = False
    if args.no_wfp:
        firewall.config._config["app_control"]["enabled"] = False
    if args.port:
        firewall.config._config["dashboard"]["port"] = args.port

    signal.signal(signal.SIGINT, lambda s, f: firewall.stop())
    signal.signal(signal.SIGTERM, lambda s, f: firewall.stop())

    firewall.start()
    firewall.run_forever()


if __name__ == "__main__":
    main()
