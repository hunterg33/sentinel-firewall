"""
Suricata/Snort Rule Parser.
Parses Suricata-compatible rule syntax into structured rule objects
that can be evaluated against captured packets.

Supports the core Suricata rule format:
  action protocol src_ip src_port -> dst_ip dst_port (options)

Example rules:
  alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET MALWARE Example"; content:"malware"; sid:2000001; rev:1;)
  alert udp any any -> any 53 (msg:"DNS Query for .xyz TLD"; dns.query; content:".xyz"; sid:2000002;)

Supported options:
  msg, content, nocase, depth, offset, distance, within,
  pcre, flow, flowbits, sid, rev, classtype, priority,
  reference, metadata, threshold, detection_filter,
  dns.query, http.uri, http.header, http.method
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger("sentinel.suricata.parser")


class RuleAction(Enum):
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"
    LOG = "log"


class RuleProtocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"


class FlowDirection(Enum):
    TO_SERVER = "to_server"
    TO_CLIENT = "to_client"
    ESTABLISHED = "established"


@dataclass
class ContentMatch:
    """A single content match directive within a rule."""
    pattern: bytes
    nocase: bool = False
    depth: Optional[int] = None
    offset: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    negated: bool = False       # ! prefix
    is_pcre: bool = False
    pcre_pattern: str = ""
    # Sticky buffer context
    buffer: str = ""  # "", "dns.query", "http.uri", "http.header", etc.


@dataclass
class ThresholdConfig:
    """Threshold/detection_filter configuration."""
    threshold_type: str = "threshold"  # "threshold", "limit", "both"
    track: str = "by_src"              # "by_src", "by_dst"
    count: int = 1
    seconds: int = 60


@dataclass
class SuricataRule:
    """Fully parsed Suricata rule."""
    # Header
    action: RuleAction = RuleAction.ALERT
    protocol: RuleProtocol = RuleProtocol.TCP
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    bidirectional: bool = False  # <> vs ->

    # Options
    sid: int = 0
    rev: int = 1
    msg: str = ""
    classtype: str = ""
    priority: int = 3
    reference: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # Detection
    content_matches: list = field(default_factory=list)  # list of ContentMatch
    flow: list = field(default_factory=list)              # flow directives
    threshold: Optional[ThresholdConfig] = None

    # Raw
    raw_rule: str = ""
    enabled: bool = True
    file_source: str = ""

    def __repr__(self):
        return f"SuricataRule(sid={self.sid}, msg='{self.msg}')"


# ──────────────────────────────────────────────────────────
# Variables
# ──────────────────────────────────────────────────────────

# Default Suricata variables
DEFAULT_VARS = {
    "$HOME_NET": "any",
    "$EXTERNAL_NET": "any",
    "$HTTP_SERVERS": "any",
    "$SMTP_SERVERS": "any",
    "$SQL_SERVERS": "any",
    "$DNS_SERVERS": "any",
    "$TELNET_SERVERS": "any",
    "$SSH_SERVERS": "any",
    "$HTTP_PORTS": "80",
    "$SHELLCODE_PORTS": "!80",
    "$ORACLE_PORTS": "1521",
    "$SSH_PORTS": "22",
    "$DNP3_PORTS": "20000",
    "$MODBUS_PORTS": "502",
    "$FILE_DATA_PORTS": "any",
    "$FTP_PORTS": "21",
    "$GENEVE_PORTS": "6081",
    "$VXLAN_PORTS": "4789",
    "$TEREDO_PORTS": "3544",
}


# ──────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────

# Regex for parsing the rule header
RULE_HEADER_RE = re.compile(
    r"^(alert|drop|reject|pass|log)\s+"
    r"(tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp)\s+"
    r"(\S+)\s+"       # src_ip
    r"(\S+)\s+"       # src_port
    r"(->|<>)\s+"     # direction
    r"(\S+)\s+"       # dst_ip
    r"(\S+)\s+"       # dst_port
    r"\((.+)\)\s*$",  # options
    re.DOTALL
)

# Regex to split options respecting quoted strings and escaped characters
OPTION_RE = re.compile(
    r'(\w[\w.]*)\s*'          # keyword (e.g., "content", "dns.query")
    r'(?::\s*'                # optional colon + value
    r'("(?:[^"\\]|\\.)*"'    # quoted string
    r'|[^;]*)'               # or unquoted value
    r')?\s*;'                 # semicolon terminator
)


def parse_suricata_rules(content: str, variables: dict = None,
                         source_file: str = "") -> list[SuricataRule]:
    """
    Parse a Suricata rules file into structured rule objects.

    Args:
        content: Raw rules file content
        variables: Variable definitions (e.g., {"$HOME_NET": "192.168.1.0/24"})
        source_file: Original filename for tracking

    Returns:
        List of parsed SuricataRule objects
    """
    vars_ = dict(DEFAULT_VARS)
    if variables:
        vars_.update(variables)

    rules = []
    line_buffer = ""

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Handle line continuations (backslash)
        if stripped.endswith("\\"):
            line_buffer += stripped[:-1] + " "
            continue

        full_line = line_buffer + stripped
        line_buffer = ""

        try:
            rule = _parse_single_rule(full_line, vars_, source_file)
            if rule:
                rules.append(rule)
        except Exception as e:
            logger.debug(f"Skipped rule at line {line_num}: {e}")

    logger.info(f"Parsed {len(rules)} Suricata rules from {source_file or 'input'}")
    return rules


def _parse_single_rule(raw: str, variables: dict, source: str) -> Optional[SuricataRule]:
    """Parse a single Suricata rule line."""
    # Handle disabled rules (prefixed with #)
    enabled = True
    if raw.startswith("# "):
        raw = raw[2:]
        enabled = False

    match = RULE_HEADER_RE.match(raw)
    if not match:
        return None

    action_str, proto_str, src_ip, src_port, direction, dst_ip, dst_port, options_str = match.groups()

    # Variable substitution
    src_ip = _resolve_var(src_ip, variables)
    src_port = _resolve_var(src_port, variables)
    dst_ip = _resolve_var(dst_ip, variables)
    dst_port = _resolve_var(dst_port, variables)

    rule = SuricataRule(
        action=RuleAction(action_str),
        protocol=RuleProtocol(proto_str),
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        bidirectional=(direction == "<>"),
        raw_rule=raw,
        enabled=enabled,
        file_source=source,
    )

    # Parse options
    _parse_options(rule, options_str)

    return rule


def _parse_options(rule: SuricataRule, options_str: str):
    """Parse the parenthesized options section of a rule."""
    current_buffer = ""  # Active sticky buffer

    for match in OPTION_RE.finditer(options_str):
        keyword = match.group(1)
        value = match.group(2) if match.group(2) else ""

        # Strip quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        # Unescape
        value = value.replace('\\"', '"').replace("\\;", ";")

        # ── Metadata options ──
        if keyword == "msg":
            rule.msg = value
        elif keyword == "sid":
            rule.sid = int(value)
        elif keyword == "rev":
            rule.rev = int(value)
        elif keyword == "classtype":
            rule.classtype = value
        elif keyword == "priority":
            rule.priority = int(value)
        elif keyword == "reference":
            rule.reference.append(value)
        elif keyword == "metadata":
            for item in value.split(","):
                item = item.strip()
                if " " in item:
                    k, v = item.split(" ", 1)
                    rule.metadata[k.strip()] = v.strip()

        # ── Sticky buffers ──
        elif keyword in ("dns.query", "dns_query"):
            current_buffer = "dns.query"
        elif keyword in ("http.uri", "http_uri"):
            current_buffer = "http.uri"
        elif keyword in ("http.header", "http_header"):
            current_buffer = "http.header"
        elif keyword in ("http.method", "http_method"):
            current_buffer = "http.method"
        elif keyword in ("http.host", "http_host"):
            current_buffer = "http.host"
        elif keyword in ("http.user_agent", "http_user_agent"):
            current_buffer = "http.user_agent"
        elif keyword in ("file.data", "file_data"):
            current_buffer = "file.data"
        elif keyword == "pkt_data":
            current_buffer = "pkt_data"

        # ── Content matching ──
        elif keyword == "content":
            negated = value.startswith("!")
            if negated:
                value = value[1:]
            pattern = _parse_content_pattern(value)
            cm = ContentMatch(
                pattern=pattern,
                negated=negated,
                buffer=current_buffer,
            )
            rule.content_matches.append(cm)

        elif keyword == "pcre":
            pcre_str = value
            cm = ContentMatch(
                pattern=b"",
                is_pcre=True,
                pcre_pattern=pcre_str,
                buffer=current_buffer,
            )
            rule.content_matches.append(cm)

        # ── Content modifiers (apply to last content) ──
        elif keyword == "nocase" and rule.content_matches:
            rule.content_matches[-1].nocase = True
        elif keyword == "depth" and rule.content_matches:
            rule.content_matches[-1].depth = int(value)
        elif keyword == "offset" and rule.content_matches:
            rule.content_matches[-1].offset = int(value)
        elif keyword == "distance" and rule.content_matches:
            rule.content_matches[-1].distance = int(value)
        elif keyword == "within" and rule.content_matches:
            rule.content_matches[-1].within = int(value)

        # ── Flow ──
        elif keyword == "flow":
            rule.flow = [f.strip() for f in value.split(",")]

        # ── Threshold ──
        elif keyword in ("threshold", "detection_filter"):
            rule.threshold = _parse_threshold(value)

    # Reset sticky buffer
    current_buffer = ""


def _parse_content_pattern(value: str) -> bytes:
    """
    Parse Suricata content string into bytes.
    Handles pipe-delimited hex: content:"|0d 0a|Host|0d 0a|"
    """
    result = bytearray()
    i = 0
    in_hex = False

    while i < len(value):
        if value[i] == '|':
            in_hex = not in_hex
            i += 1
            continue

        if in_hex:
            # Read hex bytes
            hex_str = ""
            while i < len(value) and value[i] != '|':
                if value[i] in (' ', '\t'):
                    i += 1
                    continue
                hex_str += value[i]
                i += 1
            # Convert pairs
            for j in range(0, len(hex_str), 2):
                if j + 1 < len(hex_str):
                    result.append(int(hex_str[j:j+2], 16))
        else:
            # Plain text
            if value[i] == '\\' and i + 1 < len(value):
                result.append(ord(value[i+1]))
                i += 2
            else:
                result.append(ord(value[i]))
                i += 1

    return bytes(result)


def _parse_threshold(value: str) -> ThresholdConfig:
    """Parse threshold/detection_filter option value."""
    config = ThresholdConfig()
    for part in value.split(","):
        part = part.strip()
        if " " in part:
            key, val = part.split(" ", 1)
            key = key.strip()
            val = val.strip()
            if key == "type":
                config.threshold_type = val
            elif key == "track":
                config.track = val
            elif key == "count":
                config.count = int(val)
            elif key == "seconds":
                config.seconds = int(val)
    return config


def _resolve_var(value: str, variables: dict) -> str:
    """Resolve Suricata variable references."""
    if value in variables:
        return variables[value]
    # Handle negation: !$HOME_NET
    if value.startswith("!") and value[1:] in variables:
        return "!" + variables[value[1:]]
    # Handle groups: [$HOME_NET, $DNS_SERVERS]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1]
        parts = [_resolve_var(p.strip(), variables) for p in inner.split(",")]
        return "[" + ",".join(parts) + "]"
    return value


def load_rules_file(filepath: str, variables: dict = None) -> list[SuricataRule]:
    """Load and parse a Suricata rules file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return parse_suricata_rules(content, variables, source_file=filepath)
    except Exception as e:
        logger.error(f"Failed to load rules file {filepath}: {e}")
        return []


def load_rules_from_url(url: str, variables: dict = None,
                        cache_dir: str = None) -> list[SuricataRule]:
    """Download and parse Suricata rules from a URL."""
    import requests
    from pathlib import Path

    try:
        resp = requests.get(url, timeout=60, headers={
            "User-Agent": "Sentinel-Firewall/1.0"
        })
        resp.raise_for_status()
        content = resp.text

        # Cache the download
        if cache_dir:
            cache_path = Path(cache_dir) / "suricata_rules"
            cache_path.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w\-.]", "_", url.split("/")[-1])
            (cache_path / safe_name).write_text(content, encoding="utf-8")

        return parse_suricata_rules(content, variables, source_file=url)
    except Exception as e:
        logger.error(f"Failed to download rules from {url}: {e}")
        return []
