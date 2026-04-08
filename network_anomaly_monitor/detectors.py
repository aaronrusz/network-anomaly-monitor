"""
detectors.py — All packet-level detection logic.

Detectors are pure functions: they receive state as arguments and return
lists of alert strings.  No global mutable state; no side effects beyond
the mutable containers passed in.

Covered detection categories
-----------------------------
* AI / ML service traffic (DNS + high-frequency TCP)
* Agent protocol traffic  (A2A, ACP, MCP — ports + payload patterns)
* Protocol signature scanning (JSON-RPC, coordination keywords)
* Encrypted traffic analysis (TLS fingerprinting, entropy, flow patterns)
* General traffic-rate anomalies

Dependencies
------------
    scapy >= 2.4   (scapy.all, optionally scapy.layers.tls)
    Python >= 3.10
"""

from __future__ import annotations

import re
import statistics
from collections import Counter
from collections import defaultdict as _DefaultDict
from datetime import datetime, timedelta

from .config import (
    AGENT_PROTOCOLS,
    AGENT_TLS_PATTERNS,
    AI_PROTOCOLS,
    AI_STANDARD_PORTS,
    BASELINE_WINDOW,
    COORDINATION_KEYWORDS,
    JSON_RPC_AGENT_PATTERNS,
)
from .crypto_utils import calculate_entropy, chi_square_uniformity

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

AlertList  = list[str]
FlowStore  = _DefaultDict
CountStore = _DefaultDict
ConnStore  = _DefaultDict

# ---------------------------------------------------------------------------
# Lazy scapy loader
# ---------------------------------------------------------------------------
# scapy is imported on the first packet processed, not at module load time.
# This means the package imports cleanly even when scapy is not yet installed,
# and the user gets a clear, actionable error only when capture actually starts.

_scapy_layers: dict = {}
TLS_AVAILABLE: bool = False


def _layers() -> dict:
    """
    Return a dict mapping layer-name strings to scapy layer classes.
    Imports scapy on the very first call; returns the cached dict on all
    subsequent calls.
    """
    global _scapy_layers, TLS_AVAILABLE
    if _scapy_layers:
        return _scapy_layers

    try:
        from scapy.all import DNS, IP, Raw, TCP, UDP
    except ImportError as exc:
        raise ImportError(
            "scapy is required for packet analysis.\n"
            "Install with: pip install scapy"
        ) from exc

    _scapy_layers = {"IP": IP, "TCP": TCP, "UDP": UDP, "DNS": DNS, "Raw": Raw}

    try:
        from scapy.layers.tls import TLS
        _scapy_layers["TLS"] = TLS
        TLS_AVAILABLE = True
    except ImportError:
        _scapy_layers["TLS"] = None
        TLS_AVAILABLE = False

    return _scapy_layers


# ---------------------------------------------------------------------------
# AI / ML service detection
# ---------------------------------------------------------------------------

def detect_ai_traffic(
    packet,
    dns_queries,
    connection_counts: CountStore,
    agent_protocols_cfg: dict,
) -> AlertList:
    """
    Detect potential AI/ML API traffic.

    Checks DNS queries against known AI service domains and monitors TCP
    connections to AI/agent ports for high-frequency patterns.

    Returns a list of alert strings (empty if nothing detected).
    """
    _L = _layers()
    IP, TCP, DNS = _L["IP"], _L["TCP"], _L["DNS"]

    alerts: AlertList = []

    if not packet.haslayer(IP):
        return alerts

    # ── DNS query inspection ─────────────────────────────────────────────
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        query: str = packet[DNS].qd.qname.decode("utf-8").rstrip(".")
        dns_queries.append({
            "timestamp": datetime.now(),
            "query":     query,
            "src_ip":    packet[IP].src,
        })
        for service, domains in AI_PROTOCOLS.items():
            for domain in domains:
                if domain in query:
                    alerts.append(
                        f"AI Service DNS Query: {service} - {query} from {packet[IP].src}"
                    )

    # ── TCP connection frequency ─────────────────────────────────────────
    if packet.haslayer(TCP):
        src_ip:   str = packet[IP].src
        dst_ip:   str = packet[IP].dst
        dst_port: int = packet[TCP].dport

        agent_ports: list[int] = [
            port
            for cfg in agent_protocols_cfg.values()
            for port in cfg["ports"]
        ]
        all_monitored_ports = AI_STANDARD_PORTS + agent_ports

        if dst_port in all_monitored_ports:
            conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
            connection_counts[conn_key] += 1
            if connection_counts[conn_key] > 50:
                alerts.append(
                    f"High frequency AI-like traffic: {conn_key} "
                    f"({connection_counts[conn_key]} connections)"
                )

    return alerts


# ---------------------------------------------------------------------------
# Agent protocol detection (A2A / ACP / MCP)
# ---------------------------------------------------------------------------

def detect_agent_protocols(
    packet,
    agent_connections: ConnStore,
    protocol_sessions: CountStore,
    suspicious_patterns: CountStore,
) -> AlertList:
    """
    Detect A2A, ACP, and MCP protocol traffic by port number.

    Also identifies agent mesh networks (both src and dst on agent ports)
    and potential swarm activity (> 20 agent connections within 60 s).

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, TCP = _L["IP"], _L["TCP"]

    alerts: AlertList = []

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return alerts

    src_ip:   str = packet[IP].src
    dst_ip:   str = packet[IP].dst
    dst_port: int = packet[TCP].dport
    src_port: int = packet[TCP].sport

    # ── Per-protocol port matching ───────────────────────────────────────
    for protocol_name, cfg in AGENT_PROTOCOLS.items():
        if dst_port in cfg["ports"] or src_port in cfg["ports"]:
            conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
            agent_connections[protocol_name].append({
                "timestamp":  datetime.now(),
                "connection": conn_key,
                "direction":  "outbound" if dst_port in cfg["ports"] else "inbound",
            })
            protocol_sessions[protocol_name] += 1
            alerts.append(
                f"{protocol_name.upper()} Protocol Traffic: {conn_key} "
                f"(Session #{protocol_sessions[protocol_name]})"
            )

    # ── Agent mesh detection ─────────────────────────────────────────────
    all_agent_ports: list[int] = [
        port for cfg in AGENT_PROTOCOLS.values() for port in cfg["ports"]
    ]
    if dst_port in all_agent_ports and src_port in all_agent_ports:
        alerts.append(
            f"Agent-to-Agent Communication Detected: "
            f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
        )
        suspicious_patterns["agent_mesh"] += 1

    # ── Swarm detection ──────────────────────────────────────────────────
    current_time = datetime.now()
    recent_connections = [
        c
        for conns in agent_connections.values()
        for c in conns
        if (current_time - c["timestamp"]).total_seconds() < 60
    ]
    if len(recent_connections) > 20:
        alerts.append(
            f"Potential Agent Swarm Activity: "
            f"{len(recent_connections)} connections in last minute"
        )
        suspicious_patterns["swarm_activity"] += 1

    return alerts


# ---------------------------------------------------------------------------
# Protocol signature scanning
# ---------------------------------------------------------------------------

def detect_protocol_signatures(
    packet,
    suspicious_patterns: CountStore,
) -> AlertList:
    """
    Detect protocol-specific signatures in the TCP payload.

    Scans for:
    * Agent protocol URL patterns (A2A / ACP / MCP path strings)
    * JSON-RPC method names common in agent frameworks
    * Multi-agent coordination keywords

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, TCP = _L["IP"], _L["TCP"]

    alerts: AlertList = []

    if not (packet.haslayer(TCP) and hasattr(packet[TCP], "payload")):
        return alerts

    try:
        payload: str = str(packet[TCP].payload)

        # Agent protocol URL / content-type patterns
        for protocol_name, cfg in AGENT_PROTOCOLS.items():
            for pattern in cfg["patterns"]:
                if re.search(pattern, payload, re.IGNORECASE):
                    alerts.append(
                        f"{protocol_name.upper()} Protocol Pattern Detected: "
                        f"{pattern} in traffic from {packet[IP].src}"
                    )
                    suspicious_patterns[f"{protocol_name}_pattern"] += 1

        # JSON-RPC agent method patterns
        for pattern in JSON_RPC_AGENT_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                alerts.append(
                    f"Agent JSON-RPC Communication: {pattern[:30]}... "
                    f"from {packet[IP].src}"
                )
                suspicious_patterns["json_rpc_agent"] += 1

        # Multi-agent coordination keywords — at most one alert per packet
        for keyword in COORDINATION_KEYWORDS:
            if keyword.lower() in payload.lower():
                alerts.append(
                    f"Multi-Agent Coordination Keyword: '{keyword}' "
                    f"detected from {packet[IP].src}"
                )
                suspicious_patterns["coordination"] += 1
                break

    except (UnicodeDecodeError, AttributeError):
        pass

    return alerts


# ---------------------------------------------------------------------------
# Encrypted traffic: timing analysis
# ---------------------------------------------------------------------------

def analyze_packet_timing(
    flow_key: str,
    timestamp: datetime,
    encrypted_flows: FlowStore,
) -> str | None:
    """
    Append *timestamp* to the flow's timing list and check for suspiciously
    regular inter-packet intervals (indicative of automated heartbeats).

    Returns an alert string if a regular pattern is detected, otherwise None.
    """
    flow = encrypted_flows[flow_key]
    flow["timing"].append(timestamp)

    if len(flow["timing"]) > 100:
        flow["timing"] = flow["timing"][-100:]

    if len(flow["timing"]) >= 5:
        intervals = [
            (flow["timing"][i] - flow["timing"][i - 1]).total_seconds()
            for i in range(1, len(flow["timing"]))
        ]
        if len(intervals) >= 10:
            mean_interval = statistics.mean(intervals)
            std_interval  = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            if std_interval < mean_interval * 0.1 and 0.1 <= mean_interval <= 60:
                return (
                    f"Regular encrypted communication pattern detected: "
                    f"{mean_interval:.2f}s intervals"
                )

    return None


# ---------------------------------------------------------------------------
# Encrypted traffic: packet size analysis
# ---------------------------------------------------------------------------

def analyze_packet_sizes(
    flow_key: str,
    size: int,
    encrypted_flows: FlowStore,
) -> str | None:
    """
    Append *size* to the flow's size history and look for:
    * A single size dominating > 30 % of all packets (protocol header pattern)
    * Alternating small-then-large bursts (control + data pattern)

    Returns an alert string if a pattern is detected, otherwise None.
    """
    flow = encrypted_flows[flow_key]
    flow["sizes"].append(size)

    if len(flow["sizes"]) > 200:
        flow["sizes"] = flow["sizes"][-200:]

    if len(flow["sizes"]) >= 20:
        size_counter = Counter(flow["sizes"])
        for sz, count in size_counter.most_common(5):
            if count > len(flow["sizes"]) * 0.3:
                return (
                    f"Repeated packet size pattern: {sz} bytes "
                    f"({count}/{len(flow['sizes'])} packets)"
                )

        recent = flow["sizes"][-10:]
        small_then_large = sum(
            1 for i in range(len(recent) - 1)
            if recent[i] < 100 and recent[i + 1] > 1000
        )
        if small_then_large > 3:
            return "Agent-like communication pattern: small control + large data transfers"

    return None


# ---------------------------------------------------------------------------
# Encrypted traffic: TLS fingerprinting
# ---------------------------------------------------------------------------

def detect_tls_fingerprints(
    packet,
    flow_key: str,
    encrypted_flows: FlowStore,
    encryption_patterns: CountStore,
) -> AlertList:
    """
    Analyse TLS handshake data for agent-software fingerprints.

    Two strategies are applied:
    1. If scapy's TLS layer is available, parse the TLS message directly.
    2. Inspect the raw payload bytes for TLS record type (0x16) and
       Client Hello marker — works regardless of TLS layer availability.

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, TCP, Raw, TLS = _L["IP"], _L["TCP"], _L["Raw"], _L["TLS"]

    alerts: AlertList = []

    # ── Strategy 1: scapy TLS layer ─────────────────────────────────────
    if TLS_AVAILABLE and TLS is not None and packet.haslayer(TLS):
        try:
            tls_layer = packet[TLS]
            flow = encrypted_flows[flow_key]

            if hasattr(tls_layer, "version"):
                flow["tls_info"]["version"] = tls_layer.version

            if hasattr(tls_layer, "msg") and tls_layer.msg:
                tls_data = bytes(tls_layer.msg)

                if b"\x00\x17" in tls_data:
                    flow["tls_info"]["extended_master_secret"] = True

                for pattern in AGENT_TLS_PATTERNS:
                    if pattern in tls_data:
                        alerts.append(
                            f"TLS fingerprint suggests agent software: "
                            f"{pattern.decode('utf-8', errors='ignore')}"
                        )
                        encryption_patterns["agent_tls_library"] += 1
        except Exception:
            pass  # degrade gracefully to strategy 2

    # ── Strategy 2: raw byte inspection ─────────────────────────────────
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw])
        if len(payload) >= 6:
            if payload[0] == 0x16:  # TLS Handshake record type
                tls_version = (payload[1] << 8) | payload[2]
                alerts.append(
                    f"TLS handshake detected (version: 0x{tls_version:04x}) "
                    f"from {packet[IP].src}"
                )
                encryption_patterns["tls_handshake"] += 1

            if b"\x01\x00" in payload[:10]:  # Client Hello message type
                alerts.append(f"TLS Client Hello detected from {packet[IP].src}")
                encryption_patterns["tls_client_hello"] += 1

    return alerts


# ---------------------------------------------------------------------------
# Encrypted traffic: payload pattern analysis
# ---------------------------------------------------------------------------

def analyze_encrypted_payload(
    packet,
    flow_key: str,
    encrypted_flows: FlowStore,
    encryption_patterns: CountStore,
) -> AlertList:
    """
    Analyse an encrypted payload for structural patterns without decrypting it.

    High-entropy payloads (> 7.5 bits) are checked for:
    * Repeated 16-byte headers
    * Alternating request/response size patterns
    * Potential nested base64 encoding
    * Non-uniform byte distribution (chi-square > 300)

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, Raw = _L["IP"], _L["Raw"]

    alerts: AlertList = []

    if not packet.haslayer(Raw):
        return alerts

    payload: bytes = bytes(packet[Raw])
    flow           = encrypted_flows[flow_key]
    entropy: float = calculate_entropy(payload)
    flow["entropy_scores"].append(entropy)

    if entropy <= 7.5:
        return alerts  # low entropy — not encrypted, no further analysis

    # ── Repeated header check ────────────────────────────────────────────
    if len(payload) >= 16:
        header = payload[:16]
        if payload.count(header) > 1:
            alerts.append(
                f"Repeated header pattern in encrypted stream from {packet[IP].src}"
            )
            encryption_patterns["repeated_headers"] += 1

    # ── Request/response length pattern ─────────────────────────────────
    flow["flow_patterns"].append(len(payload))
    if len(flow["flow_patterns"]) >= 10:
        recent = flow["flow_patterns"][-10:]
        alternating = all(
            abs(recent[i] - recent[i - 1]) >= 50
            for i in range(1, len(recent))
        )
        if alternating and len(set(recent)) <= 3:
            alerts.append("Encrypted request/response pattern suggests agent protocol")
            encryption_patterns["req_resp_pattern"] += 1

    # ── Nested base64 encoding check ─────────────────────────────────────
    if len(payload) > 50:
        try:
            decoded = payload.decode("utf-8", errors="ignore")
            base64_chars = set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            )
            if len(decoded) > 0 and len(set(decoded) & base64_chars) > len(decoded) * 0.8:
                alerts.append("Potential nested encoding in encrypted stream")
                encryption_patterns["nested_encoding"] += 1
        except Exception:
            pass

    # ── Chi-square byte uniformity test ─────────────────────────────────
    if len(payload) >= 100:
        chi_sq = chi_square_uniformity(payload)
        if chi_sq > 300:
            alerts.append(
                "Unusual byte distribution in encrypted data suggests nested protocols"
            )
            encryption_patterns["unusual_distribution"] += 1

    return alerts


# ---------------------------------------------------------------------------
# Encrypted traffic: orchestrator
# ---------------------------------------------------------------------------

def detect_encrypted_agent_traffic(
    packet,
    encrypted_flows: FlowStore,
    encryption_patterns: CountStore,
) -> AlertList:
    """
    Main entry point for encrypted-traffic analysis.

    Builds a per-flow record keyed by ``src_ip:dst_ip:dst_port``, then
    delegates to the four specialised helpers and performs flow-level
    rate and persistence checks.

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, TCP = _L["IP"], _L["TCP"]

    alerts: AlertList = []

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return alerts

    src_ip:      str      = packet[IP].src
    dst_ip:      str      = packet[IP].dst
    dst_port:    int      = packet[TCP].dport
    flow_key:    str      = f"{src_ip}:{dst_ip}:{dst_port}"
    timestamp:   datetime = datetime.now()
    packet_size: int      = len(packet)

    # ── Maintain bounded packet timestamp list ───────────────────────────
    flow = encrypted_flows[flow_key]
    flow["packets"].append(timestamp)
    if len(flow["packets"]) > 500:
        flow["packets"] = flow["packets"][-500:]

    # ── Delegate to specialised helpers ─────────────────────────────────
    timing_alert = analyze_packet_timing(flow_key, timestamp, encrypted_flows)
    if timing_alert:
        alerts.append(timing_alert)

    size_alert = analyze_packet_sizes(flow_key, packet_size, encrypted_flows)
    if size_alert:
        alerts.append(size_alert)

    alerts.extend(detect_tls_fingerprints(packet, flow_key, encrypted_flows, encryption_patterns))
    alerts.extend(analyze_encrypted_payload(packet, flow_key, encrypted_flows, encryption_patterns))

    # ── Flow-level rate and persistence checks ───────────────────────────
    if len(flow["packets"]) >= 50:
        recent_pkts = [p for p in flow["packets"] if (timestamp - p).total_seconds() < 60]
        ppm = len(recent_pkts)
        if ppm > 30:
            alerts.append(
                f"High-frequency encrypted communication: {ppm} ppm to {dst_ip}:{dst_port}"
            )
            encryption_patterns["high_freq_encrypted"] += 1

        session_duration = (timestamp - flow["packets"][0]).total_seconds()
        if session_duration > 1800:
            alerts.append(
                f"Long-lived encrypted session: {session_duration / 60:.1f} minutes "
                f"to {dst_ip}:{dst_port}"
            )
            encryption_patterns["persistent_encrypted"] += 1

    return alerts


# ---------------------------------------------------------------------------
# General traffic pattern analysis
# ---------------------------------------------------------------------------

def analyze_traffic_patterns(
    packet,
    traffic_stats,
    protocol_stats: CountStore,
) -> AlertList:
    """
    Analyse general traffic patterns for anomalies.

    * Tracks per-source-IP packet timestamps within a rolling baseline window.
    * Alerts when the per-IP packet rate exceeds 10 packets/second.
    * Counts TCP and UDP packets for the protocol distribution report.

    Returns a list of alert strings.
    """
    _L = _layers()
    IP, TCP, UDP = _L["IP"], _L["TCP"], _L["UDP"]

    alerts: AlertList = []
    current_time      = datetime.now()

    if not packet.haslayer(IP):
        return alerts

    src_ip: str = packet[IP].src
    traffic_stats[src_ip].append(current_time)

    # Evict entries older than the baseline window
    cutoff = current_time - timedelta(seconds=BASELINE_WINDOW)
    while traffic_stats[src_ip] and traffic_stats[src_ip][0] < cutoff:
        traffic_stats[src_ip].popleft()

    if len(traffic_stats[src_ip]) > 10:
        time_span = (current_time - traffic_stats[src_ip][0]).total_seconds()
        if time_span > 0:
            packet_rate = len(traffic_stats[src_ip]) / time_span
            if packet_rate > 10:
                alerts.append(f"High packet rate from {src_ip}: {packet_rate:.2f} pps")

    if packet.haslayer(TCP):
        protocol_stats["TCP"] += 1
    elif packet.haslayer(UDP):
        protocol_stats["UDP"] += 1

    return alerts
