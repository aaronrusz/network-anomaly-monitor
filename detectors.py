"""
detectors.py — All packet-level detection logic:
    * AI/ML service traffic
    * Agent protocol detection (A2A, ACP, MCP)
    * Protocol signature scanning
    * Encrypted traffic analysis
    * General traffic pattern anomalies
"""

import re
import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import IP, TCP, UDP, DNS, Raw
    try:
        from scapy.layers.tls import TLS
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False
except ImportError as e:
    raise ImportError(f"Required package missing: {e}") from e

from .config import (
    AI_PROTOCOLS,
    AGENT_PROTOCOLS,
    AI_AGENT_PATTERNS,
    JSON_RPC_AGENT_PATTERNS,
    COORDINATION_KEYWORDS,
    AGENT_TLS_PATTERNS,
    AI_STANDARD_PORTS,
    BASELINE_WINDOW,
)
from .crypto_utils import calculate_entropy, chi_square_uniformity


# ---------------------------------------------------------------------------
# AI / ML service detection
# ---------------------------------------------------------------------------

def detect_ai_traffic(packet, dns_queries, connection_counts, agent_protocols_cfg):
    """Detect potential AI/ML API traffic. Returns a list of alert strings."""
    alerts = []

    if not packet.haslayer(IP):
        return alerts

    # DNS-level detection
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
        dns_queries.append({
            'timestamp': datetime.now(),
            'query': query,
            'src_ip': packet[IP].src,
        })
        for service, domains in AI_PROTOCOLS.items():
            for domain in domains:
                if domain in query:
                    alerts.append(
                        f"AI Service DNS Query: {service} - {query} from {packet[IP].src}"
                    )

    # TCP connection-level detection
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        agent_ports = []
        for cfg in agent_protocols_cfg.values():
            agent_ports.extend(cfg['ports'])
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

def detect_agent_protocols(packet, agent_connections, protocol_sessions, suspicious_patterns):
    """Detect A2A, ACP, and MCP protocol traffic. Returns a list of alert strings."""
    alerts = []

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return alerts

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    dst_port = packet[TCP].dport
    src_port = packet[TCP].sport

    for protocol_name, config in AGENT_PROTOCOLS.items():
        if dst_port in config['ports'] or src_port in config['ports']:
            conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
            agent_connections[protocol_name].append({
                'timestamp': datetime.now(),
                'connection': conn_key,
                'direction': 'outbound' if dst_port in config['ports'] else 'inbound',
            })
            protocol_sessions[protocol_name] += 1
            alerts.append(
                f"{protocol_name.upper()} Protocol Traffic: {conn_key} "
                f"(Session #{protocol_sessions[protocol_name]})"
            )

    # Detect potential agent mesh networks
    all_agent_ports = []
    for cfg in AGENT_PROTOCOLS.values():
        all_agent_ports.extend(cfg['ports'])

    if dst_port in all_agent_ports and src_port in all_agent_ports:
        alerts.append(
            f"Agent-to-Agent Communication Detected: "
            f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
        )
        suspicious_patterns['agent_mesh'] += 1

    # Rapid successive connections → agent swarm
    current_time = datetime.now()
    recent_connections = []
    for protocol_conns in agent_connections.values():
        recent_connections.extend(
            c for c in protocol_conns
            if (current_time - c['timestamp']).total_seconds() < 60
        )

    if len(recent_connections) > 20:
        alerts.append(
            f"Potential Agent Swarm Activity: "
            f"{len(recent_connections)} connections in last minute"
        )
        suspicious_patterns['swarm_activity'] += 1

    return alerts


# ---------------------------------------------------------------------------
# Protocol signature scanning
# ---------------------------------------------------------------------------

def detect_protocol_signatures(packet, suspicious_patterns):
    """Detect protocol-specific signatures in packet payload. Returns a list of alert strings."""
    alerts = []

    if not (packet.haslayer(TCP) and hasattr(packet[TCP], 'payload')):
        return alerts

    try:
        payload = str(packet[TCP].payload)

        # Agent protocol URL/content patterns
        for protocol_name, config in AGENT_PROTOCOLS.items():
            for pattern in config['patterns']:
                if re.search(pattern, payload, re.IGNORECASE):
                    alerts.append(
                        f"{protocol_name.upper()} Protocol Pattern Detected: "
                        f"{pattern} in traffic from {packet[IP].src}"
                    )
                    suspicious_patterns[f'{protocol_name}_pattern'] += 1

        # JSON-RPC agent patterns
        for pattern in JSON_RPC_AGENT_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                alerts.append(
                    f"Agent JSON-RPC Communication: {pattern[:30]}... "
                    f"from {packet[IP].src}"
                )
                suspicious_patterns['json_rpc_agent'] += 1

        # Multi-agent coordination keywords
        for keyword in COORDINATION_KEYWORDS:
            if keyword.lower() in payload.lower():
                alerts.append(
                    f"Multi-Agent Coordination Keyword: '{keyword}' "
                    f"detected from {packet[IP].src}"
                )
                suspicious_patterns['coordination'] += 1
                break  # one alert per packet

    except (UnicodeDecodeError, AttributeError):
        pass

    return alerts


# ---------------------------------------------------------------------------
# Encrypted traffic analysis helpers
# ---------------------------------------------------------------------------

def analyze_packet_timing(flow_key, timestamp, encrypted_flows):
    """Analyse timing patterns in an encrypted flow. Returns an alert string or None."""
    flow = encrypted_flows[flow_key]
    flow['timing'].append(timestamp)

    if len(flow['timing']) > 100:
        flow['timing'] = flow['timing'][-100:]

    if len(flow['timing']) >= 5:
        intervals = [
            (flow['timing'][i] - flow['timing'][i - 1]).total_seconds()
            for i in range(1, len(flow['timing']))
        ]
        if len(intervals) >= 10:
            mean_interval = statistics.mean(intervals)
            std_interval  = statistics.stdev(intervals) if len(intervals) > 1 else 0
            if std_interval < mean_interval * 0.1 and 0.1 <= mean_interval <= 60:
                return (
                    f"Regular encrypted communication pattern detected: "
                    f"{mean_interval:.2f}s intervals"
                )

    return None


def analyze_packet_sizes(flow_key, size, encrypted_flows):
    """Analyse packet size patterns in an encrypted flow. Returns an alert string or None."""
    flow = encrypted_flows[flow_key]
    flow['sizes'].append(size)

    if len(flow['sizes']) > 200:
        flow['sizes'] = flow['sizes'][-200:]

    if len(flow['sizes']) >= 20:
        size_counter = Counter(flow['sizes'])
        for sz, count in size_counter.most_common(5):
            if count > len(flow['sizes']) * 0.3:
                return (
                    f"Repeated packet size pattern: {sz} bytes "
                    f"({count}/{len(flow['sizes'])} packets)"
                )

        recent_sizes = flow['sizes'][-10:]
        small_then_large = sum(
            1 for i in range(len(recent_sizes) - 1)
            if recent_sizes[i] < 100 and recent_sizes[i + 1] > 1000
        )
        if small_then_large > 3:
            return "Agent-like communication pattern: small control + large data transfers"

    return None


def detect_tls_fingerprints(packet, flow_key, encrypted_flows, encryption_patterns):
    """Analyse TLS handshake for agent protocol fingerprints. Returns a list of alert strings."""
    alerts = []

    if TLS_AVAILABLE:
        try:
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                flow = encrypted_flows[flow_key]

                if hasattr(tls_layer, 'version'):
                    flow['tls_info']['version'] = tls_layer.version

                if hasattr(tls_layer, 'msg') and tls_layer.msg:
                    tls_data = bytes(tls_layer.msg)

                    if b'\x00\x17' in tls_data:
                        flow['tls_info']['extended_master_secret'] = True

                    for pattern in AGENT_TLS_PATTERNS:
                        if pattern in tls_data:
                            alerts.append(
                                f"TLS fingerprint suggests agent software: "
                                f"{pattern.decode('utf-8', errors='ignore')}"
                            )
                            encryption_patterns['agent_tls_library'] += 1
        except Exception:
            pass

    # Fallback raw TLS detection
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw])
        if len(payload) >= 6:
            if payload[0] == 0x16:
                tls_version = (payload[1] << 8) | payload[2]
                alerts.append(
                    f"TLS handshake detected (version: 0x{tls_version:04x}) "
                    f"from {packet[IP].src}"
                )
                encryption_patterns['tls_handshake'] += 1

            if b'\x01\x00' in payload[:10]:
                alerts.append(f"TLS Client Hello detected from {packet[IP].src}")
                encryption_patterns['tls_client_hello'] += 1

    return alerts


def analyze_encrypted_payload(packet, flow_key, encrypted_flows, encryption_patterns):
    """Analyse encrypted payload for patterns without decrypting. Returns a list of alert strings."""
    alerts = []

    if not packet.haslayer(Raw):
        return alerts

    payload = bytes(packet[Raw])
    flow = encrypted_flows[flow_key]
    entropy = calculate_entropy(payload)
    flow['entropy_scores'].append(entropy)

    if entropy > 7.5:
        # Repeated header pattern
        if len(payload) >= 16:
            header = payload[:16]
            if payload.count(header) > 1:
                alerts.append(
                    f"Repeated header pattern in encrypted stream from {packet[IP].src}"
                )
                encryption_patterns['repeated_headers'] += 1

        # Length pattern analysis
        payload_len = len(payload)
        flow['flow_patterns'].append(payload_len)

        if len(flow['flow_patterns']) >= 10:
            recent_patterns = flow['flow_patterns'][-10:]
            alternating = all(
                abs(recent_patterns[i] - recent_patterns[i - 1]) >= 50
                for i in range(1, len(recent_patterns))
            )
            if alternating and len(set(recent_patterns)) <= 3:
                alerts.append("Encrypted request/response pattern suggests agent protocol")
                encryption_patterns['req_resp_pattern'] += 1

        # Nested base64 encoding check
        if len(payload) > 50:
            try:
                decoded_attempt = payload.decode('utf-8', errors='ignore')
                base64_chars = set(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
                )
                if len(set(decoded_attempt) & base64_chars) > len(decoded_attempt) * 0.8:
                    alerts.append("Potential nested encoding in encrypted stream")
                    encryption_patterns['nested_encoding'] += 1
            except Exception:
                pass

        # Chi-square byte uniformity test
        if len(payload) >= 100:
            chi_square = chi_square_uniformity(payload)
            if chi_square > 300:
                alerts.append(
                    "Unusual byte distribution in encrypted data suggests nested protocols"
                )
                encryption_patterns['unusual_distribution'] += 1

    return alerts


# ---------------------------------------------------------------------------
# Encrypted traffic orchestrator
# ---------------------------------------------------------------------------

def detect_encrypted_agent_traffic(packet, encrypted_flows, encryption_patterns):
    """Main entry point for encrypted-traffic analysis. Returns a list of alert strings."""
    alerts = []

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return alerts

    src_ip    = packet[IP].src
    dst_ip    = packet[IP].dst
    dst_port  = packet[TCP].dport
    flow_key  = f"{src_ip}:{dst_ip}:{dst_port}"
    timestamp = datetime.now()
    packet_size = len(packet)

    flow = encrypted_flows[flow_key]
    flow['packets'].append(timestamp)
    if len(flow['packets']) > 500:
        flow['packets'] = flow['packets'][-500:]

    timing_alert = analyze_packet_timing(flow_key, timestamp, encrypted_flows)
    if timing_alert:
        alerts.append(timing_alert)

    size_alert = analyze_packet_sizes(flow_key, packet_size, encrypted_flows)
    if size_alert:
        alerts.append(size_alert)

    alerts.extend(detect_tls_fingerprints(packet, flow_key, encrypted_flows, encryption_patterns))
    alerts.extend(analyze_encrypted_payload(packet, flow_key, encrypted_flows, encryption_patterns))

    # Flow-level rate / persistence checks
    if len(flow['packets']) >= 50:
        recent_packets = [p for p in flow['packets'] if (timestamp - p).total_seconds() < 60]
        ppm = len(recent_packets)
        if ppm > 30:
            alerts.append(
                f"High-frequency encrypted communication: {ppm} ppm to {dst_ip}:{dst_port}"
            )
            encryption_patterns['high_freq_encrypted'] += 1

        session_duration = (timestamp - flow['packets'][0]).total_seconds()
        if session_duration > 1800:
            alerts.append(
                f"Long-lived encrypted session: {session_duration / 60:.1f} minutes "
                f"to {dst_ip}:{dst_port}"
            )
            encryption_patterns['persistent_encrypted'] += 1

    return alerts


# ---------------------------------------------------------------------------
# General traffic pattern analysis
# ---------------------------------------------------------------------------

def analyze_traffic_patterns(packet, traffic_stats, protocol_stats):
    """Analyse traffic for anomalous patterns. Returns a list of alert strings."""
    alerts = []
    current_time = datetime.now()

    if not packet.haslayer(IP):
        return alerts

    src_ip = packet[IP].src
    traffic_stats[src_ip].append(current_time)

    # Evict entries older than the baseline window
    cutoff_time = current_time - timedelta(seconds=BASELINE_WINDOW)
    while traffic_stats[src_ip] and traffic_stats[src_ip][0] < cutoff_time:
        traffic_stats[src_ip].popleft()

    if len(traffic_stats[src_ip]) > 10:
        time_span = (current_time - traffic_stats[src_ip][0]).total_seconds()
        if time_span > 0:
            packet_rate = len(traffic_stats[src_ip]) / time_span
            if packet_rate > 10:
                alerts.append(f"High packet rate from {src_ip}: {packet_rate:.2f} pps")

    if packet.haslayer(TCP):
        protocol_stats['TCP'] += 1
    elif packet.haslayer(UDP):
        protocol_stats['UDP'] += 1

    return alerts
