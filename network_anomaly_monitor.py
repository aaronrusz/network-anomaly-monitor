#!/usr/bin/env python3
"""
Network Anomaly Detection and AI Agent Protocol Monitor
Requires: pip install scapy psutil requests
Run with elevated privileges (sudo on Linux/Mac, admin on Windows)
"""

import time
import json
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics
import re
import hashlib
import numpy as np
from collections import Counter
import math

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    import psutil
    import requests
    from scipy import stats

    # Try to import TLS support - it's optional for encrypted analysis
    try:
        from scapy.layers.tls import TLS
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False
        print("Note: TLS layer not available in this scapy version. TLS fingerprinting will be limited.")

except ImportError as e:
    print(f"Required package missing: {e}")
    print("Install with: pip install scapy psutil requests scipy numpy")
    exit(1)

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.baseline_window = 300  # 5 minutes for baseline
        self.alert_threshold = 2.0  # Standard deviations for anomaly

        # Traffic tracking
        self.traffic_stats = defaultdict(lambda: deque(maxlen=100))
        self.connection_counts = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.dns_queries = deque(maxlen=1000)

        # AI/ML protocol signatures
        self.ai_protocols = {
            'openai': ['api.openai.com', 'openai.com'],
            'anthropic': ['api.anthropic.com', 'claude.ai'],
            'google_ai': ['generativelanguage.googleapis.com', 'bard.google.com'],
            'azure_openai': ['openai.azure.com'],
            'huggingface': ['huggingface.co', 'api-inference.huggingface.co'],
            'ollama': ['localhost:11434'],  # Default Ollama port
            'langchain': ['langchain.com', 'api.langchain.com'],
            'replicate': ['replicate.com', 'api.replicate.com'],
            'cohere': ['api.cohere.ai'],
            'stability': ['api.stability.ai'],
        }

        # Agent-to-Agent and specialized protocol ports/patterns
        self.agent_protocols = {
            'a2a': {
                'ports': [8080, 8081, 8082, 9090, 9091, 5000, 5001],  # Common A2A ports
                'patterns': [r'agent-to-agent', r'a2a-protocol', r'/agents/', r'/communicate'],
                'content_types': ['application/x-a2a', 'application/agent-message']
            },
            'acp': {
                'ports': [7000, 7001, 7777, 8888, 9999],  # Common ACP ports
                'patterns': [r'agent-communication', r'acp-protocol', r'/acp/', r'agent-comm'],
                'content_types': ['application/x-acp', 'application/agent-comm']
            },
            'mcp': {
                'ports': [3000, 3001, 3333, 4000, 4001],  # Common MCP ports
                'patterns': [r'model-context', r'mcp-protocol', r'/mcp/', r'context-protocol'],
                'content_types': ['application/x-mcp', 'application/model-context']
            }
        }

        # Common AI agent user agents and headers
        self.ai_agent_patterns = [
            r'langchain',
            r'openai-python',
            r'anthropic-sdk',
            r'ollama',
            r'autogen',
            r'crewai',
            r'agent',
            r'llm',
            r'chatbot',
            r'a2a-agent',
            r'acp-client',
            r'mcp-client',
            r'agent-framework',
            r'multi-agent',
            r'swarm',
        ]

        # Protocol-specific tracking
        self.agent_connections = defaultdict(list)
        self.protocol_sessions = defaultdict(int)
        self.suspicious_patterns = defaultdict(int)

        # Encrypted traffic analysis
        self.encrypted_flows = defaultdict(lambda: {
            'packets': [],
            'sizes': [],
            'timing': [],
            'entropy_scores': [],
            'tls_info': {},
            'flow_patterns': []
        })
        self.flow_fingerprints = defaultdict(list)
        self.encryption_patterns = defaultdict(int)

        self.alerts = []
        self.running = False

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def detect_agent_protocols(self, packet):
        """Detect A2A, ACP, and MCP protocol traffic"""
        alerts = []

        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport

            # Check for agent protocol ports
            for protocol_name, config in self.agent_protocols.items():
                if dst_port in config['ports'] or src_port in config['ports']:
                    conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                    self.agent_connections[protocol_name].append({
                        'timestamp': datetime.now(),
                        'connection': conn_key,
                        'direction': 'outbound' if dst_port in config['ports'] else 'inbound'
                    })

                    # Increment session counter
                    self.protocol_sessions[protocol_name] += 1

                    alerts.append(f"{protocol_name.upper()} Protocol Traffic: {conn_key} (Session #{self.protocol_sessions[protocol_name]})")

            # Detect potential agent mesh networks (multiple agents communicating)
            agent_ports = []
            for config in self.agent_protocols.values():
                agent_ports.extend(config['ports'])

            if dst_port in agent_ports and src_port in agent_ports:
                alerts.append(f"Agent-to-Agent Communication Detected: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
                self.suspicious_patterns['agent_mesh'] += 1

            # Look for rapid successive connections (agent swarm behavior)
            current_time = datetime.now()
            recent_connections = []
            for protocol_connections in self.agent_connections.values():
                recent_connections.extend([
                    conn for conn in protocol_connections 
                    if (current_time - conn['timestamp']).total_seconds() < 60
                ])

            if len(recent_connections) > 20:  # More than 20 agent connections in last minute
                alerts.append(f"Potential Agent Swarm Activity: {len(recent_connections)} connections in last minute")
                self.suspicious_patterns['swarm_activity'] += 1

    def detect_ai_traffic(self, packet):
        """Detect potential AI/ML API traffic"""
        alerts = []

        if packet.haslayer(IP):
            # Check DNS queries for AI services
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                self.dns_queries.append({
                    'timestamp': datetime.now(),
                    'query': query,
                    'src_ip': packet[IP].src
                })

                # Check if DNS query matches AI service domains
                for service, domains in self.ai_protocols.items():
                    for domain in domains:
                        if domain in query:
                            alerts.append(f"AI Service DNS Query: {service} - {query} from {packet[IP].src}")

            # Check HTTP/HTTPS traffic patterns
            if packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport

                # Common AI API ports (including agent protocol ports)
                ai_ports = [80, 443, 8080, 11434]  # Standard ports
                agent_ports = []
                for config in self.agent_protocols.values():
                    agent_ports.extend(config['ports'])
                all_monitored_ports = ai_ports + agent_ports

                if dst_port in all_monitored_ports:
                    # Track connection patterns
                    conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                    self.connection_counts[conn_key] += 1

                    # High frequency connections might indicate AI agents
                    if self.connection_counts[conn_key] > 50:  # Threshold
                        alerts.append(f"High frequency AI-like traffic: {conn_key} ({self.connection_counts[conn_key]} connections)")

        return alerts

    def detect_protocol_signatures(self, packet):
        """Detect protocol-specific signatures in packet payload"""
        alerts = []

        if packet.haslayer(TCP) and hasattr(packet[TCP], 'payload'):
            try:
                payload = str(packet[TCP].payload)

                # Check for protocol-specific patterns in payload
                for protocol_name, config in self.agent_protocols.items():
                    for pattern in config['patterns']:
                        if re.search(pattern, payload, re.IGNORECASE):
                            alerts.append(f"{protocol_name.upper()} Protocol Pattern Detected: {pattern} in traffic from {packet[IP].src}")
                            self.suspicious_patterns[f'{protocol_name}_pattern'] += 1

                # Check for JSON-RPC patterns (common in agent protocols)
                json_rpc_patterns = [
                    r'"method"\s*:\s*"agent\.',
                    r'"method"\s*:\s*"communicate"',
                    r'"method"\s*:\s*"execute_task"',
                    r'"method"\s*:\s*"coordinate"',
                    r'"params"\s*:\s*\{.*"agent_id"',
                    r'"result"\s*:\s*\{.*"status".*"completed"'
                ]

                for pattern in json_rpc_patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        alerts.append(f"Agent JSON-RPC Communication: {pattern[:30]}... from {packet[IP].src}")
                        self.suspicious_patterns['json_rpc_agent'] += 1

                # Check for multi-agent coordination keywords
                coordination_keywords = [
                    'task_delegation', 'agent_handoff', 'coordination_request',
                    'agent_status', 'task_assignment', 'agent_response',
                    'multi_agent', 'agent_swarm', 'collective_intelligence'
                ]

                for keyword in coordination_keywords:
                    if keyword.lower() in payload.lower():
                        alerts.append(f"Multi-Agent Coordination Keyword: '{keyword}' detected from {packet[IP].src}")
                        self.suspicious_patterns['coordination'] += 1
                        break  # Only alert once per packet

            except (UnicodeDecodeError, AttributeError):
                # Skip packets we can't decode
                pass

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data to detect encryption patterns"""
        if not data:
            return 0

        # Convert to bytes if string
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')

        # Count frequency of each byte value
        byte_counts = Counter(data)
        data_len = len(data)

        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_packet_timing(self, flow_key, timestamp):
        """Analyze timing patterns in encrypted flows"""
        flow = self.encrypted_flows[flow_key]
        flow['timing'].append(timestamp)

        # Keep only recent timing data (last 100 packets)
        if len(flow['timing']) > 100:
            flow['timing'] = flow['timing'][-100:]

        # Calculate inter-arrival times if we have enough data
        if len(flow['timing']) >= 5:
            intervals = []
            for i in range(1, len(flow['timing'])):
                interval = (flow['timing'][i] - flow['timing'][i-1]).total_seconds()
                intervals.append(interval)

            # Detect regular patterns (potential agent heartbeats)
            if len(intervals) >= 10:
                mean_interval = statistics.mean(intervals)
                std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

                # Regular intervals might indicate automated agent communication
                if std_interval < mean_interval * 0.1 and 0.1 <= mean_interval <= 60:  # Very regular, 0.1s to 1min intervals
                    return f"Regular encrypted communication pattern detected: {mean_interval:.2f}s intervals"

        return None

    def analyze_packet_sizes(self, flow_key, size):
        """Analyze packet size patterns in encrypted flows"""
        flow = self.encrypted_flows[flow_key]
        flow['sizes'].append(size)

        # Keep only recent size data
        if len(flow['sizes']) > 200:
            flow['sizes'] = flow['sizes'][-200:]

        if len(flow['sizes']) >= 20:
            # Look for patterns in packet sizes
            size_counter = Counter(flow['sizes'])

            # Check for repeated exact sizes (potential protocol signatures)
            most_common = size_counter.most_common(5)
            for size, count in most_common:
                if count > len(flow['sizes']) * 0.3:  # More than 30% of packets same size
                    return f"Repeated packet size pattern: {size} bytes ({count}/{len(flow['sizes'])} packets)"

            # Check for size patterns typical of AI/agent protocols
            # Small control messages followed by larger data
            recent_sizes = flow['sizes'][-10:]
            small_then_large = sum(1 for i in range(len(recent_sizes)-1) 
                                 if recent_sizes[i] < 100 and recent_sizes[i+1] > 1000)

            if small_then_large > 3:  # Multiple small->large patterns
                return "Agent-like communication pattern: small control + large data transfers"

        return None

    def detect_tls_fingerprints(self, packet, flow_key):
        """Analyze TLS handshake for agent protocol fingerprints"""
        alerts = []

        # Check if TLS support is available
        if not TLS_AVAILABLE:
            return alerts

        try:
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                flow = self.encrypted_flows[flow_key]

                # Extract TLS version and cipher suites if available
                if hasattr(tls_layer, 'version'):
                    flow['tls_info']['version'] = tls_layer.version

                # Look for specific cipher preferences that might indicate agent software
                if hasattr(tls_layer, 'msg') and tls_layer.msg:
                    # This is a simplified check - real implementation would need deeper TLS parsing
                    tls_data = bytes(tls_layer.msg)

                    # Check for specific TLS extensions or patterns
                    if b'\x00\x17' in tls_data:  # Extended Master Secret extension
                        flow['tls_info']['extended_master_secret'] = True

                    # Agent software often uses specific libraries with identifiable TLS fingerprints
                    agent_tls_patterns = [
                        b'python-requests',  # Python requests library
                        b'aiohttp',         # Async HTTP client
                        b'httpx',           # Modern Python HTTP client
                        b'golang',          # Go HTTP client
                        b'node-fetch'       # Node.js fetch
                    ]

                    for pattern in agent_tls_patterns:
                        if pattern in tls_data:
                            alerts.append(f"TLS fingerprint suggests agent software: {pattern.decode('utf-8', errors='ignore')}")
                            self.encryption_patterns['agent_tls_library'] += 1

        except Exception:
            # If no TLS layer or parsing fails, try alternative SSL/TLS detection
            pass

        # Alternative TLS detection for older scapy versions or when TLS layer isn't available
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw])

            # Look for TLS handshake patterns in raw data
            if len(payload) >= 6:
                # TLS handshake starts with specific byte patterns
                # 0x16 = Handshake, followed by version bytes
                if payload[0] == 0x16:  # TLS Handshake
                    if len(payload) >= 6:
                        tls_version = (payload[1] << 8) | payload[2]
                        alerts.append(f"TLS handshake detected (version: 0x{tls_version:04x}) from {packet[IP].src}")
                        self.encryption_patterns['tls_handshake'] += 1

                # Look for specific TLS client hello patterns
                if b'\x01\x00' in payload[:10]:  # Client Hello message type
                    alerts.append(f"TLS Client Hello detected from {packet[IP].src}")
                    self.encryption_patterns['tls_client_hello'] += 1

        return alerts

    def analyze_encrypted_payload(self, packet, flow_key):
        """Analyze encrypted payload for patterns without decrypting"""
        alerts = []

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            flow = self.encrypted_flows[flow_key]

            # Calculate entropy to confirm encryption
            entropy = self.calculate_entropy(payload)
            flow['entropy_scores'].append(entropy)

            # High entropy suggests encryption, but patterns in encrypted data can still reveal info
            if entropy > 7.5:  # High entropy indicates encryption
                # Look for patterns even in encrypted data

                # 1. Check for repeated byte sequences (potential protocol headers)
                if len(payload) >= 16:
                    header = payload[:16]
                    if payload.count(header) > 1:
                        alerts.append(f"Repeated header pattern in encrypted stream from {packet[IP].src}")
                        self.encryption_patterns['repeated_headers'] += 1

                # 2. Look for length patterns typical of JSON-RPC or similar protocols
                # Even encrypted, these often have predictable structures
                payload_len = len(payload)
                flow['flow_patterns'].append(payload_len)

                if len(flow['flow_patterns']) >= 10:
                    recent_patterns = flow['flow_patterns'][-10:]

                    # Check for alternating request/response pattern lengths
                    alternating = True
                    for i in range(1, len(recent_patterns)):
                        if abs(recent_patterns[i] - recent_patterns[i-1]) < 50:  # Similar sizes
                            alternating = False
                            break

                    if alternating and len(set(recent_patterns)) <= 3:  # Few distinct sizes
                        alerts.append("Encrypted request/response pattern suggests agent protocol")
                        self.encryption_patterns['req_resp_pattern'] += 1

                # 3. Check for base64-like patterns (sometimes used in agent protocols)
                # Even within encrypted streams, there might be nested encoding
                base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
                if len(payload) > 50:
                    try:
                        decoded_attempt = payload.decode('utf-8', errors='ignore')
                        if len(set(decoded_attempt) & base64_chars) > len(decoded_attempt) * 0.8:
                            alerts.append("Potential nested encoding in encrypted stream")
                            self.encryption_patterns['nested_encoding'] += 1
                    except:
                        pass

                # 4. Statistical analysis of byte distribution
                if len(payload) >= 100:
                    byte_freqs = [payload.count(i) for i in range(256)]

                    # Calculate chi-square test against uniform distribution
                    expected = len(payload) / 256
                    chi_square = sum((observed - expected) ** 2 / expected for observed in byte_freqs if expected > 0)

                    # Very high chi-square might indicate poor encryption or nested protocols
                    if chi_square > 300:  # Arbitrary threshold
                        alerts.append("Unusual byte distribution in encrypted data suggests nested protocols")
                        self.encryption_patterns['unusual_distribution'] += 1

        return alerts

    def detect_encrypted_agent_traffic(self, packet):
        """Main function to detect agent protocols in encrypted traffic"""
        alerts = []

        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            # Create flow identifier
            flow_key = f"{src_ip}:{dst_ip}:{dst_port}"
            timestamp = datetime.now()
            packet_size = len(packet)

            # Store packet info for flow analysis
            flow = self.encrypted_flows[flow_key]
            flow['packets'].append(timestamp)

            # Keep flow data manageable
            if len(flow['packets']) > 500:
                flow['packets'] = flow['packets'][-500:]

            # Analyze timing patterns
            timing_alert = self.analyze_packet_timing(flow_key, timestamp)
            if timing_alert:
                alerts.append(timing_alert)

            # Analyze packet size patterns  
            size_alert = self.analyze_packet_sizes(flow_key, packet_size)
            if size_alert:
                alerts.append(size_alert)

            # Analyze TLS fingerprints
            tls_alerts = self.detect_tls_fingerprints(packet, flow_key)
            alerts.extend(tls_alerts)

            # Analyze encrypted payload patterns
            payload_alerts = self.analyze_encrypted_payload(packet, flow_key)
            alerts.extend(payload_alerts)

            # Flow-level analysis
            if len(flow['packets']) >= 50:
                # Calculate packets per minute
                recent_packets = [p for p in flow['packets'] if (timestamp - p).total_seconds() < 60]
                ppm = len(recent_packets)

                # High packet rate in encrypted channel
                if ppm > 30:  # More than 30 packets per minute
                    alerts.append(f"High-frequency encrypted communication: {ppm} ppm to {dst_ip}:{dst_port}")
                    self.encryption_patterns['high_freq_encrypted'] += 1

                # Long-lived encrypted sessions (potential persistent agent connections)
                session_duration = (timestamp - flow['packets'][0]).total_seconds()
                if session_duration > 1800:  # More than 30 minutes
                    alerts.append(f"Long-lived encrypted session: {session_duration/60:.1f} minutes to {dst_ip}:{dst_port}")
                    self.encryption_patterns['persistent_encrypted'] += 1

        return alerts
        """Detect potential AI/ML API traffic"""
        alerts = []

        if packet.haslayer(IP):
            # Check DNS queries for AI services
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                self.dns_queries.append({
                    'timestamp': datetime.now(),
                    'query': query,
                    'src_ip': packet[IP].src
                })

                # Check if DNS query matches AI service domains
                for service, domains in self.ai_protocols.items():
                    for domain in domains:
                        if domain in query:
                            alerts.append(f"AI Service DNS Query: {service} - {query} from {packet[IP].src}")

            # Check HTTP/HTTPS traffic patterns
            if packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport

                # Common AI API ports (including agent protocol ports)
                ai_ports = [80, 443, 8080, 11434]  # Standard ports
                agent_ports = []
                for config in self.agent_protocols.values():
                    agent_ports.extend(config['ports'])
                all_monitored_ports = ai_ports + agent_ports

                if dst_port in all_monitored_ports:
                    # Track connection patterns
                    conn_key = f"{src_ip}:{dst_ip}:{dst_port}"
                    self.connection_counts[conn_key] += 1

                    # High frequency connections might indicate AI agents
                    if self.connection_counts[conn_key] > 50:  # Threshold
                        alerts.append(f"High frequency AI-like traffic: {conn_key} ({self.connection_counts[conn_key]} connections)")

        return alerts

    def analyze_traffic_patterns(self, packet):
        """Analyze traffic for anomalous patterns"""
        alerts = []
        current_time = datetime.now()

        if packet.haslayer(IP):
            src_ip = packet[IP].src

            # Track packet rates per IP
            self.traffic_stats[src_ip].append(current_time)

            # Remove old entries (older than baseline window)
            cutoff_time = current_time - timedelta(seconds=self.baseline_window)
            while self.traffic_stats[src_ip] and self.traffic_stats[src_ip][0] < cutoff_time:
                self.traffic_stats[src_ip].popleft()

            # Calculate packet rate
            if len(self.traffic_stats[src_ip]) > 10:  # Need some data
                time_span = (current_time - self.traffic_stats[src_ip][0]).total_seconds()
                if time_span > 0:
                    packet_rate = len(self.traffic_stats[src_ip]) / time_span

                    # Simple anomaly detection based on packet rate
                    if packet_rate > 10:  # More than 10 packets per second
                        alerts.append(f"High packet rate from {src_ip}: {packet_rate:.2f} pps")

            # Protocol analysis
            if packet.haslayer(TCP):
                self.protocol_stats['TCP'] += 1
            elif packet.haslayer(UDP):
                self.protocol_stats['UDP'] += 1

        return alerts

    def packet_handler(self, packet):
        """Main packet processing function"""
        try:
            # Detect AI traffic
            ai_alerts = self.detect_ai_traffic(packet)

            # Detect agent protocols (A2A, ACP, MCP)
            agent_alerts = self.detect_agent_protocols(packet)

            # Detect protocol signatures in payload
            signature_alerts = self.detect_protocol_signatures(packet)

            # Analyze encrypted traffic patterns
            encrypted_alerts = self.detect_encrypted_agent_traffic(packet)

            # Analyze general traffic patterns
            pattern_alerts = self.analyze_traffic_patterns(packet)

            # Process alerts
            all_alerts = ai_alerts + agent_alerts + signature_alerts + encrypted_alerts + pattern_alerts
            for alert in all_alerts:
                self.logger.warning(f"ALERT: {alert}")
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'alert': alert,
                    'packet_info': str(packet.summary())
                })

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        for interface_name, addresses in psutil.net_if_addrs().items():
            interfaces.append(interface_name)
        return interfaces

    def print_statistics(self):
        """Print current statistics"""
        print("\n" + "="*50)
        print("NETWORK MONITORING STATISTICS")
        print("="*50)

        print(f"Active IPs being monitored: {len(self.traffic_stats)}")
        print(f"Total alerts generated: {len(self.alerts)}")

        print("\nProtocol Distribution:")
        total_packets = sum(self.protocol_stats.values())
        for protocol, count in self.protocol_stats.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            print(f"  {protocol}: {count} ({percentage:.1f}%)")

        print(f"\nRecent DNS queries: {len(self.dns_queries)}")
        if self.dns_queries:
            recent_queries = list(self.dns_queries)[-5:]  # Last 5 queries
            for query in recent_queries:
                print(f"  {query['timestamp'].strftime('%H:%M:%S')} - {query['query']} from {query['src_ip']}")

        print(f"\nAgent Protocol Activity:")
        for protocol, sessions in self.protocol_sessions.items():
            if sessions > 0:
                print(f"  {protocol.upper()}: {sessions} sessions")
                recent_connections = [
                    conn for conn in self.agent_connections[protocol]
                    if (datetime.now() - conn['timestamp']).total_seconds() < 300  # Last 5 minutes
                ]
                if recent_connections:
                    print(f"    Recent connections: {len(recent_connections)}")

        print(f"\nEncrypted Traffic Analysis:")
        print(f"  Active encrypted flows: {len(self.encrypted_flows)}")

        # Show encryption pattern detections
        for pattern, count in self.encryption_patterns.items():
            if count > 0:
                pattern_name = pattern.replace('_', ' ').title()
                print(f"  {pattern_name}: {count} detections")

        # Show top encrypted flows by activity
        if self.encrypted_flows:
            flow_activity = [(flow_key, len(flow_data['packets'])) 
                           for flow_key, flow_data in self.encrypted_flows.items()]
            top_flows = sorted(flow_activity, key=lambda x: x[1], reverse=True)[:5]

            print(f"  Most active encrypted flows:")
            for flow_key, packet_count in top_flows:
                print(f"    {flow_key}: {packet_count} packets")

        print(f"\nSuspicious Pattern Detections:")
        for pattern, count in self.suspicious_patterns.items():
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count} detections")

        print(f"\nTop connection patterns:")
        top_connections = sorted(self.connection_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for conn, count in top_connections:
            print(f"  {conn}: {count} connections")

        if self.alerts:
            print(f"\nRecent alerts (last 5):")
            recent_alerts = self.alerts[-5:]
            for alert in recent_alerts:
                print(f"  {alert['timestamp'][:19]} - {alert['alert']}")

    def start_monitoring(self):
        """Start packet capture and monitoring"""
        self.running = True

        # Get available interfaces if none specified
        if not self.interface:
            interfaces = self.get_network_interfaces()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"  {i}: {iface}")

            try:
                choice = input("\nSelect interface number (or press Enter for all): ").strip()
                if choice.isdigit() and int(choice) < len(interfaces):
                    self.interface = interfaces[int(choice)]
                else:
                    self.interface = None  # Monitor all interfaces
            except KeyboardInterrupt:
                print("\nExiting...")
                return

        print(f"\nStarting network monitoring on interface: {self.interface or 'ALL'}")
        print("Press Ctrl+C to stop")

        # Start statistics reporting thread
        stats_thread = threading.Thread(target=self.periodic_stats)
        stats_thread.daemon = True
        stats_thread.start()

        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,  # Don't store packets in memory
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            self.running = False
            self.print_statistics()

            # Save alerts to file
            if self.alerts:
                with open('network_alerts.json', 'w') as f:
                    json.dump(self.alerts, f, indent=2)
                print(f"\nAlerts saved to network_alerts.json")

    def periodic_stats(self):
        """Periodically print statistics"""
        while self.running:
            time.sleep(30)  # Print stats every 30 seconds
            if self.running:
                self.print_statistics()

def main():
    print("Network Anomaly Detection and AI Agent Protocol Monitor")
    print("=" * 55)

    # Check if running with sufficient privileges
    try:
        # Test if we can create a raw socket (requires privileges)
        import socket
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("ERROR: This script requires elevated privileges.")
        print("Please run as administrator (Windows) or with sudo (Linux/Mac)")
        return
    except OSError:
        pass  # This is expected on some systems

    monitor = NetworkMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()