"""
monitor.py — NetworkMonitor class: state management, packet dispatch, and reporting.
"""

import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff
    import psutil
except ImportError as e:
    raise ImportError(f"Required package missing: {e}") from e

from .detectors import (
    detect_ai_traffic,
    detect_agent_protocols,
    detect_protocol_signatures,
    detect_encrypted_agent_traffic,
    analyze_traffic_patterns,
)
from .config import AGENT_PROTOCOLS, BASELINE_WINDOW, ALERT_THRESHOLD


def _make_encrypted_flow():
    return {
        'packets':        [],
        'sizes':          [],
        'timing':         [],
        'entropy_scores': [],
        'tls_info':       {},
        'flow_patterns':  [],
    }


class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface       = interface
        self.baseline_window = BASELINE_WINDOW
        self.alert_threshold = ALERT_THRESHOLD

        # Traffic tracking
        self.traffic_stats     = defaultdict(lambda: deque(maxlen=100))
        self.connection_counts = defaultdict(int)
        self.protocol_stats    = defaultdict(int)
        self.dns_queries       = deque(maxlen=1000)

        # Protocol-specific tracking
        self.agent_connections  = defaultdict(list)
        self.protocol_sessions  = defaultdict(int)
        self.suspicious_patterns = defaultdict(int)

        # Encrypted-traffic tracking
        self.encrypted_flows     = defaultdict(_make_encrypted_flow)
        self.flow_fingerprints   = defaultdict(list)
        self.encryption_patterns = defaultdict(int)

        self.alerts  = []
        self.running = False

        # Logging setup
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_monitor.log'),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------

    def packet_handler(self, packet):
        """Dispatch a captured packet through all detectors."""
        try:
            ai_alerts = detect_ai_traffic(
                packet, self.dns_queries, self.connection_counts, AGENT_PROTOCOLS
            )
            agent_alerts = detect_agent_protocols(
                packet, self.agent_connections, self.protocol_sessions, self.suspicious_patterns
            )
            signature_alerts = detect_protocol_signatures(packet, self.suspicious_patterns)
            encrypted_alerts = detect_encrypted_agent_traffic(
                packet, self.encrypted_flows, self.encryption_patterns
            )
            pattern_alerts = analyze_traffic_patterns(
                packet, self.traffic_stats, self.protocol_stats
            )

            all_alerts = (
                ai_alerts + agent_alerts + signature_alerts +
                encrypted_alerts + pattern_alerts
            )

            for alert in all_alerts:
                self.logger.warning(f"ALERT: {alert}")
                self.alerts.append({
                    'timestamp':   datetime.now().isoformat(),
                    'alert':       alert,
                    'packet_info': str(packet.summary()),
                })

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    # ------------------------------------------------------------------
    # Statistics / reporting
    # ------------------------------------------------------------------

    def print_statistics(self):
        """Print a summary of current monitoring statistics to stdout."""
        print("\n" + "=" * 50)
        print("NETWORK MONITORING STATISTICS")
        print("=" * 50)

        print(f"Active IPs being monitored: {len(self.traffic_stats)}")
        print(f"Total alerts generated:     {len(self.alerts)}")

        print("\nProtocol Distribution:")
        total_packets = sum(self.protocol_stats.values())
        for protocol, count in self.protocol_stats.items():
            pct = (count / total_packets * 100) if total_packets > 0 else 0
            print(f"  {protocol}: {count} ({pct:.1f}%)")

        print(f"\nRecent DNS queries: {len(self.dns_queries)}")
        if self.dns_queries:
            for q in list(self.dns_queries)[-5:]:
                print(f"  {q['timestamp'].strftime('%H:%M:%S')} - {q['query']} from {q['src_ip']}")

        print("\nAgent Protocol Activity:")
        for protocol, sessions in self.protocol_sessions.items():
            if sessions > 0:
                print(f"  {protocol.upper()}: {sessions} sessions")
                recent = [
                    c for c in self.agent_connections[protocol]
                    if (datetime.now() - c['timestamp']).total_seconds() < 300
                ]
                if recent:
                    print(f"    Recent connections: {len(recent)}")

        print(f"\nEncrypted Traffic Analysis:")
        print(f"  Active encrypted flows: {len(self.encrypted_flows)}")
        for pattern, count in self.encryption_patterns.items():
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count} detections")

        if self.encrypted_flows:
            flow_activity = [
                (fk, len(fd['packets'])) for fk, fd in self.encrypted_flows.items()
            ]
            top_flows = sorted(flow_activity, key=lambda x: x[1], reverse=True)[:5]
            print("  Most active encrypted flows:")
            for flow_key, pkt_count in top_flows:
                print(f"    {flow_key}: {pkt_count} packets")

        print("\nSuspicious Pattern Detections:")
        for pattern, count in self.suspicious_patterns.items():
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count} detections")

        print("\nTop connection patterns:")
        top_connections = sorted(
            self.connection_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        for conn, count in top_connections:
            print(f"  {conn}: {count} connections")

        if self.alerts:
            print("\nRecent alerts (last 5):")
            for alert in self.alerts[-5:]:
                print(f"  {alert['timestamp'][:19]} - {alert['alert']}")

    def periodic_stats(self):
        """Background thread: print statistics every 30 seconds."""
        while self.running:
            time.sleep(30)
            if self.running:
                self.print_statistics()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def get_network_interfaces(self):
        """Return a list of available network interface names."""
        return list(psutil.net_if_addrs().keys())

    def start_monitoring(self):
        """Prompt for interface selection, then start packet capture."""
        self.running = True

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

        stats_thread = threading.Thread(target=self.periodic_stats)
        stats_thread.daemon = True
        stats_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda x: not self.running,
            )
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            self.running = False
            self.print_statistics()

            if self.alerts:
                with open('network_alerts.json', 'w') as f:
                    json.dump(self.alerts, f, indent=2)
                print("\nAlerts saved to network_alerts.json")
