"""
monitor.py — NetworkMonitor: owns shared state, dispatches packets, reports.

Dependencies
------------
    scapy >= 2.4
    psutil >= 5.0
    Python >= 3.10
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path


from .config import AGENT_PROTOCOLS, ALERT_THRESHOLD, BASELINE_WINDOW
from .detectors import (
    analyze_traffic_patterns,
    detect_agent_protocols,
    detect_ai_traffic,
    detect_encrypted_agent_traffic,
    detect_protocol_signatures,
)


# ---------------------------------------------------------------------------
# Flow record factory
# ---------------------------------------------------------------------------

def _new_flow() -> dict:
    """Return a fresh, empty encrypted-flow record."""
    return {
        "packets":        [],
        "sizes":          [],
        "timing":         [],
        "entropy_scores": [],
        "tls_info":       {},
        "flow_patterns":  [],
    }


# ---------------------------------------------------------------------------
# NetworkMonitor
# ---------------------------------------------------------------------------

class NetworkMonitor:
    """
    Captures packets on a network interface and runs all detectors against
    each packet, accumulating alerts and statistics.

    Parameters
    ----------
    interface : str | None
        Network interface to capture on.  Pass ``None`` to prompt the user
        at start-up (default), or ``""`` to capture on all interfaces.
    """

    def __init__(self, interface: str | None = None) -> None:
        self.interface:       str | None = interface
        self.baseline_window: int        = BASELINE_WINDOW
        self.alert_threshold: float      = ALERT_THRESHOLD

        # ── Traffic tracking ─────────────────────────────────────────────
        self.traffic_stats:      defaultdict = defaultdict(lambda: deque(maxlen=100))
        self.connection_counts:  defaultdict = defaultdict(int)
        self.protocol_stats:     defaultdict = defaultdict(int)
        self.dns_queries:        deque       = deque(maxlen=1000)

        # ── Agent protocol tracking ──────────────────────────────────────
        self.agent_connections:   defaultdict = defaultdict(list)
        self.protocol_sessions:   defaultdict = defaultdict(int)
        self.suspicious_patterns: defaultdict = defaultdict(int)

        # ── Encrypted traffic tracking ───────────────────────────────────
        self.encrypted_flows:     defaultdict = defaultdict(_new_flow)
        self.flow_fingerprints:   defaultdict = defaultdict(list)
        self.encryption_patterns: defaultdict = defaultdict(int)

        self.alerts:  list[dict] = []
        self.running: bool       = False

        # ── Logging ──────────────────────────────────────────────────────
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("network_monitor.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Dispatch *packet* through every detector and record any alerts."""
        try:
            ai_alerts        = detect_ai_traffic(
                packet, self.dns_queries, self.connection_counts, AGENT_PROTOCOLS
            )
            agent_alerts     = detect_agent_protocols(
                packet, self.agent_connections, self.protocol_sessions, self.suspicious_patterns
            )
            signature_alerts = detect_protocol_signatures(packet, self.suspicious_patterns)
            encrypted_alerts = detect_encrypted_agent_traffic(
                packet, self.encrypted_flows, self.encryption_patterns
            )
            pattern_alerts   = analyze_traffic_patterns(
                packet, self.traffic_stats, self.protocol_stats
            )

            for alert in (
                ai_alerts + agent_alerts + signature_alerts +
                encrypted_alerts + pattern_alerts
            ):
                self.logger.warning("ALERT: %s", alert)
                self.alerts.append({
                    "timestamp":   datetime.now().isoformat(),
                    "alert":       alert,
                    "packet_info": str(packet.summary()),
                })

        except Exception as exc:  # noqa: BLE001
            self.logger.error("Error processing packet: %s", exc)

    # ------------------------------------------------------------------
    # Statistics / reporting
    # ------------------------------------------------------------------

    def print_statistics(self) -> None:
        """Print a formatted summary of current monitoring state to stdout."""
        print("\n" + "=" * 50)
        print("NETWORK MONITORING STATISTICS")
        print("=" * 50)

        print(f"Active IPs being monitored: {len(self.traffic_stats)}")
        print(f"Total alerts generated:     {len(self.alerts)}")

        print("\nProtocol Distribution:")
        total_packets = sum(self.protocol_stats.values())
        for protocol, count in self.protocol_stats.items():
            pct = (count / total_packets * 100) if total_packets > 0 else 0.0
            print(f"  {protocol}: {count} ({pct:.1f}%)")

        print(f"\nRecent DNS queries: {len(self.dns_queries)}")
        if self.dns_queries:
            for q in list(self.dns_queries)[-5:]:
                print(
                    f"  {q['timestamp'].strftime('%H:%M:%S')} - "
                    f"{q['query']} from {q['src_ip']}"
                )

        print("\nAgent Protocol Activity:")
        for protocol, sessions in self.protocol_sessions.items():
            if sessions > 0:
                print(f"  {protocol.upper()}: {sessions} sessions")
                recent = [
                    c for c in self.agent_connections[protocol]
                    if (datetime.now() - c["timestamp"]).total_seconds() < 300
                ]
                if recent:
                    print(f"    Recent connections: {len(recent)}")

        print(f"\nEncrypted Traffic Analysis:")
        print(f"  Active encrypted flows: {len(self.encrypted_flows)}")
        for pattern, count in self.encryption_patterns.items():
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count} detections")

        if self.encrypted_flows:
            top_flows = sorted(
                ((k, len(v["packets"])) for k, v in self.encrypted_flows.items()),
                key=lambda x: x[1],
                reverse=True,
            )[:5]
            print("  Most active encrypted flows:")
            for flow_key, pkt_count in top_flows:
                print(f"    {flow_key}: {pkt_count} packets")

        print("\nSuspicious Pattern Detections:")
        for pattern, count in self.suspicious_patterns.items():
            if count > 0:
                print(f"  {pattern.replace('_', ' ').title()}: {count} detections")

        print("\nTop connection patterns:")
        top_conns = sorted(
            self.connection_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        for conn, count in top_conns:
            print(f"  {conn}: {count} connections")

        if self.alerts:
            print("\nRecent alerts (last 5):")
            for alert in self.alerts[-5:]:
                print(f"  {alert['timestamp'][:19]} - {alert['alert']}")

    def periodic_stats(self) -> None:
        """Background thread target: print statistics every 30 seconds."""
        while self.running:
            time.sleep(30)
            if self.running:
                self.print_statistics()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def get_network_interfaces(self) -> list[str]:
        """Return the names of all available network interfaces."""
        try:
            import psutil
        except ImportError as exc:
            raise ImportError(
                "psutil is required to list network interfaces.\n"
                "Install with: pip install psutil"
            ) from exc
        return list(psutil.net_if_addrs().keys())

    def start_monitoring(self) -> None:
        """
        Select a network interface (interactively if needed) and begin
        packet capture.  Blocks until Ctrl-C; saves alerts on exit.
        """
        self.running = True

        if self.interface is None:
            interfaces = self.get_network_interfaces()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"  {i}: {iface}")

            try:
                choice = input("\nSelect interface number (or press Enter for all): ").strip()
                self.interface = (
                    interfaces[int(choice)]
                    if choice.isdigit() and int(choice) < len(interfaces)
                    else None
                )
            except KeyboardInterrupt:
                print("\nExiting...")
                return

        print(f"\nStarting network monitoring on interface: {self.interface or 'ALL'}")
        print("Press Ctrl+C to stop")

        stats_thread = threading.Thread(target=self.periodic_stats, daemon=True)
        stats_thread.start()

        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise ImportError(
                "scapy is required for packet capture.\n"
                "Install with: pip install scapy"
            ) from exc

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            self.running = False
            self.print_statistics()
            self._save_alerts()

    def _save_alerts(self, path: str = "network_alerts.json") -> None:
        """Write accumulated alerts to a JSON file."""
        if not self.alerts:
            return
        Path(path).write_text(
            json.dumps(self.alerts, indent=2),
            encoding="utf-8",
        )
        print(f"\nAlerts saved to {path}")
