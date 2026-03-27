#!/usr/bin/env python3
"""
main.py — Entry point for the Network Anomaly Detection and AI Agent Protocol Monitor.

Usage
-----
    sudo python main.py            # Linux / macOS
    python main.py                 # Windows (run as Administrator)

Requirements
------------
    pip install scapy psutil

Elevated privileges are required for raw-socket packet capture.
"""

from __future__ import annotations

import socket
import sys

# Guard: require Python 3.10+ (union type syntax used throughout the package)
if sys.version_info < (3, 10):
    sys.exit(
        f"Python 3.10 or later is required (running {sys.version_info.major}"
        f".{sys.version_info.minor})."
    )

from network_anomaly_monitor.monitor import NetworkMonitor


def check_privileges() -> bool:
    """
    Return True if the process has sufficient privileges for raw-socket capture.

    On Linux/macOS this requires root / sudo.
    On Windows this requires running as Administrator.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.close()
    except PermissionError:
        print("ERROR: This script requires elevated privileges.")
        print("  Linux / macOS : sudo python main.py")
        print("  Windows       : run as Administrator")
        return False
    except OSError:
        pass  # Some platforms raise OSError for unrelated reasons — continue.
    return True


def main() -> None:
    print("Network Anomaly Detection and AI Agent Protocol Monitor")
    print("=" * 55)

    if not check_privileges():
        sys.exit(1)

    monitor = NetworkMonitor()
    monitor.start_monitoring()


if __name__ == "__main__":
    main()
