#!/usr/bin/env python3
"""
main.py — Entry point for the Network Anomaly Detection and AI Agent Protocol Monitor.

Usage:
    sudo python main.py

Requires: pip install scapy psutil requests scipy numpy
Run with elevated privileges (sudo on Linux/Mac, admin on Windows).
"""

import socket

from network_anomaly_monitor.monitor import NetworkMonitor


def check_privileges():
    """Verify the process has sufficient privileges for raw-socket capture."""
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("ERROR: This script requires elevated privileges.")
        print("Please run as administrator (Windows) or with sudo (Linux/Mac)")
        return False
    except OSError:
        pass  # Expected on some systems
    return True


def main():
    print("Network Anomaly Detection and AI Agent Protocol Monitor")
    print("=" * 55)

    if not check_privileges():
        return

    monitor = NetworkMonitor()
    monitor.start_monitoring()


if __name__ == "__main__":
    main()
