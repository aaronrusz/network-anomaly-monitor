# network-anomaly-monitor

This project is a Python-based tool for monitoring network traffic, detecting anomalies, and analyzing AI agent communication patterns. It leverages packet sniffing, statistical analysis, and system metrics to provide insights into unusual activity on a host or network.

## Features

* **Real-time packet sniffing** using [Scapy](https://scapy.net/).
* **Protocol support** for IP, TCP, UDP, DNS, and optional TLS fingerprinting.
* **System monitoring** via [psutil](https://pypi.org/project/psutil/) (CPU, memory, process usage).
* **Anomaly detection** using statistical methods (`numpy`, `scipy`, rolling averages, z-scores).
* **AI agent communication analysis** (pattern matching, protocol behaviors).
* **Logging and alerting** for suspicious activity.
* **Extensible design** with modular components for traffic analysis and anomaly detection.

## Requirements

* Python 3.8+
* Dependencies:

  ```bash
  pip install scapy psutil requests scipy numpy
  ```
* Optional:

  * TLS support (requires compatible `scapy` version with `scapy.layers.tls`).

## Usage

> ⚠️ **Note:** This program requires elevated privileges (e.g., `sudo` on Linux/Mac or administrator rights on Windows) to capture network traffic.

Run the monitor with stealth mode disabled (default):

```bash
sudo python3 network_anomaly_monitor.py
```

Run the monitor with stealth mode enabled:

```bash
sudo python3 network_anomaly_monitor.py --stealth
```

The script will:

* Capture live packets.
* Analyze traffic patterns.
* Detect anomalies based on statistical thresholds.
* Log alerts for suspicious or unusual network behavior.

## Configuration

* Logging behavior can be adjusted in the script via the `logging` module.
* Detection thresholds and statistical methods can be tuned in the anomaly detection functions.
* Certain protocol-specific checks (DNS, TLS, AI agent fingerprints) can be enabled/disabled as needed.

## Example Output

* **Alerts** for high-volume traffic spikes.
* **Warnings** for unusual port usage or rare protocol combinations.
* **TLS/DNS fingerprinting results** when available.

## Limitations

* TLS fingerprinting is only partially supported depending on your `scapy` version.
* Heavy traffic environments may require performance tuning (threading, buffer sizes).
* Anomalies are based on heuristic/statistical models; false positives/negatives are possible.

## Roadmap / Possible Improvements

* Machine learning–based anomaly classification.
* Integration with SIEM/logging tools.
* Remote alerting via webhooks (Slack, Discord, email).
* Visualization dashboard for real-time monitoring.

## License

This project is licensed under the **GNU Affero General Public License (AGPL)**. See the `LICENSE` file for details.
