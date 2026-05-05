# network-anomaly-monitor

This project is a Python-based tool for monitoring network traffic, detecting anomalies, and analyzing AI agent communication patterns. It leverages packet sniffing, statistical analysis, and system metrics to provide insights into unusual activity on a host or network.

## Features

* **Real-time packet sniffing** using [Scapy](https://scapy.net/).
* **Protocol support** for IP, TCP, UDP, DNS, and optional TLS fingerprinting.
* **System monitoring** via [psutil](https://pypi.org/project/psutil/) (CPU, memory, process usage).
* **Anomaly detection** using statistical methods (`numpy`, `scipy`, rolling averages, z-scores).
* **AI agent communication analysis** (pattern matching, protocol behaviors).
* **Logging and alerting** for suspicious activity.
* **Unattended operation mode** options for automated operation (suppress output, disable logging, daemon mode).
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

### Basic Usage

Run the monitor in interactive mode:

```bash
sudo python3 network_anomaly_monitor.py
```

The script will:

* Capture live packets.
* Analyze traffic patterns.
* Detect anomalies based on statistical thresholds.
* Log alerts for suspicious or unusual network behavior.

### Unattended Operation Mode Options

The script supports various unattended operation options for automated monitoring:

#### Suppress Console Output
Run without printing statistics or status messages:

```bash
sudo python3 network_anomaly_monitor.py --quiet
```

#### Disable File Logging
Prevent creation of log files:

```bash
sudo python3 network_anomaly_monitor.py --no-log
```

#### Custom Log File Location
Specify a different log file path:

```bash
sudo python3 network_anomaly_monitor.py --log-file /path/to/custom.log
```

#### Daemon Mode
Run as a background process (detached from terminal):

```bash
sudo python3 network_anomaly_monitor.py --daemon --interface eth0
```

> **Note:** When using `--daemon`, you must specify an interface with `--interface` since interactive prompts won't work in background mode.

#### Specify Network Interface
Bypass the interactive interface selection:

```bash
sudo python3 network_anomaly_monitor.py --interface wlan0
```

#### Combined Unattended Operation Mode
For full unattended operation, combine options:

```bash
sudo python3 network_anomaly_monitor.py --quiet --no-log --daemon --interface eth0
```

This runs the monitor completely silently in the background, with no console output, no log files, and no interactive prompts.

### Command-Line Options

* `--quiet`: Suppress all console output
* `--no-log`: Disable logging to files
* `--log-file PATH`: Specify custom log file path (default: `network_monitor.log`)
* `--daemon`: Run as background daemon process
* `--interface NAME`: Specify network interface to monitor

## Configuration

* Logging behavior can be adjusted via command-line options or in the script via the `logging` module.
* Detection thresholds and statistical methods can be tuned in the anomaly detection functions.
* Certain protocol-specific checks (DNS, TLS, AI agent fingerprints) can be enabled/disabled as needed.

## Example Output

When not in quiet mode, the script displays:

* **Alerts** for high-volume traffic spikes.
* **Warnings** for unusual port usage or rare protocol combinations.
* **TLS/DNS fingerprinting results** when available.
* **Periodic statistics** every 30 seconds showing protocol distributions, active connections, and anomaly detections.

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
