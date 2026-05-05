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
* Dependencies (install system-wide for sudo compatibility):

  ```bash
  sudo pip3 install scapy psutil requests scipy numpy
  ```
  
  > **Important:** Install packages system-wide with `sudo pip3` rather than `pip3` to ensure they are available when running the script with elevated privileges.

* Optional:

  * TLS support (requires compatible `scapy` version with `scapy.layers.tls`).

## Usage

> ⚠️ **Note:** This program requires elevated privileges (e.g., `sudo` on Linux/Mac or administrator rights on Windows) to capture network traffic.

### Interactive Mode

Run the monitor in interactive mode (recommended for initial setup and monitoring):

```bash
sudo python3 network_anomaly_monitor.py
```

The script will:

* Display available network interfaces and prompt for selection
* Capture live packets on the selected interface
* Analyze traffic patterns in real-time
* Detect anomalies based on statistical thresholds
* Log alerts for suspicious or unusual network behavior
* Print periodic statistics every 30 seconds

### Unattended Operation Mode

For automated, background monitoring without user interaction:

#### Suppress Console Output
Run without printing statistics or status messages:

```bash
sudo python3 network_anomaly_monitor.py --quiet --interface eth0
```

#### Disable File Logging
Prevent creation of log files:

```bash
sudo python3 network_anomaly_monitor.py --no-log --interface eth0
```

#### Custom Log File Location
Specify a different log file path:

```bash
sudo python3 network_anomaly_monitor.py --log-file /var/log/network_monitor.log --interface eth0
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
