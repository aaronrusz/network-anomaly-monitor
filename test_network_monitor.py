#!/usr/bin/env python3
"""
Functional test suite for the modular network_anomaly_monitor package.

All scapy / psutil / scipy / numpy / requests imports are mocked so the
tests run without any third-party packages installed.

Run with:  python3 test_network_monitor.py
"""

import sys
import math
import types
import unittest
from collections import defaultdict, deque
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# ─────────────────────────────────────────────────────────────────────────────
# 1. Build stub modules for every external dependency
# ─────────────────────────────────────────────────────────────────────────────

def _make_module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

# ── scapy top-level ──────────────────────────────────────────────────────────
scapy_mod        = _make_module("scapy")
scapy_all        = _make_module("scapy.all")
scapy_layers     = _make_module("scapy.layers")
scapy_layers_tls = _make_module("scapy.layers.tls")

class _Layer:
    """Minimal scapy layer stand-in."""
    pass

class _IP(_Layer):
    src = "1.2.3.4"
    dst = "5.6.7.8"

class _TCP(_Layer):
    sport = 12345
    dport = 80
    payload = b""

class _UDP(_Layer):
    sport = 54321
    dport = 53

class _DNS(_Layer):
    qr = 0
    class _QD:
        qname = b"api.openai.com."
    qd = _QD()

class _Raw(_Layer):
    load = b""

    def __bytes__(self):
        return self.load if isinstance(self.load, bytes) else self.load.encode()

class _TLS(_Layer):
    version = 0x0303
    msg = None

# Expose layer classes on the stub modules
for attr in ("IP", "TCP", "UDP", "DNS", "Raw", "sniff"):
    setattr(scapy_all, attr, globals().get(f"_{attr}", MagicMock()))
scapy_all.sniff = MagicMock()
scapy_layers_tls.TLS = _TLS

# ── psutil ───────────────────────────────────────────────────────────────────
psutil_mod = _make_module("psutil")
psutil_mod.net_if_addrs = lambda: {"eth0": [], "lo": []}

# ── scipy / numpy / requests ─────────────────────────────────────────────────
scipy_mod  = _make_module("scipy")
stats_mod  = _make_module("scipy.stats")
numpy_mod  = _make_module("numpy")
req_mod    = _make_module("requests")

scipy_mod.stats = stats_mod


# ─────────────────────────────────────────────────────────────────────────────
# 2. Packet factory helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_packet(layers):
    """
    Return a minimal fake packet that responds to haslayer() / __getitem__()
    based on the dict {LayerClass: instance} passed in.
    """
    class FakePacket:
        def __init__(self, layer_map):
            self._layers = layer_map

        def haslayer(self, cls):
            return cls in self._layers

        def __getitem__(self, cls):
            return self._layers[cls]

        def summary(self):
            return "FakePacket"

        def __len__(self):
            return sum(
                len(getattr(v, "load", b"") or b"")
                for v in self._layers.values()
            ) or 64  # default 64 bytes

    return FakePacket(layers)


def _ip(src="1.2.3.4", dst="5.6.7.8"):
    ip = _IP(); ip.src = src; ip.dst = dst
    return ip

def _tcp(sport=12345, dport=80, payload=b""):
    t = _TCP(); t.sport = sport; t.dport = dport; t.payload = payload
    return t

def _udp(sport=54321, dport=53):
    u = _UDP(); u.sport = sport; u.dport = dport
    return u

def _dns(qname=b"api.openai.com."):
    d = _DNS()
    d.qr = 0
    d.qd = type("QD", (), {"qname": qname})()
    return d

def _raw(load=b""):
    r = _Raw(); r.load = load
    return r


IP  = _IP
TCP = _TCP
UDP = _UDP
DNS = _DNS
Raw = _Raw
TLS = _TLS


# ─────────────────────────────────────────────────────────────────────────────
# 3. Now import the package under test
# ─────────────────────────────────────────────────────────────────────────────
sys.path.insert(0, "/home/claude/nam_v2")

# Patch TLS_AVAILABLE so TLS branch is exercised
import importlib

# Import config and crypto_utils first (no scapy dependency at parse time)
from network_anomaly_monitor import config
from network_anomaly_monitor import crypto_utils
from network_anomaly_monitor import detectors
from network_anomaly_monitor import monitor

# Monkey-patch the layer references inside detectors to point at our stubs
detectors.IP  = _IP
detectors.TCP = _TCP
detectors.UDP = _UDP
detectors.DNS = _DNS
detectors.Raw = _Raw
detectors.TLS = _TLS
detectors.TLS_AVAILABLE = True

monitor.NetworkMonitor  # just ensure it imported OK


# ─────────────────────────────────────────────────────────────────────────────
# 4. Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig(unittest.TestCase):
    """config.py — verify all expected keys/values exist."""

    def test_ai_protocols_keys(self):
        expected = {"openai", "anthropic", "google_ai", "azure_openai",
                    "huggingface", "ollama", "langchain", "replicate",
                    "cohere", "stability"}
        self.assertEqual(set(config.AI_PROTOCOLS.keys()), expected)

    def test_agent_protocols_keys(self):
        self.assertIn("a2a", config.AGENT_PROTOCOLS)
        self.assertIn("acp", config.AGENT_PROTOCOLS)
        self.assertIn("mcp", config.AGENT_PROTOCOLS)

    def test_agent_protocol_structure(self):
        for name, cfg in config.AGENT_PROTOCOLS.items():
            with self.subTest(protocol=name):
                self.assertIn("ports",         cfg)
                self.assertIn("patterns",      cfg)
                self.assertIn("content_types", cfg)
                self.assertIsInstance(cfg["ports"], list)

    def test_thresholds(self):
        self.assertEqual(config.BASELINE_WINDOW, 300)
        self.assertEqual(config.ALERT_THRESHOLD, 2.0)

    def test_ai_standard_ports(self):
        for port in (80, 443, 8080, 11434):
            self.assertIn(port, config.AI_STANDARD_PORTS)

    def test_coordination_keywords_non_empty(self):
        self.assertTrue(len(config.COORDINATION_KEYWORDS) > 0)

    def test_json_rpc_patterns_non_empty(self):
        self.assertTrue(len(config.JSON_RPC_AGENT_PATTERNS) > 0)


class TestCryptoUtils(unittest.TestCase):
    """crypto_utils.py — entropy and chi-square helpers."""

    def test_entropy_empty(self):
        self.assertEqual(crypto_utils.calculate_entropy(b""), 0)

    def test_entropy_uniform(self):
        # A single repeated byte has entropy 0
        self.assertAlmostEqual(crypto_utils.calculate_entropy(b"\x00" * 100), 0.0)

    def test_entropy_two_values(self):
        # 50/50 split → entropy = 1.0 bit
        data = bytes([0] * 50 + [1] * 50)
        self.assertAlmostEqual(crypto_utils.calculate_entropy(data), 1.0, places=5)

    def test_entropy_high_for_random_like(self):
        # All 256 byte values once → max entropy = 8 bits
        data = bytes(range(256))
        e = crypto_utils.calculate_entropy(data)
        self.assertAlmostEqual(e, 8.0, places=5)

    def test_entropy_string_input(self):
        # Should accept a str without raising
        e = crypto_utils.calculate_entropy("hello world")
        self.assertGreater(e, 0)

    def test_chi_square_uniform(self):
        # Perfectly uniform → chi-square ≈ 0
        data = bytes(list(range(256)) * 4)   # 1024 bytes, perfectly uniform
        chi = crypto_utils.chi_square_uniformity(data)
        self.assertAlmostEqual(chi, 0.0, places=5)

    def test_chi_square_skewed(self):
        # All same byte → maximum skew → very large chi-square
        data = b"\x00" * 1000
        chi = crypto_utils.chi_square_uniformity(data)
        self.assertGreater(chi, 300)


class TestDetectAiTraffic(unittest.TestCase):
    """detectors.detect_ai_traffic()"""

    def _run(self, packet):
        dns_queries       = deque(maxlen=1000)
        connection_counts = defaultdict(int)
        return (
            detectors.detect_ai_traffic(
                packet, dns_queries, connection_counts, config.AGENT_PROTOCOLS
            ),
            dns_queries,
            connection_counts,
        )

    def test_no_ip_layer_returns_empty(self):
        pkt = _make_packet({})
        alerts, _, _ = self._run(pkt)
        self.assertEqual(alerts, [])

    def test_dns_query_for_openai_raises_alert(self):
        pkt = _make_packet({
            _IP: _ip(),
            _DNS: _dns(b"api.openai.com."),
        })
        alerts, dns_q, _ = self._run(pkt)
        self.assertTrue(any("openai" in a.lower() for a in alerts))
        self.assertEqual(len(dns_q), 1)
        self.assertEqual(dns_q[0]["query"], "api.openai.com")

    def test_dns_query_for_anthropic_raises_alert(self):
        pkt = _make_packet({
            _IP: _ip(),
            _DNS: _dns(b"api.anthropic.com."),
        })
        alerts, _, _ = self._run(pkt)
        self.assertTrue(any("anthropic" in a.lower() for a in alerts))

    def test_dns_query_for_unknown_domain_no_alert(self):
        pkt = _make_packet({
            _IP: _ip(),
            _DNS: _dns(b"example.com."),
        })
        alerts, _, _ = self._run(pkt)
        self.assertEqual(alerts, [])

    def test_high_frequency_tcp_connection_alert(self):
        dns_q   = deque(maxlen=1000)
        cc      = defaultdict(int)
        ip      = _ip(src="1.1.1.1", dst="2.2.2.2")
        tcp     = _tcp(dport=443)
        pkt     = _make_packet({_IP: ip, _TCP: tcp})
        # Pre-seed count to just below threshold
        cc["1.1.1.1:2.2.2.2:443"] = 50
        alerts = detectors.detect_ai_traffic(pkt, dns_q, cc, config.AGENT_PROTOCOLS)
        self.assertTrue(any("High frequency" in a for a in alerts))

    def test_non_monitored_port_no_alert(self):
        dns_q = deque(maxlen=1000)
        cc    = defaultdict(int)
        pkt   = _make_packet({_IP: _ip(), _TCP: _tcp(dport=9999)})
        # 9999 is an ACP port — let's use a truly unmonitored one
        tcp = _tcp(dport=22)
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        alerts = detectors.detect_ai_traffic(pkt, dns_q, cc, config.AGENT_PROTOCOLS)
        self.assertEqual(alerts, [])


class TestDetectAgentProtocols(unittest.TestCase):
    """detectors.detect_agent_protocols()"""

    def _state(self):
        return defaultdict(list), defaultdict(int), defaultdict(int)

    def test_no_ip_tcp_returns_empty(self):
        pkt = _make_packet({})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertEqual(alerts, [])

    def test_a2a_port_detected(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertTrue(any("A2A" in a for a in alerts))
        self.assertEqual(ps["a2a"], 1)

    def test_acp_port_detected(self):
        acp_port = config.AGENT_PROTOCOLS["acp"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=acp_port)})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertTrue(any("ACP" in a for a in alerts))

    def test_mcp_port_detected(self):
        mcp_port = config.AGENT_PROTOCOLS["mcp"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=mcp_port)})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertTrue(any("MCP" in a for a in alerts))

    def test_agent_mesh_detection(self):
        # src and dst ports are both agent ports → mesh alert
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        mcp_port = config.AGENT_PROTOCOLS["mcp"]["ports"][0]
        tcp = _tcp(sport=a2a_port, dport=mcp_port)
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertTrue(any("Agent-to-Agent" in a for a in alerts))
        self.assertEqual(sp["agent_mesh"], 1)

    def test_swarm_activity_detection(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        ac, ps, sp = self._state()
        # Pre-seed 21 recent connections for 'a2a'
        now = datetime.now()
        ac["a2a"] = [{"timestamp": now, "connection": f"x:y:{i}", "direction": "outbound"}
                     for i in range(21)]
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertTrue(any("Swarm" in a for a in alerts))
        self.assertEqual(sp["swarm_activity"], 1)

    def test_session_counter_increments(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        ac, ps, sp = self._state()
        detectors.detect_agent_protocols(pkt, ac, ps, sp)
        detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertEqual(ps["a2a"], 2)

    def test_non_agent_port_no_alert(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=22)})
        ac, ps, sp = self._state()
        alerts = detectors.detect_agent_protocols(pkt, ac, ps, sp)
        self.assertEqual(alerts, [])


class TestDetectProtocolSignatures(unittest.TestCase):
    """detectors.detect_protocol_signatures()"""

    def test_no_tcp_layer_returns_empty(self):
        pkt = _make_packet({})
        sp = defaultdict(int)
        self.assertEqual(detectors.detect_protocol_signatures(pkt, sp), [])

    def test_a2a_url_pattern_detected(self):
        tcp = _tcp(payload="/agents/communicate")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        self.assertTrue(any("A2A" in a for a in alerts))
        self.assertGreaterEqual(sp["a2a_pattern"], 1)

    def test_mcp_url_pattern_detected(self):
        tcp = _tcp(payload="/mcp/context-protocol")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        self.assertTrue(any("MCP" in a for a in alerts))

    def test_json_rpc_agent_method_detected(self):
        payload = b'{"method": "agent.run", "params": {}}'
        tcp = _tcp(payload=payload)
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        self.assertTrue(any("JSON-RPC" in a for a in alerts))
        self.assertGreater(sp["json_rpc_agent"], 0)

    def test_coordination_keyword_detected(self):
        tcp = _tcp(payload="task_delegation request incoming")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        self.assertTrue(any("Coordination" in a for a in alerts))
        self.assertEqual(sp["coordination"], 1)

    def test_only_one_coordination_alert_per_packet(self):
        # Two keywords in same payload → only one alert (break after first)
        tcp = _tcp(payload="task_delegation agent_handoff")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        coord_alerts = [a for a in alerts if "Coordination" in a]
        self.assertEqual(len(coord_alerts), 1)

    def test_benign_payload_no_alert(self):
        tcp = _tcp(payload="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        sp = defaultdict(int)
        alerts = detectors.detect_protocol_signatures(pkt, sp)
        self.assertEqual(alerts, [])


class TestAnalyzeTrafficPatterns(unittest.TestCase):
    """detectors.analyze_traffic_patterns()"""

    def test_no_ip_returns_empty(self):
        pkt = _make_packet({})
        ts = defaultdict(lambda: deque(maxlen=100))
        ps = defaultdict(int)
        self.assertEqual(detectors.analyze_traffic_patterns(pkt, ts, ps), [])

    def test_tcp_increments_protocol_stats(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ts = defaultdict(lambda: deque(maxlen=100))
        ps = defaultdict(int)
        detectors.analyze_traffic_patterns(pkt, ts, ps)
        self.assertEqual(ps["TCP"], 1)

    def test_udp_increments_protocol_stats(self):
        pkt = _make_packet({_IP: _ip(), _UDP: _udp()})
        ts = defaultdict(lambda: deque(maxlen=100))
        ps = defaultdict(int)
        detectors.analyze_traffic_patterns(pkt, ts, ps)
        self.assertEqual(ps["UDP"], 1)

    def test_high_packet_rate_alert(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ts = defaultdict(lambda: deque(maxlen=100))
        ps = defaultdict(int)
        ip_key = "1.2.3.4"
        # Insert 50 timestamps spanning 2 seconds → 25 pps > threshold (10)
        base = datetime.now() - timedelta(seconds=2)
        ts[ip_key] = deque(
            [base + timedelta(milliseconds=40 * i) for i in range(50)],
            maxlen=100
        )
        alerts = detectors.analyze_traffic_patterns(pkt, ts, ps)
        self.assertTrue(any("High packet rate" in a for a in alerts))

    def test_old_entries_evicted(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ts = defaultdict(lambda: deque(maxlen=100))
        ps = defaultdict(int)
        # Insert an entry older than BASELINE_WINDOW
        old = datetime.now() - timedelta(seconds=config.BASELINE_WINDOW + 10)
        ts["1.2.3.4"].append(old)
        detectors.analyze_traffic_patterns(pkt, ts, ps)
        # The old entry should have been evicted; only the new one remains
        self.assertEqual(len(ts["1.2.3.4"]), 1)
        self.assertGreater(ts["1.2.3.4"][0], old)


class TestAnalyzePacketTiming(unittest.TestCase):
    """detectors.analyze_packet_timing()"""

    def _flows(self):
        return defaultdict(lambda: {
            "packets": [], "sizes": [], "timing": [],
            "entropy_scores": [], "tls_info": {}, "flow_patterns": []
        })

    def test_returns_none_with_few_samples(self):
        flows = self._flows()
        result = detectors.analyze_packet_timing("k", datetime.now(), flows)
        self.assertIsNone(result)

    def test_regular_interval_triggers_alert(self):
        flows = self._flows()
        base = datetime.now()
        # Insert 15 timestamps exactly 1 second apart (std ≈ 0)
        for i in range(15):
            detectors.analyze_packet_timing("k", base + timedelta(seconds=i), flows)
        result = detectors.analyze_packet_timing("k", base + timedelta(seconds=15), flows)
        self.assertIsNotNone(result)
        self.assertIn("Regular", result)

    def test_irregular_interval_no_alert(self):
        flows = self._flows()
        base = datetime.now()
        # Highly irregular: intervals 0.1, 10, 0.1, 10 …
        offsets = [0]
        t = 0
        for i in range(15):
            t += 0.1 if i % 2 == 0 else 10
            offsets.append(t)
        for off in offsets:
            detectors.analyze_packet_timing("k", base + timedelta(seconds=off), flows)
        result = detectors.analyze_packet_timing("k", base + timedelta(seconds=offsets[-1] + 5), flows)
        self.assertIsNone(result)

    def test_timing_list_capped_at_100(self):
        flows = self._flows()
        base = datetime.now()
        for i in range(110):
            detectors.analyze_packet_timing("k", base + timedelta(seconds=i), flows)
        self.assertLessEqual(len(flows["k"]["timing"]), 100)


class TestAnalyzePacketSizes(unittest.TestCase):
    """detectors.analyze_packet_sizes()"""

    def _flows(self):
        return defaultdict(lambda: {
            "packets": [], "sizes": [], "timing": [],
            "entropy_scores": [], "tls_info": {}, "flow_patterns": []
        })

    def test_returns_none_with_few_samples(self):
        flows = self._flows()
        result = detectors.analyze_packet_sizes("k", 100, flows)
        self.assertIsNone(result)

    def test_repeated_size_triggers_alert(self):
        flows = self._flows()
        # 20 packets all size 512 → > 30 % rule
        for _ in range(20):
            detectors.analyze_packet_sizes("k", 512, flows)
        result = detectors.analyze_packet_sizes("k", 512, flows)
        self.assertIsNotNone(result)
        self.assertIn("512", result)

    def test_small_then_large_pattern(self):
        flows = self._flows()
        # Alternate 50-byte and 2000-byte packets for > 20 entries
        for _ in range(10):
            detectors.analyze_packet_sizes("k", 50, flows)
            detectors.analyze_packet_sizes("k", 2000, flows)
        result = detectors.analyze_packet_sizes("k", 50, flows)
        self.assertIsNotNone(result)
        # Either the repeated-size or small->large alert fires (both are valid detections)
        self.assertTrue("50" in result or "control" in result)

    def test_sizes_capped_at_200(self):
        flows = self._flows()
        for i in range(210):
            detectors.analyze_packet_sizes("k", i, flows)
        self.assertLessEqual(len(flows["k"]["sizes"]), 200)


class TestDetectTlsFingerprints(unittest.TestCase):
    """detectors.detect_tls_fingerprints()"""

    def _flows(self):
        return defaultdict(lambda: {
            "packets": [], "sizes": [], "timing": [],
            "entropy_scores": [], "tls_info": {}, "flow_patterns": []
        })

    def test_tls_handshake_in_raw_detected(self):
        # Build a raw payload starting with 0x16 (TLS Handshake)
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x00, 0x00])
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(), _Raw: raw})
        flows = self._flows()
        ep = defaultdict(int)
        alerts = detectors.detect_tls_fingerprints(pkt, "k", flows, ep)
        self.assertTrue(any("TLS handshake" in a for a in alerts))
        self.assertEqual(ep["tls_handshake"], 1)

    def test_tls_client_hello_detected(self):
        payload = bytes([0x16, 0x03, 0x03]) + b'\x01\x00' + b'\x00' * 10
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(), _Raw: raw})
        flows = self._flows()
        ep = defaultdict(int)
        detectors.detect_tls_fingerprints(pkt, "k", flows, ep)
        self.assertEqual(ep["tls_client_hello"], 1)

    def test_no_tls_no_alert(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        flows = self._flows()
        ep = defaultdict(int)
        alerts = detectors.detect_tls_fingerprints(pkt, "k", flows, ep)
        self.assertEqual(alerts, [])


class TestAnalyzeEncryptedPayload(unittest.TestCase):
    """detectors.analyze_encrypted_payload()"""

    def _flows(self):
        return defaultdict(lambda: {
            "packets": [], "sizes": [], "timing": [],
            "entropy_scores": [], "tls_info": {}, "flow_patterns": []
        })

    def test_low_entropy_payload_no_alert(self):
        payload = b"\x00" * 200
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _Raw: raw})
        flows = self._flows(); ep = defaultdict(int)
        alerts = detectors.analyze_encrypted_payload(pkt, "k", flows, ep)
        self.assertEqual(alerts, [])

    def test_high_entropy_payload_processed(self):
        # bytes(range(256)) repeated → entropy ≈ 8, uniformly distributed
        payload = bytes(range(256)) * 4
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _Raw: raw})
        flows = self._flows(); ep = defaultdict(int)
        # Should not raise; entropy score appended
        detectors.analyze_encrypted_payload(pkt, "k", flows, ep)
        self.assertEqual(len(flows["k"]["entropy_scores"]), 1)

    def test_repeated_header_detected(self):
        # A 16-byte header repeated throughout → triggers alert
        header = bytes(range(16))
        payload = header * 20   # entropy will be moderate but header repeats
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _Raw: raw})
        # Force entropy > 7.5 by patching calculate_entropy
        flows = self._flows(); ep = defaultdict(int)
        with patch.object(detectors, "calculate_entropy", return_value=7.6):
            alerts = detectors.analyze_encrypted_payload(pkt, "k", flows, ep)
        self.assertTrue(any("Repeated header" in a for a in alerts))
        self.assertEqual(ep["repeated_headers"], 1)

    def test_no_raw_layer_returns_empty(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        flows = self._flows(); ep = defaultdict(int)
        alerts = detectors.analyze_encrypted_payload(pkt, "k", flows, ep)
        self.assertEqual(alerts, [])


class TestDetectEncryptedAgentTraffic(unittest.TestCase):
    """detectors.detect_encrypted_agent_traffic() — orchestrator."""

    def _ef(self):
        return defaultdict(lambda: {
            "packets": [], "sizes": [], "timing": [],
            "entropy_scores": [], "tls_info": {}, "flow_patterns": []
        })

    def test_no_ip_tcp_returns_empty(self):
        pkt = _make_packet({})
        ef = self._ef(); ep = defaultdict(int)
        self.assertEqual(detectors.detect_encrypted_agent_traffic(pkt, ef, ep), [])

    def test_packet_appended_to_flow(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ef = self._ef(); ep = defaultdict(int)
        detectors.detect_encrypted_agent_traffic(pkt, ef, ep)
        self.assertEqual(len(ef["1.2.3.4:5.6.7.8:80"]["packets"]), 1)

    def test_high_frequency_alert(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ef = self._ef(); ep = defaultdict(int)
        now = datetime.now()
        # Pre-load 50 packets within the last 60 s
        ef["1.2.3.4:5.6.7.8:80"]["packets"] = [
            now - timedelta(seconds=i) for i in range(50)
        ]
        # Also ensure recent_packets count > 30
        alerts = detectors.detect_encrypted_agent_traffic(pkt, ef, ep)
        self.assertTrue(any("High-frequency" in a for a in alerts))
        self.assertEqual(ep["high_freq_encrypted"], 1)

    def test_long_lived_session_alert(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ef = self._ef(); ep = defaultdict(int)
        # First packet > 30 minutes ago, plus 49 more to reach threshold
        old = datetime.now() - timedelta(minutes=35)
        ef["1.2.3.4:5.6.7.8:80"]["packets"] = (
            [old] + [old + timedelta(seconds=i) for i in range(49)]
        )
        alerts = detectors.detect_encrypted_agent_traffic(pkt, ef, ep)
        self.assertTrue(any("Long-lived" in a for a in alerts))
        self.assertEqual(ep["persistent_encrypted"], 1)

    def test_flow_packets_capped_at_500(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        ef = self._ef(); ep = defaultdict(int)
        ef["1.2.3.4:5.6.7.8:80"]["packets"] = [datetime.now()] * 500
        detectors.detect_encrypted_agent_traffic(pkt, ef, ep)
        self.assertLessEqual(len(ef["1.2.3.4:5.6.7.8:80"]["packets"]), 500)


class TestNetworkMonitor(unittest.TestCase):
    """monitor.NetworkMonitor — state init, packet handler, statistics."""

    def setUp(self):
        self.mon = monitor.NetworkMonitor(interface="eth0")

    def test_initial_state(self):
        self.assertFalse(self.mon.running)
        self.assertEqual(len(self.mon.alerts), 0)
        self.assertEqual(self.mon.interface, "eth0")

    def test_baseline_and_threshold(self):
        self.assertEqual(self.mon.baseline_window, config.BASELINE_WINDOW)
        self.assertEqual(self.mon.alert_threshold, config.ALERT_THRESHOLD)

    def test_packet_handler_ai_alert(self):
        """A DNS query for an AI domain should produce an alert entry."""
        pkt = _make_packet({
            _IP: _ip(),
            _DNS: _dns(b"api.openai.com."),
        })
        self.mon.packet_handler(pkt)
        self.assertTrue(any("openai" in a["alert"].lower() for a in self.mon.alerts))

    def test_packet_handler_agent_protocol_alert(self):
        """TCP to an A2A port should produce an alert entry."""
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        self.mon.packet_handler(pkt)
        self.assertTrue(any("A2A" in a["alert"] for a in self.mon.alerts))

    def test_packet_handler_alert_has_required_keys(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        self.mon.packet_handler(pkt)
        for entry in self.mon.alerts:
            self.assertIn("timestamp",   entry)
            self.assertIn("alert",       entry)
            self.assertIn("packet_info", entry)

    def test_packet_handler_increments_protocol_stats(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp()})
        self.mon.packet_handler(pkt)
        self.assertEqual(self.mon.protocol_stats["TCP"], 1)

    def test_packet_handler_exception_does_not_crash(self):
        """Handler should catch exceptions gracefully."""
        bad_pkt = MagicMock(side_effect=Exception("boom"))
        bad_pkt.haslayer = MagicMock(side_effect=Exception("boom"))
        try:
            self.mon.packet_handler(bad_pkt)
        except Exception:
            self.fail("packet_handler raised an exception")

    def test_get_network_interfaces_returns_list(self):
        ifaces = self.mon.get_network_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertIn("eth0", ifaces)

    def test_print_statistics_runs_without_error(self):
        """print_statistics() should not raise even on empty state."""
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.mon.print_statistics()
        output = buf.getvalue()
        self.assertIn("NETWORK MONITORING STATISTICS", output)

    def test_print_statistics_shows_alert_count(self):
        # Inject a fake alert
        self.mon.alerts.append({
            "timestamp": datetime.now().isoformat(),
            "alert": "Test alert",
            "packet_info": "summary",
        })
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.mon.print_statistics()
        self.assertIn("1", buf.getvalue())

    def test_multiple_packets_accumulate_alerts(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=a2a_port)})
        for _ in range(5):
            self.mon.packet_handler(pkt)
        # At minimum one alert per packet
        self.assertGreaterEqual(len(self.mon.alerts), 5)


class TestEndToEndFlow(unittest.TestCase):
    """
    Simulate a realistic sequence of packets through the full pipeline to
    confirm the modular code produces the same alert categories as the
    original monolithic script.
    """

    def setUp(self):
        self.mon = monitor.NetworkMonitor(interface="lo")

    def test_ai_dns_then_high_freq_connection(self):
        # Step 1: DNS query for Anthropic
        dns_pkt = _make_packet({
            _IP: _ip(src="10.0.0.1"),
            _DNS: _dns(b"api.anthropic.com."),
        })
        self.mon.packet_handler(dns_pkt)
        self.assertTrue(
            any("anthropic" in a["alert"].lower() for a in self.mon.alerts)
        )

        # Step 2: Many HTTPS connections to same host → high-frequency alert
        tcp_pkt = _make_packet({
            _IP: _ip(src="10.0.0.1", dst="3.3.3.3"),
            _TCP: _tcp(dport=443),
        })
        self.mon.connection_counts["10.0.0.1:3.3.3.3:443"] = 50
        self.mon.packet_handler(tcp_pkt)
        self.assertTrue(
            any("High frequency" in a["alert"] for a in self.mon.alerts)
        )

    def test_a2a_mesh_then_swarm(self):
        a2a_port = config.AGENT_PROTOCOLS["a2a"]["ports"][0]
        mcp_port = config.AGENT_PROTOCOLS["mcp"]["ports"][0]

        # Mesh: both src and dst are agent ports
        mesh_pkt = _make_packet({
            _IP: _ip(),
            _TCP: _tcp(sport=a2a_port, dport=mcp_port),
        })
        self.mon.packet_handler(mesh_pkt)
        self.assertTrue(
            any("Agent-to-Agent" in a["alert"] for a in self.mon.alerts)
        )

        # Swarm: pre-seed > 20 connections in last minute
        now = datetime.now()
        for proto in self.mon.agent_connections:
            self.mon.agent_connections[proto].clear()
        self.mon.agent_connections["a2a"] = [
            {"timestamp": now, "connection": f"x:y:{i}", "direction": "out"}
            for i in range(22)
        ]
        swarm_pkt = _make_packet({
            _IP: _ip(),
            _TCP: _tcp(dport=a2a_port),
        })
        self.mon.packet_handler(swarm_pkt)
        self.assertTrue(
            any("Swarm" in a["alert"] for a in self.mon.alerts)
        )

    def test_mcp_signature_in_payload(self):
        tcp = _tcp(payload=b"/mcp/context-protocol")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        self.mon.packet_handler(pkt)
        self.assertTrue(
            any("MCP" in a["alert"] for a in self.mon.alerts)
        )

    def test_coordination_keyword_end_to_end(self):
        tcp = _tcp(payload=b"agent_swarm coordination initiated")
        pkt = _make_packet({_IP: _ip(), _TCP: tcp})
        self.mon.packet_handler(pkt)
        self.assertTrue(
            any("Coordination" in a["alert"] or "coordination" in a["alert"].lower()
                for a in self.mon.alerts)
        )

    def test_tls_handshake_end_to_end(self):
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x00, 0x00])
        raw = _Raw()
        raw.load = payload
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=443), _Raw: raw})
        self.mon.packet_handler(pkt)
        self.assertTrue(
            any("TLS" in a["alert"] for a in self.mon.alerts)
        )

    def test_encrypted_flow_tracking(self):
        pkt = _make_packet({_IP: _ip(), _TCP: _tcp(dport=443)})
        self.mon.packet_handler(pkt)
        self.assertIn("1.2.3.4:5.6.7.8:443", self.mon.encrypted_flows)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()

    test_classes = [
        TestConfig,
        TestCryptoUtils,
        TestDetectAiTraffic,
        TestDetectAgentProtocols,
        TestDetectProtocolSignatures,
        TestAnalyzeTrafficPatterns,
        TestAnalyzePacketTiming,
        TestAnalyzePacketSizes,
        TestDetectTlsFingerprints,
        TestAnalyzeEncryptedPayload,
        TestDetectEncryptedAgentTraffic,
        TestNetworkMonitor,
        TestEndToEndFlow,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
