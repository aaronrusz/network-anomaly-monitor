"""
config.py — Static configuration: protocol definitions, signatures, and thresholds.

All values are plain Python 3 literals; no third-party dependencies.
"""

# ---------------------------------------------------------------------------
# Baseline and alert thresholds
# ---------------------------------------------------------------------------

BASELINE_WINDOW: int   = 300   # seconds — rolling window for traffic baselines
ALERT_THRESHOLD: float = 2.0   # standard deviations before anomaly is raised

# ---------------------------------------------------------------------------
# AI / ML service domains
# ---------------------------------------------------------------------------

AI_PROTOCOLS: dict[str, list[str]] = {
    "openai":       ["api.openai.com", "openai.com"],
    "anthropic":    ["api.anthropic.com", "claude.ai"],
    "google_ai":    ["generativelanguage.googleapis.com", "bard.google.com"],
    "azure_openai": ["openai.azure.com"],
    "huggingface":  ["huggingface.co", "api-inference.huggingface.co"],
    "ollama":       ["localhost:11434"],
    "langchain":    ["langchain.com", "api.langchain.com"],
    "replicate":    ["replicate.com", "api.replicate.com"],
    "cohere":       ["api.cohere.ai"],
    "stability":    ["api.stability.ai"],
}

# ---------------------------------------------------------------------------
# Agent-to-Agent / ACP / MCP protocol definitions
# ---------------------------------------------------------------------------

AGENT_PROTOCOLS: dict[str, dict] = {
    "a2a": {
        "ports":         [8080, 8081, 8082, 9090, 9091, 5000, 5001],
        "patterns":      [r"agent-to-agent", r"a2a-protocol", r"/agents/", r"/communicate"],
        "content_types": ["application/x-a2a", "application/agent-message"],
    },
    "acp": {
        "ports":         [7000, 7001, 7777, 8888, 9999],
        "patterns":      [r"agent-communication", r"acp-protocol", r"/acp/", r"agent-comm"],
        "content_types": ["application/x-acp", "application/agent-comm"],
    },
    "mcp": {
        "ports":         [3000, 3001, 3333, 4000, 4001],
        "patterns":      [r"model-context", r"mcp-protocol", r"/mcp/", r"context-protocol"],
        "content_types": ["application/x-mcp", "application/model-context"],
    },
}

# ---------------------------------------------------------------------------
# HTTP User-Agent / header patterns that suggest AI agent software
# ---------------------------------------------------------------------------

AI_AGENT_PATTERNS: list[str] = [
    r"langchain",
    r"openai-python",
    r"anthropic-sdk",
    r"ollama",
    r"autogen",
    r"crewai",
    r"agent",
    r"llm",
    r"chatbot",
    r"a2a-agent",
    r"acp-client",
    r"mcp-client",
    r"agent-framework",
    r"multi-agent",
    r"swarm",
]

# ---------------------------------------------------------------------------
# JSON-RPC patterns common in agent protocols
# ---------------------------------------------------------------------------

JSON_RPC_AGENT_PATTERNS: list[str] = [
    r'"method"\s*:\s*"agent\.',
    r'"method"\s*:\s*"communicate"',
    r'"method"\s*:\s*"execute_task"',
    r'"method"\s*:\s*"coordinate"',
    r'"params"\s*:\s*\{.*"agent_id"',
    r'"result"\s*:\s*\{.*"status".*"completed"',
]

# ---------------------------------------------------------------------------
# Multi-agent coordination keywords searched in packet payloads
# ---------------------------------------------------------------------------

COORDINATION_KEYWORDS: list[str] = [
    "task_delegation",
    "agent_handoff",
    "coordination_request",
    "agent_status",
    "task_assignment",
    "agent_response",
    "multi_agent",
    "agent_swarm",
    "collective_intelligence",
]

# ---------------------------------------------------------------------------
# TLS library byte-string fingerprints that suggest agent software
# ---------------------------------------------------------------------------

AGENT_TLS_PATTERNS: list[bytes] = [
    b"python-requests",
    b"aiohttp",
    b"httpx",
    b"golang",
    b"node-fetch",
]

# ---------------------------------------------------------------------------
# Standard TCP ports monitored for AI API traffic
# ---------------------------------------------------------------------------

AI_STANDARD_PORTS: list[int] = [80, 443, 8080, 11434]
