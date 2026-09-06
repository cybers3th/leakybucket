"""Production-shape serving layer:
  * async gateway wrapping the sync core
  * streaming SSE inspection with hard-cut mid-response
  * OpenAI-compatible proxy (works with any upstream speaking the same shape)
  * signed, chain-hashed audit log with SIEM sinks
  * distributed state layer (in-memory + Redis backends)
"""
from firewall.serve.async_gateway import AsyncGateway
from firewall.serve.stream    import StreamingInspector, HardCut
from firewall.serve.signed_audit import SignedAuditLog
from firewall.serve.distributed_state import StateBackend, InMemoryState, RedisState
from firewall.serve.proxy    import build_openai_app

__all__ = [
    "AsyncGateway", "StreamingInspector", "HardCut", "SignedAuditLog",
    "StateBackend", "InMemoryState", "RedisState",
    "build_openai_app",
]
