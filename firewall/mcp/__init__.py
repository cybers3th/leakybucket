"""MCP-native firewall layer.

Sits between an MCP client and one or more MCP servers, inspects every
JSON-RPC message flowing in each direction, and enforces trust, provenance,
and policy.
"""
from firewall.mcp.types import (
    MCPServerDef, MCPToolFingerprint, MCPMessage, MCPDirection,
)
from firewall.mcp.registry import MCPServerRegistry
from firewall.mcp.gateway import MCPGateway, MCPBlocked, MCPApprovalRequired
from firewall.mcp.inspector import MCPInspector, MCPDataFlowTracker

__all__ = [
    "MCPServerDef", "MCPToolFingerprint", "MCPMessage", "MCPDirection",
    "MCPServerRegistry", "MCPGateway", "MCPBlocked", "MCPApprovalRequired",
    "MCPInspector", "MCPDataFlowTracker",
]
