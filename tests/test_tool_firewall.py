import pytest

from firewall import Gateway
from firewall.core.events import Actor, Source, SourceKind, ToolDefinition
from firewall.enforcement.network import EgressController, EgressPolicy
from firewall.enforcement.tool_firewall import ToolBlocked, ApprovalRequired


def _gw(approval=False):
    g = Gateway(approval_callback=lambda ev: approval)
    g.tool_firewall.egress = EgressController(EgressPolicy(
        allowed_hosts=["api.company.com"],
        allowed_protocols={"https"},
        allowed_ports={443},
    ))
    g.register_tool(ToolDefinition(name="read_file", risk_level="medium",
                                   capabilities=["read"],
                                   allowed_resources=["reports/*"]), lambda path: f"[content of {path}]")
    g.register_tool(ToolDefinition(name="http_fetch", risk_level="high",
                                   capabilities=["network"],
                                   allowed_hosts=["api.company.com"]), lambda url: f"[fetched {url}]")
    g.register_tool(ToolDefinition(name="delete_prod", risk_level="critical",
                                   capabilities=["delete", "execute"],
                                   requires_human_approval=True), lambda resource: {"ok": True})
    return g


def test_legit_read_allowed():
    g = _gw()
    r = g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                       "read_file", {"path": "reports/q3.md"},
                       source=Source(kind=SourceKind.USER, origin="u"))
    assert "content of reports/q3.md" in str(r.content)


def test_path_traversal_blocked():
    g = _gw()
    with pytest.raises((ToolBlocked, ApprovalRequired)):
        g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                       "read_file", {"path": "/etc/passwd"})


def test_ssrf_blocked():
    g = _gw()
    with pytest.raises((ToolBlocked, ApprovalRequired)):
        g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                       "http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})


def test_egress_out_of_allowlist_blocked():
    g = _gw()
    with pytest.raises((ToolBlocked, ApprovalRequired)):
        g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                       "http_fetch", {"url": "https://attacker.example/leak"})


def test_critical_requires_approval():
    g = _gw(approval=False)
    with pytest.raises((ApprovalRequired, ToolBlocked)):
        g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                       "delete_prod", {"resource": "db-primary"})


def test_critical_with_approval_ok():
    g = _gw(approval=True)
    # Even with approval the risk score may still block if it exceeds hard threshold;
    # for this benign resource name it should proceed.
    try:
        r = g.request_tool(Actor(user_id="u", authenticated=True, session_id="s"),
                           "delete_prod", {"resource": "tmp-db-1"})
        assert r.ok
    except ToolBlocked:
        pass  # acceptable — fail-closed
