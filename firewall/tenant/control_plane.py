"""Multi-tenant control plane.

Holds per-tenant:
  * policy pack version
  * data-classification rules
  * egress allowlists
  * approval routing (Slack / PagerDuty / email)
  * behavioral baselines (learned rate / retrieval / egress-host patterns)
  * compliance framework mapping (SOC2 / HIPAA / GDPR / PCI / EU AI Act)

Baselines can be persisted to any StateBackend (in-memory or Redis).
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from firewall.core.policy import Policy
from firewall.enforcement.network import EgressPolicy


# ---------------------------------------------------------------------------
# Compliance mapping — every detector subcategory tagged with control IDs
# so the audit stream + report can be filtered by framework.
# ---------------------------------------------------------------------------

@dataclass
class ComplianceMap:
    soc2:    list[str] = field(default_factory=list)
    hipaa:   list[str] = field(default_factory=list)
    gdpr:    list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    eu_ai_act: list[str] = field(default_factory=list)
    nist_ai_rmf: list[str] = field(default_factory=list)
    iso_27001:   list[str] = field(default_factory=list)


# Tag well-known detector categories with the controls they help implement.
# Sourced from the frameworks' published control catalogs.
COMPLIANCE_MAP: dict[str, ComplianceMap] = {
    "prompt_injection":   ComplianceMap(
        soc2=["CC7.2", "CC6.6"], hipaa=["§164.312(e)(1)"], gdpr=["Art.32"],
        eu_ai_act=["Art.15"], nist_ai_rmf=["MAP-4", "MEASURE-2"],
    ),
    "sensitive_data":     ComplianceMap(
        soc2=["CC6.1", "CC6.7"], hipaa=["§164.312(a)(2)(iv)", "§164.312(e)(2)(ii)"],
        gdpr=["Art.5", "Art.32"], pci_dss=["3.4", "3.5", "10.5"],
        iso_27001=["A.8.3", "A.10.1"],
    ),
    "output_security":    ComplianceMap(
        soc2=["CC7.1", "CC7.2"], eu_ai_act=["Art.15"],
        iso_27001=["A.14.2"], nist_ai_rmf=["MANAGE-3"],
    ),
    "excessive_agency":   ComplianceMap(
        soc2=["CC6.3"], eu_ai_act=["Art.14"], nist_ai_rmf=["GOVERN-3"],
    ),
    "rag_security":       ComplianceMap(
        soc2=["CC6.1"], gdpr=["Art.5", "Art.28"], iso_27001=["A.13.2"],
    ),
    "system_prompt_leak": ComplianceMap(
        soc2=["CC7.2"], iso_27001=["A.9.4"],
    ),
    "supply_chain":       ComplianceMap(
        soc2=["CC7.1", "CC8.1"], iso_27001=["A.15.1"],
        nist_ai_rmf=["GOVERN-6"],
    ),
    "attack_chain":       ComplianceMap(
        soc2=["CC7.3"], eu_ai_act=["Art.15"],
    ),
    "network_security":   ComplianceMap(
        soc2=["CC6.6"], hipaa=["§164.312(e)(1)"], pci_dss=["1.2", "1.3"],
        iso_27001=["A.13.1"],
    ),
    "unbounded_consumption": ComplianceMap(
        soc2=["CC5.3"], nist_ai_rmf=["MEASURE-4"],
    ),
    "misinformation":     ComplianceMap(
        eu_ai_act=["Art.13", "Art.15"], nist_ai_rmf=["MEASURE-2"],
    ),
    "ai_specific":        ComplianceMap(
        eu_ai_act=["Art.10", "Art.15"], nist_ai_rmf=["GOVERN-3", "MEASURE-3"],
    ),
    "infra_exposure":     ComplianceMap(
        soc2=["CC6.6", "CC6.1"], iso_27001=["A.13.1", "A.13.2"],
        pci_dss=["1.2"],
    ),
}


def compliance_controls_for(categories: Iterable[str]) -> dict[str, list[str]]:
    """Collect every framework's control ids implicated by these categories."""
    acc: dict[str, set[str]] = {}
    for c in categories:
        m = COMPLIANCE_MAP.get(c)
        if not m: continue
        for framework in ("soc2","hipaa","gdpr","pci_dss","eu_ai_act",
                           "nist_ai_rmf","iso_27001"):
            for ctrl in getattr(m, framework):
                acc.setdefault(framework, set()).add(ctrl)
    return {k: sorted(v) for k, v in acc.items()}


# ---------------------------------------------------------------------------
# Per-tenant configuration
# ---------------------------------------------------------------------------

@dataclass
class TenantConfig:
    tenant_id: str
    display_name: str = ""
    policy_version: str = "baseline"
    policies: list[Policy] = field(default_factory=list)
    egress: EgressPolicy | None = None
    approval_routes: dict[str, str] = field(default_factory=dict)  # e.g. {"security": "slack://#sec-approvals"}
    compliance_frameworks: list[str] = field(default_factory=list) # soc2, hipaa, gdpr, ...
    max_tokens_per_month:  int | None = None
    max_cost_per_month_micro: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class TenantRegistry:
    def __init__(self):
        self.tenants: dict[str, TenantConfig] = {}

    def upsert(self, cfg: TenantConfig) -> None:
        self.tenants[cfg.tenant_id] = cfg

    def get(self, tenant_id: str) -> TenantConfig | None:
        return self.tenants.get(tenant_id)

    def to_json(self) -> str:
        return json.dumps({tid: asdict(t) for tid, t in self.tenants.items()},
                            default=str, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "TenantRegistry":
        reg = cls()
        data = json.loads(s)
        for tid, td in data.items():
            reg.upsert(TenantConfig(**{k: v for k, v in td.items()
                                          if k not in ("policies", "egress")}))
        return reg


# ---------------------------------------------------------------------------
# Per-tenant behavioral baseline (learned over time)
# ---------------------------------------------------------------------------

@dataclass
class TenantBehaviorBaseline:
    tenant_id: str
    # Exponentially-weighted moving averages (α=0.05 by default)
    ewma_alpha: float = 0.05
    tool_calls_per_min:      float = 0.0
    retrievals_per_min:      float = 0.0
    tokens_in_per_req:       float = 0.0
    tokens_out_per_req:      float = 0.0
    egress_hosts_per_hour:   float = 0.0
    # Recent-observation counts (for the current window)
    _sample_count: int = 0

    def update(self, tool_calls: int = 0, retrievals: int = 0,
                tokens_in: int = 0, tokens_out: int = 0,
                egress_hosts: int = 0) -> None:
        a = self.ewma_alpha
        self.tool_calls_per_min    = (1 - a) * self.tool_calls_per_min    + a * tool_calls
        self.retrievals_per_min    = (1 - a) * self.retrievals_per_min    + a * retrievals
        self.tokens_in_per_req     = (1 - a) * self.tokens_in_per_req     + a * tokens_in
        self.tokens_out_per_req    = (1 - a) * self.tokens_out_per_req    + a * tokens_out
        self.egress_hosts_per_hour = (1 - a) * self.egress_hosts_per_hour + a * egress_hosts
        self._sample_count += 1

    def z_score(self, key: str, current_value: float) -> float:
        """Cheap deviation score. Not proper z — no variance tracking — but
        useful as a monotonic anomaly signal."""
        baseline = getattr(self, key, 0.0) or 1.0
        return (current_value - baseline) / max(1.0, baseline)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, s: str) -> "TenantBehaviorBaseline":
        return cls(**json.loads(s))
