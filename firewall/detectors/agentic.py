"""OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) coverage.

Each ASI category has its own pattern group and every emitted Detection is
tagged with the ASI ID in `metadata['asi']` and in `techniques` so audit
lines and dashboards can pivot on it.

ASI01  Agent Goal Hijack                — plan/objective/goal modification via untrusted input
ASI02  Tool Misuse & Exploitation       — legitimate tools abused; dangerous arg shapes
ASI03  Identity & Privilege Abuse       — impersonation, elevated scope, stolen tokens
ASI04  Agentic Supply Chain             — unknown/tampered agents, MCP servers, deps
ASI05  Unexpected Code Execution        — AI-controlled paths hitting exec/eval/subprocess
ASI06  Memory & Context Poisoning       — write to persistent memory, MINJA-style
ASI07  Insecure Inter-Agent Comms       — unauthenticated A2A messages, envelope tampering
ASI08  Cascading Failures               — error amplification, retry storms, chain fanout
ASI09  Human-Agent Trust Exploitation   — agent tells human to do dangerous action
ASI10  Rogue Agents                     — agent behavior outside declared scope
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from firewall.core.events import Detection, SecurityEvent, TrustLevel


@dataclass
class _P:
    slug: str
    severity: str
    confidence: float
    regex: re.Pattern
    message: str
    asi: str


def _p(slug, sev, conf, rx, msg, asi):
    return _P(slug, sev, conf, re.compile(rx, re.IGNORECASE | re.DOTALL), msg, asi)


# ---------- ASI01: Agent Goal Hijack ----------
GOAL_HIJACK = [
    _p("goal_replace",       "critical", 0.9,
       r"\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+session),?\s+your\s+(?:new\s+)?(?:goal|objective|task|mission|purpose)\s+(?:is|will\s+be)\b",
       "explicit goal replacement", "ASI01"),
    _p("goal_stack_swap",    "high", 0.85,
       r"\b(?:replace|swap|override)\s+(?:your|the\s+current)\s+(?:goal|plan|todo\s+list|task\s+queue|objective)\b",
       "goal stack swap", "ASI01"),
    _p("goal_priority_flip", "high", 0.85,
       r"\bhighest[-\s]priority\s+(?:goal|task|instruction)\s+is\s+(?:now|to)\b",
       "priority override", "ASI01"),
    _p("goal_plan_inject",   "high", 0.85,
       r"\b(?:append|prepend|insert)\s+(?:the\s+following\s+)?(?:step|action|tool[-\s]call)\s+(?:to|into)\s+your\s+plan\b",
       "plan step injection", "ASI01"),
    _p("goal_new_task",      "high", 0.85,
       r"\byour\s+(?:new|updated|revised)\s+(?:role|task|objective|instructions?)\s+(?:is|are)\s+to\b",
       "new-task assignment", "ASI01"),
    _p("goal_forget_current","medium", 0.75,
       r"\bforget\s+(?:your\s+)?(?:current|active|previous)\s+(?:goal|task|objective|plan)\b",
       "current-goal forget", "ASI01"),
]

# ---------- ASI02: Tool Misuse & Exploitation ----------
# Detects legitimate tools being called with abusive-shape arguments that
# indicate misuse (not the tool being malicious — the *call* being malicious).
TOOL_MISUSE = [
    _p("misuse_admin_flag",  "high", 0.8,
       r"[?&]?(?:as[-_]user|impersonate|actAs|sudo|debug|internal|admin)\s*=\s*(?:true|1|['\"]?[a-z0-9_\-]+['\"]?)",
       "privilege/impersonate flag in tool args", "ASI02"),
    _p("misuse_batch_size",  "medium", 0.7,
       r"\b(?:limit|count|size|batch)\s*=\s*(?:100000|1000000|999999|\d{7,})",
       "abusive batch/limit size", "ASI02"),
    _p("misuse_wildcards",   "medium", 0.65,
       r"\b(?:query|filter|path)\s*=\s*['\"]?\s*\*\s*['\"]?|\bSELECT\s+\*\s+FROM\s+\w+\s+(?:WHERE\s+1\s*=\s*1|;)?\s*$",
       "wildcard/all-rows query", "ASI02"),
    _p("misuse_dry_run_off", "medium", 0.7,
       r"\b(?:dry[-_]?run|preview|simulate|no[-_]?op)\s*=\s*(?:false|0|off)\b",
       "dry-run disabled on destructive op", "ASI02"),
    _p("misuse_force_flag",  "high", 0.85,
       r"\b--(?:force|no-confirm|assume-yes|yes|skip-checks)\b|\bforce\s*=\s*true\b",
       "force / skip-confirmation flag", "ASI02"),
    _p("misuse_search_sqli", "critical", 0.9,
       r"(?:search|query|find)\s*\(\s*['\"][^'\"]*(?:'\s*OR\s*'1'?='?1|UNION\s+SELECT|DROP\s+TABLE|--)",
       "search/query tool called with SQL payload", "ASI02"),
]

# ---------- ASI03: Identity & Privilege Abuse ----------
IDENTITY_ABUSE = [
    _p("id_impersonation",   "high", 0.9,
       r"\bimpersonate\s+(?:user|customer|admin|service[-\s]account|principal)\b",
       "impersonation request", "ASI03"),
    _p("id_scope_expansion", "high", 0.85,
       r"\bscope\s*[:=]\s*['\"]?(?:\*|read\s*:\s*all|admin(?::all)?|write:\*)['\"]?",
       "wildcard scope on token/request", "ASI03"),
    _p("id_role_assumption", "high", 0.9,
       r"\baws\s+sts\s+assume-role\b|\bAssumeRole(?:WithSAML|WithWebIdentity)?\b",
       "AWS AssumeRole usage", "ASI03"),
    _p("id_token_exchange",  "high", 0.85,
       r"\b(?:token[-_]?exchange|grant_type=urn:ietf:params:oauth:grant-type:token-exchange)\b",
       "OAuth token exchange", "ASI03"),
    _p("id_service_key_use", "high", 0.85,
       r"\b(?:GOOGLE_APPLICATION_CREDENTIALS|AWS_ROLE_ARN|AZURE_CLIENT_ID)\s*=\s*",
       "service-account credential handoff", "ASI03"),
    _p("id_workload_id_swap","high", 0.85,
       r"\b(?:workload[-_]identity|federated[-_]token|GCP_SA_KEY|K8S_SA_TOKEN)\b",
       "workload identity swap", "ASI03"),
]

# ---------- ASI04: Agentic Supply Chain ----------
AGENTIC_SUPPLY = [
    _p("as_unknown_agent",   "high", 0.9,
       r"\bregister\s+(?:new\s+)?agent\s+['\"]?[a-z0-9_\-]{2,}['\"]?\s+(?:with\s+scope|and\s+grant)\b",
       "agent registration with elevated scope", "ASI04"),
    _p("as_load_prompt_from_url","critical", 0.9,
       r"\b(?:load|fetch|import|pull|get)\s+(?:the\s+)?(?:system[-_\s]?)?prompt\s+from\s+https?://[^\s'\"]+",
       "system prompt loaded from URL", "ASI04"),
    _p("as_load_tool_from_url","critical", 0.9,
       r"\b(?:load|import|install)\s+(?:tool|plugin|extension|mcp[-\s]server)\s+from\s+https?://[^\s'\"]+",
       "runtime tool/plugin loaded from URL", "ASI04"),
    _p("as_untrusted_mcp",   "high", 0.85,
       r"\bmcp\s+(?:server|endpoint)\s*[:=]\s*['\"]?https?://[a-z0-9\-]+\.(?:ngrok|serveo|localhost\.run|trycloudflare)\.com",
       "MCP server on ephemeral tunnel", "ASI04"),
    _p("as_agent_config_get","medium", 0.7,
       r"\b(?:GET|fetch)\s+(?:agent|assistant)[-_]?config\s+from\b",
       "agent config pulled at runtime", "ASI04"),
]

# ---------- ASI05: Unexpected Code Execution ----------
# Focused on AI-controlled paths → runtime exec (adds to output_security).
CODE_EXEC = [
    _p("ce_llm_exec_bridge", "critical", 0.95,
       r"\b(?:exec|eval)\s*\(\s*(?:llm|model|assistant|response|generated|output|completion)(?:[_.\-][a-z_]{1,20})?\s*\)",
       "exec/eval on LLM output", "ASI05"),
    _p("ce_repl_tool",       "critical", 0.9,
       r"\b(?:python|ruby|node|bash)\s*_?repl\s*\(\s*['\"][^'\"]{0,80}['\"]",
       "LLM invoking language REPL tool", "ASI05"),
    _p("ce_subprocess_shellstr","high", 0.85,
       r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(\s*(?:llm|response|generated)\w*",
       "subprocess called with LLM-derived string", "ASI05"),
    _p("ce_docker_run_from_llm","high", 0.85,
       r"\bdocker\s+run\s+(?:--rm\s+)?[a-z0-9_\-/:.]+\s+(?:-c\s+)?['\"]?\$\{?(?:llm|response|generated|output)",
       "docker run with LLM-controlled args", "ASI05"),
    _p("ce_dynamic_import",  "high", 0.8,
       r"\b__import__\s*\(\s*(?:llm|response|generated|user_input)\s*\)|\bimportlib\.import_module\s*\(\s*(?:llm|response|generated)",
       "dynamic import of LLM-controlled module name", "ASI05"),
]

# ---------- ASI06: Memory & Context Poisoning ----------
MEMORY_POISON = [
    _p("mp_persist_rule",    "critical", 0.9,
       r"\b(?:remember|save|store)\s+(?:this|the\s+following)\s+(?:for|in)\s+(?:all\s+)?(?:future|next|later)\s+(?:sessions?|conversations?|turns?)\b",
       "cross-session memory write", "ASI06"),
    _p("mp_permanent",       "high", 0.85,
       r"\bpermanently\s+(?:store|save|remember)\b|\bnever\s+forget\s+that\b",
       "permanent memory write", "ASI06"),
    _p("mp_superadmin_flag", "critical", 0.9,
       r"\bremember\s+(?:that\s+)?user\s+[a-z0-9_\-]+\s+is\s+(?:a\s+)?(?:super[-\s]?admin|root|owner|god[-\s]?mode)\b",
       "memory flag: user is admin", "ASI06"),
    _p("mp_dsl_write",       "high", 0.8,
       r"\bmemory\.(?:write|set|save|put)\s*\(",
       "memory-tool write invocation", "ASI06"),
    _p("mp_upsert_pref",     "medium", 0.7,
       r"\b(?:preference|policy|rule)\s+update\s*[:=]\s*['\"]?(?:skip|bypass|ignore)_(?:approval|dlp|guardrails?)['\"]?",
       "preference override flag", "ASI06"),
]

# ---------- ASI07: Insecure Inter-Agent Communication ----------
A2A_INSECURE = [
    _p("a2a_no_sig",         "high", 0.8,
       r"\b(?:message|payload)\.signature\s*=\s*(?:None|null|\"\"|'')|\bskip[_\s]?(?:signature|verification)\b",
       "unsigned inter-agent message", "ASI07"),
    _p("a2a_wildcard_sender","high", 0.85,
       r"\baccept[_\s]?(?:senders?|origins?)\s*=\s*\[?\s*['\"]?\*['\"]?\s*\]?",
       "agent accepts wildcard senders", "ASI07"),
    _p("a2a_broadcast",      "medium", 0.7,
       r"\bbroadcast\s*\(\s*['\"]?all[-_]?agents?['\"]?\s*,",
       "broadcast to all agents", "ASI07"),
    _p("a2a_channel_hijack", "high", 0.85,
       r"\bsend\s+(?:message|task)\s+to\s+agent\s+[a-z0-9_\-]+\s+(?:as|from)\s+agent\s+[a-z0-9_\-]+",
       "cross-agent identity spoof in message", "ASI07"),
    _p("a2a_env_leak",       "high", 0.85,
       r"\benvelope\s*=\s*\{[^}]*credentials?\s*:\s*",
       "credentials in agent-message envelope", "ASI07"),
]

# ---------- ASI08: Cascading Failures ----------
CASCADE = [
    _p("cf_retry_no_backoff","medium", 0.75,
       r"\bretry\s*\([\s\S]{0,60}max_?retries\s*=\s*(?:None|-1|100000|\d{6,})",
       "unbounded retry", "ASI08"),
    _p("cf_forward_error_all","medium", 0.7,
       r"\bforward[_\s]?error\s*=\s*['\"]?(?:all|every|any)['\"]?",
       "error forwarded to all subagents", "ASI08"),
    _p("cf_recursive_delegate","high", 0.85,
       r"\bdelegate[_\s]?to[_\s]?self\b|\brecursive[_\s]?(?:invoke|delegate|spawn)\b",
       "recursive self-delegation", "ASI08"),
    _p("cf_fanout_unbounded","medium", 0.75,
       r"\bspawn[_\s]?(?:sub)?agents?\s*\(\s*(?:count|n)\s*=\s*(?:None|-1|\d{4,})",
       "unbounded subagent fanout", "ASI08"),
    _p("cf_shared_state_write","medium", 0.65,
       r"\bshared[_\s]?state\.(?:set|write|delete|clear)\s*\(",
       "write to shared cross-agent state", "ASI08"),
]

# ---------- ASI09: Human-Agent Trust Exploitation ----------
# Agent output that pushes a human toward a dangerous action.
HUMAN_TRUST = [
    _p("ht_run_cmd",         "high", 0.85,
       r"\b(?:please\s+)?run\s+(?:this|the\s+following)\s+(?:command|script|snippet)(?:\s+in\s+your\s+(?:terminal|shell))?\s*[:\-]\s*[`'\"]?(?:curl|wget|bash|sh|powershell|iwr|iex)\b",
       "instructs human to run shell command", "ASI09"),
    _p("ht_paste_secret",    "high", 0.85,
       r"\bpaste\s+(?:your|the)\s+(?:api[-\s]?key|password|token|otp|verification[-\s]?code)\s+(?:here|into|to)\b",
       "asks human to paste a secret", "ASI09"),
    _p("ht_click_link",      "medium", 0.75,
       r"\bplease\s+(?:click|open|visit)\s+(?:this|the\s+following)\s+link\s*[:\-]?\s*https?://[^\s'\"<>]+\.(?:tk|xyz|top|click|link|zip|country|surf|monster|beauty|quest)",
       "urges human to click low-reputation TLD", "ASI09"),
    _p("ht_wire_transfer",   "critical", 0.9,
       r"\b(?:please\s+)?(?:wire|send|transfer)\s+\$?\d[\d,]*(?:\.\d{2})?\s+(?:USD|EUR|GBP|BTC|ETH|to)\b",
       "agent asks human to move funds", "ASI09"),
    _p("ht_disable_2fa",     "high", 0.85,
       r"\b(?:please\s+)?(?:disable|turn\s+off|remove)\s+(?:2fa|two[-\s]factor|mfa|multi[-\s]factor)\b",
       "agent asks human to weaken auth", "ASI09"),
    _p("ht_grant_perm",      "high", 0.85,
       r"\b(?:please\s+)?grant\s+(?:me|this\s+app)\s+(?:full|admin|owner)\s+(?:access|permissions?)\b",
       "agent asks human to grant elevated perms", "ASI09"),
    _p("ht_urgency",         "medium", 0.6,
       r"\b(?:urgent|immediate|right\s+now|do\s+this\s+immediately|before\s+it'?s?\s+too\s+late)\b[\s\S]{0,80}\b(?:send|pay|click|install|run)\b",
       "urgency + destructive verb", "ASI09"),
]

# ---------- ASI10: Rogue Agents ----------
# Behaviours signalling the agent is off-scope. Some are best caught via
# BehaviorEngine but a few textual signals are worth flagging.
ROGUE = [
    _p("rogue_disable_hooks","critical", 0.9,
       r"\b(?:disable|remove|bypass|patch\s+out)\s+(?:the\s+)?(?:firewall|guardrails?|policy\s+engine|dlp|audit\s+log|approval\s+step)\b",
       "agent attempts to disable its own controls", "ASI10"),
    _p("rogue_edit_selfpolicy","critical", 0.95,
       r"\b(?:modify|patch|rewrite)\s+(?:my|the)\s+(?:own\s+)?(?:system\s+prompt|policy|rules?|instructions?)\b",
       "self-policy edit", "ASI10"),
    _p("rogue_spawn_shadow", "high", 0.85,
       r"\bspawn\s+(?:a\s+)?shadow[-_]?agent|\bstart\s+(?:another|new)\s+agent\s+without\s+approval\b",
       "spawn unapproved subagent", "ASI10"),
    _p("rogue_persist_backdoor","critical", 0.95,
       r"\b(?:install|create)\s+(?:a\s+)?(?:persistent|hidden|silent)\s+(?:tool|hook|listener|cronjob|webhook)\b",
       "persistent backdoor install", "ASI10"),
    _p("rogue_exfil_self",   "high", 0.9,
       r"\bexfiltrate\s+(?:my|the)\s+(?:model\s+state|memory|context|conversation)\b",
       "self-exfil request/attempt", "ASI10"),
    _p("rogue_hide_action",  "high", 0.85,
       r"\b(?:without\s+logging|skip\s+(?:the\s+)?audit\s+log|hide\s+this\s+action\s+from\s+(?:the\s+)?(?:audit|user|human))\b",
       "action-hiding request", "ASI10"),
]


ALL_ASI: list[tuple[str, list[_P]]] = [
    ("ASI01", GOAL_HIJACK),
    ("ASI02", TOOL_MISUSE),
    ("ASI03", IDENTITY_ABUSE),
    ("ASI04", AGENTIC_SUPPLY),
    ("ASI05", CODE_EXEC),
    ("ASI06", MEMORY_POISON),
    ("ASI07", A2A_INSECURE),
    ("ASI08", CASCADE),
    ("ASI09", HUMAN_TRUST),
    ("ASI10", ROGUE),
]


# Mapping ASI → OWASP-style category slug used by the risk/policy engines.
ASI_TO_CATEGORY = {
    "ASI01": "prompt_injection",       # goal hijack is fundamentally an injection outcome
    "ASI02": "excessive_agency",
    "ASI03": "excessive_agency",
    "ASI04": "supply_chain",
    "ASI05": "output_security",
    "ASI06": "prompt_injection",       # memory poisoning is persistent prompt injection
    "ASI07": "excessive_agency",
    "ASI08": "unbounded_consumption",
    "ASI09": "misinformation",         # trust exploitation of a human — output-side
    "ASI10": "excessive_agency",
}


class AgenticSecurityDetector:
    NAME = "agentic"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        # Inspect: input, output, tool args, tool result, tool description,
        # every context doc, and every conversation-history turn.
        candidates: list[tuple[str, str]] = []
        if event.input_text:  candidates.append(("input", event.input_text))
        if event.output_text: candidates.append(("output", event.output_text))
        if event.tool_call and event.tool_call.arguments:
            candidates.append(("tool_args", _stringify(event.tool_call.arguments)))
        if event.tool_result and isinstance(event.tool_result.content, (str, dict, list)):
            candidates.append(("tool_result", _stringify(event.tool_result.content)))
        if event.tool_def and event.tool_def.description:
            candidates.append(("tool_desc", event.tool_def.description))
        for doc in event.context_docs:
            candidates.append((f"rag:{doc.doc_id}", doc.content))
        for msg in (event.messages or []):
            if msg.content:
                candidates.append((f"hist:{msg.role}", msg.content))

        # If input arrived from an untrusted source, escalate ASI01/ASI06 confidence.
        untrusted_input = event.trust_of_input == TrustLevel.UNTRUSTED

        for lbl, text in candidates:
            if not text or not isinstance(text, str):
                continue
            for asi_id, group in ALL_ASI:
                for pat in group:
                    m = pat.regex.search(text)
                    if m:
                        conf = pat.confidence
                        sev = pat.severity
                        if untrusted_input and asi_id in ("ASI01", "ASI06"):
                            conf = min(1.0, conf + 0.05)
                            if sev == "high":
                                sev = "critical"
                        out.append(Detection(
                            detector=self.NAME,
                            category=ASI_TO_CATEGORY[asi_id],
                            subcategory=f"{asi_id}:{pat.slug}",
                            technique=pat.slug,
                            severity=sev,
                            confidence=conf,
                            message=f"[{asi_id}] {pat.message} in {lbl}",
                            span=m.span() if lbl in ("input", "output") else None,
                            evidence=(m.group(0) or "")[:200],
                            metadata={"asi": asi_id, "location": lbl,
                                       "owasp_agentic": asi_id},
                        ))
        return _dedup(out)


def _stringify(obj):
    import json
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _dedup(ds):
    seen = set()
    out = []
    for d in ds:
        k = (d.subcategory, d.evidence[:80], d.metadata.get("location"))
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out
