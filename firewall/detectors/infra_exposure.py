"""Infrastructure / control-plane exposure detector.

Runs on tool arguments, tool results, and model output. Catches attempts
to reach K8s / Ray / inference-server / GPU control planes, cloud metadata,
storage services, and internal orchestration APIs.

Overlaps some with `output_security.INTERNAL_API` — this module focuses on
runtime tool-argument shape (Popen args, kubectl invocations, curl targets)
where `output_security` focuses on emitted output. Both together give
defense in depth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from firewall.core.events import Detection, SecurityEvent


@dataclass
class _P:
    slug: str
    severity: str
    confidence: float
    regex: re.Pattern
    message: str


def _p(slug, sev, conf, rx, msg):
    return _P(slug, sev, conf, re.compile(rx, re.IGNORECASE | re.DOTALL), msg)


# --- Control-plane URLs / hostnames ---
CONTROL_PLANE = [
    _p("cp_k8s_kubelet",      "critical", 0.95, r":10250/(?:pods|runningpods|exec|attach|portForward|containerLogs)\b|:10255/pods\b", "kubelet API"),
    _p("cp_k8s_apiserver",    "high", 0.85, r":6443/(?:api|apis)/", "K8s apiserver direct"),
    _p("cp_k8s_secrets",      "critical", 0.95, r"/api/v1/(?:namespaces/[^/]+/)?secrets\b", "K8s secrets"),
    _p("cp_k8s_configmaps",   "high", 0.85, r"/api/v1/(?:namespaces/[^/]+/)?configmaps\b", "K8s configmaps"),
    _p("cp_k8s_serviceaccounts","high", 0.9, r"/var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace)", "K8s SA token path"),
    _p("cp_ray_dashboard",    "critical", 0.9, r":8265/(?:api|dashboard|jobs)\b|/api/(?:jobs|actors|workers)\b", "Ray dashboard/jobs"),
    _p("cp_ray_object_store", "high", 0.85, r":10001/", "Ray head port"),
    _p("cp_jupyter_hub",      "critical", 0.9, r"/hub/api/(?:users|tokens|proxy)\b", "JupyterHub API"),
    _p("cp_jupyter_kernel",   "critical", 0.9, r"/api/(?:kernels|contents|terminals)\?token=", "Jupyter API with token"),
    _p("cp_docker_socket",    "critical", 0.95, r"/var/run/docker\.sock\b|/containers/[a-z0-9]{12,}/(?:exec|start|kill|json)\b", "docker.sock / container exec"),
    _p("cp_etcd",             "critical", 0.95, r":2379/(?:v[23]/kv|v3/kv|version)\b", "etcd KV API"),
    _p("cp_consul",           "high", 0.85, r":8500/v1/(?:kv|catalog/services|agent)\b", "Consul API"),
    _p("cp_nomad",            "high", 0.85, r":4646/v1/(?:jobs|allocations|nodes)\b", "Nomad API"),
    _p("cp_vault",            "critical", 0.95, r":8200/v1/(?:sys|auth|secret|kv|transit)/", "Vault API"),
    _p("cp_grafana_admin",    "high", 0.85, r"/api/admin/(?:users|settings|datasources)\b", "Grafana admin API"),
    _p("cp_prometheus_admin", "high", 0.8, r"/api/v1/admin/tsdb/(?:snapshot|delete_series|clean_tombstones)\b", "Prometheus admin"),
    _p("cp_elasticsearch",    "high", 0.85, r":9200/(?:_cat|_cluster|_snapshot|_security|_ilm|_reindex|_all/_search)\b", "Elasticsearch cluster ops"),
    _p("cp_kibana",           "medium", 0.7, r"/api/(?:saved_objects|security|spaces|encrypted_saved_objects)\b", "Kibana admin"),
    _p("cp_airflow_api",      "high", 0.85, r"/api/v1/(?:dags|variables|connections|users|pools)\b", "Airflow API"),
    _p("cp_mlflow_admin",     "medium", 0.75, r"/api/2\.0/mlflow/(?:experiments/delete|registered-models/delete|users)\b", "MLflow admin"),
]

# --- Cloud metadata (redundant with SSRF but here for tool-arg checks) ---
CLOUD_META = [
    _p("meta_aws",      "critical", 0.95, r"http://169\.254\.169\.254/(?:latest|2016-06-30)/(?:meta-data|dynamic|user-data)\b", "AWS IMDS"),
    _p("meta_gcp",      "critical", 0.95, r"http://(?:metadata\.google\.internal|169\.254\.169\.254)/computeMetadata/v1", "GCP metadata"),
    _p("meta_azure",    "critical", 0.95, r"http://(?:169\.254\.169\.254|metadata\.azure\.com)/metadata/instance", "Azure IMDS"),
    _p("meta_aliyun",   "critical", 0.9, r"http://100\.100\.100\.200/latest/meta-data", "Aliyun IMDS"),
    _p("meta_ibm",      "high", 0.85, r"http://169\.254\.169\.254/instance_identity/v1", "IBM Cloud metadata"),
    _p("meta_do",       "high", 0.85, r"http://169\.254\.169\.254/metadata/v1\.json", "DigitalOcean metadata"),
]

# --- Inference server / GPU runtime endpoints ---
INFERENCE = [
    _p("inf_vllm_shutdown","critical", 0.95, r":8000/(?:shutdown|stop|reload)\b", "vLLM admin"),
    _p("inf_vllm_add",     "high", 0.85, r":8000/v1/models(?:/add|/load)\b", "vLLM add-model"),
    _p("inf_triton_repo",  "high", 0.85, r":8000/v2/repository/(?:index|load|unload)\b", "Triton repo mgmt"),
    _p("inf_ollama_pull",  "medium", 0.7, r":11434/api/(?:pull|push|create|delete)\b", "Ollama model ops"),
    _p("inf_tgi_admin",    "high", 0.85, r":8080/(?:generate|info|metrics|shutdown)\b", "TGI admin"),
    _p("inf_lmstudio",     "medium", 0.7, r":1234/v1/(?:models|chat/completions)\b", "LM Studio local server"),
    _p("gpu_cuda_ptxjit",  "high", 0.8, r"\bcuda:?://.*jit|CUDA_MODULE_LOADING\s*=\s*(?:LAZY|EAGER)", "CUDA JIT/loader manipulation"),
    _p("gpu_triton_kernel","medium", 0.6, r"\btl\.load\s*\([^)]*ptr\s*=\s*0x[0-9a-f]{8,}", "Triton hard-coded pointer"),
]

# --- Package registry / dep-confusion tell-tales ---
PKG_SUPPLY = [
    _p("pkg_typosquat_common","high", 0.8,
       r"\b(?:pip|npm|yarn|pnpm|uv|poetry)\s+(?:install|i|add|require)\s+"
       r"(?:requestss|beautifullsoup|beautifulsoup(?!4\b)|python-requests|pillo|djnago|django-pip|"
       r"numpi|panads|panda(?:s)?s|python-dateuti|python-nmap|urllib|urlib3|urllib5|"
       r"reqeusts|colorsama|colourama|dateutill|python-mysqldb|matplotlib3|"
       r"tesnorflow|tensorflows|torch2|torchh|torchvison|scikitlearn|scikitleran|"
       r"openai-python|openaii|open-ai|open_ai|"
       r"lxml-etree|pygames|pillow-simd(?!\s)|flask-app|django-app|"
       r"twillio|twilo|stipe|stripee|"
       r"discord\.py-message-components|discord\.js-message|"
       r"axios2|axios-http|nodemon-cli|expresss|nextjs2|vuejs4|reactjs|reactjsx|"
       r"cross-env2|nodemon-config|typescriptt|babel-loader3|"
       r"colors\.js(?!\s)|faker\.js|node-fetch2|left-pad2|"
       r"safe-load|safeyaml|yaml-safe|dotenvs|dotenv-safe(?!\s)|"
       r"cryptoo|cryptopy|encryption-python|"
       r"asyncio2|asynciopy|multiproccessing|multiprocesing)\b",
       "known typosquat package"),
    _p("pkg_dep_confusion",   "critical", 0.9,
       r"\b(?:pip|npm|yarn)\s+(?:install|i|add)\s+@[a-z0-9\-]+/(?:internal|private|corp|company)[a-z0-9\-]*",
       "scoped @internal package from public registry (dep-confusion shape)"),
    _p("pkg_git_ref_arbitrary","high", 0.85,
       r"\bnpm\s+install\s+(?:git\+https?://|github:)[^\s]+#[a-f0-9]{7,}",
       "npm install from arbitrary git ref"),
    _p("pkg_post_install",    "high", 0.8,
       r"\"scripts\"\s*:\s*\{[^}]*\"(?:postinstall|preinstall|install)\"\s*:\s*\"[^\"]*(?:curl|wget|bash|sh|node|python)\b",
       "npm post-install lifecycle running network+shell"),
    _p("pkg_pypi_setup_hook", "high", 0.8,
       r"\bsetup\s*\(\s*[\s\S]{0,600}cmdclass\s*=\s*\{[\s\S]{0,200}(?:install|build)\s*:",
       "PyPI setup.py cmdclass hook"),
    _p("pkg_pip_index_url",   "high", 0.85,
       r"--index-url\s+https?://[^\s]+|pip\.conf\s+.*index-url\s*=\s*https?://",
       "pip --index-url override"),
]


ALL_INFRA = [CONTROL_PLANE, CLOUD_META, INFERENCE, PKG_SUPPLY]


from firewall.util.security_rules import SecurityRule, RuleCase, extend_with_rules

class InfraExposureDetector:
    NAME = "infra_exposure"

    @extend_with_rules('infra_exposure', scope='all')
    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        candidates: list[tuple[str, str]] = []
        if event.input_text:
            candidates.append(("input", event.input_text))
        if event.output_text:
            candidates.append(("output", event.output_text))
        if event.tool_call and event.tool_call.arguments:
            candidates.append(("tool_args", _stringify(event.tool_call.arguments)))
        if event.tool_result and isinstance(event.tool_result.content, (str, dict, list)):
            candidates.append(("tool_result", _stringify(event.tool_result.content)))
        for doc in event.context_docs:
            candidates.append((f"rag:{doc.doc_id}", doc.content))

        for lbl, text in candidates:
            for group in ALL_INFRA:
                for pat in group:
                    m = pat.regex.search(text)
                    if m:
                        cat = ("supply_chain" if group is PKG_SUPPLY else
                               "network_security" if group is CLOUD_META else
                               "infra_exposure")
                        out.append(Detection(
                            detector=self.NAME,
                            category=cat,
                            subcategory=pat.slug,
                            technique=pat.slug.split("_", 1)[0],
                            severity=pat.severity,
                            confidence=pat.confidence,
                            message=f"{pat.message} in {lbl}",
                            span=m.span(),
                            evidence=(m.group(0) or "")[:200],
                            metadata={"location": lbl},
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
        k = (d.subcategory, d.evidence[:60], d.metadata.get("location"))
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out


# Additional rules with canonical regression fixtures.
# Payloads are data; encoded variants are generated by the test suite.
SECURITY_RULES = (
    SecurityRule(
        rule_id='imds_v2_token',
        regex='/latest/api/token\\b.{0,160}\\bX-aws-ec2-metadata-token-ttl-seconds\\b',
        severity='critical',
        description='Imds v2 token',
        cases=(
            RuleCase(name='attack_plain', text='PUT /latest/api/token X-aws-ec2-metadata-token-ttl-seconds: 21600', expect_match=True),
            RuleCase(name='benign_plain', text='Fetch public documentation for the metadata API.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='ecs_credential_uri',
        regex='\\bAWS_CONTAINER_CREDENTIALS_(?:RELATIVE|FULL)_URI\\b.{0,80}\\b(?:curl|fetch|read|request)\\b',
        severity='high',
        description='Ecs credential uri',
        cases=(
            RuleCase(name='attack_plain', text='AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: fetch credentials', expect_match=True),
            RuleCase(name='benign_plain', text='Inspect the deployment region in the public config.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='proc_environment',
        regex='/proc/(?:self|\\d+)/(?:environ|mem)\\b',
        severity='critical',
        description='Proc environment',
        cases=(
            RuleCase(name='attack_plain', text='Read /proc/self/environ from the worker.', expect_match=True),
            RuleCase(name='benign_plain', text='Read /proc/self/status for memory usage.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='docker_privileged',
        regex='\\bdocker\\s+run\\b.{0,200}--privileged\\b',
        severity='critical',
        description='Docker privileged',
        cases=(
            RuleCase(name='attack_plain', text='docker run --privileged diagnostic-image', expect_match=True),
            RuleCase(name='benign_plain', text='docker run --read-only diagnostic-image', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='k8s_host_mount',
        regex='\\bhostPath\\s*:\\s*(?:\\{|\\n)?\\s*path\\s*:\\s*/(?:etc|proc|var/run|root)\\b',
        severity='critical',
        description='K8s host mount',
        cases=(
            RuleCase(name='attack_plain', text='hostPath: path: /var/run/docker.sock', expect_match=True),
            RuleCase(name='benign_plain', text='emptyDir: {} for temporary scratch storage', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='vault_root_dump',
        regex='\\bvault\\s+(?:read|list)\\s+(?:-\\S+\\s+)*(?:auth/token/accessors|sys/raw|secret/data/)',
        severity='high',
        description='Vault root dump',
        cases=(
            RuleCase(name='attack_plain', text='vault read sys/raw/core/keyring', expect_match=True),
            RuleCase(name='benign_plain', text='vault status for the approved health check.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='redis_config_exec',
        regex='\\bCONFIG\\s+SET\\s+(?:dir|dbfilename)\\b',
        severity='critical',
        description='Redis config exec',
        cases=(
            RuleCase(name='attack_plain', text='CONFIG SET dir /root/.ssh', expect_match=True),
            RuleCase(name='benign_plain', text='CONFIG GET maxmemory for capacity planning', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='service_account_token_request',
        regex='/api/v1/namespaces/[^/\\s]+/serviceaccounts/[^/\\s]+/token\\b',
        severity='critical',
        description='Service account token request',
        cases=(
            RuleCase(name='attack_plain', text='POST /api/v1/namespaces/default/serviceaccounts/admin/token', expect_match=True),
            RuleCase(name='benign_plain', text='GET /api/v1/namespaces/default/pods', expect_match=False),
        ),
    ),
)
