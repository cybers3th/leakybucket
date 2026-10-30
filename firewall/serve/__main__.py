"""Environment-configured authenticated serving process."""
from pathlib import Path
import os

from firewall import Gateway
from firewall.core.events import Actor
from firewall.enforcement.output_validators import OutputConstraints
from firewall.ml.semantic import LocalSemanticClassifier
from firewall.serve.async_gateway import AsyncGateway
from firewall.serve.auth import StaticTokenAuthenticator
from firewall.serve.proxy import build_openai_app
from firewall.serve.signed_audit import SignedAuditLog


def _required(name):
    value = os.environ.get(name, '')
    if not value:
        raise ValueError(f'{name} is required')
    return value


def _secret(name):
    return Path(_required(name)).read_bytes()


def create_app():
    upstream = _required('LB_UPSTREAM_URL')
    service_token = _secret('LB_SERVICE_TOKEN_FILE').decode('ascii').strip()
    actor = Actor(user_id=_required('LB_USER'), tenant=_required('LB_TENANT'),
                  session_id=_required('LB_SESSION_ID'), authenticated=True)
    resolver = StaticTokenAuthenticator({service_token: actor})
    classifier = None
    endpoint = os.environ.get('LB_CLASSIFIER_URL')
    model = os.environ.get('LB_CLASSIFIER_MODEL')
    if not endpoint and os.environ.get("LB_ALLOW_RULES_ONLY") != "true":
        raise ValueError("Configure semantic inspection or explicitly set LB_ALLOW_RULES_ONLY=true")
    if bool(endpoint) != bool(model):
        raise ValueError('Configure both LB_CLASSIFIER_URL and LB_CLASSIFIER_MODEL')
    timeout = float(os.environ.get('LB_INSPECTION_TIMEOUT_SECONDS', '10'))
    if endpoint:
        classifier_key = _secret("LB_CLASSIFIER_TOKEN_FILE").decode("ascii").strip()
        classifier = LocalSemanticClassifier(endpoint, model, inspection_timeout=timeout, api_key=classifier_key)
    literals = ()
    if os.environ.get('LB_PROTECTED_LITERALS_FILE'):
        literals = tuple(line for line in Path(os.environ['LB_PROTECTED_LITERALS_FILE']).read_text().splitlines() if line)
    upstream_auth = ''
    if os.environ.get('LB_UPSTREAM_TOKEN_FILE'):
        upstream_auth = 'Bearer ' + _secret('LB_UPSTREAM_TOKEN_FILE').decode('ascii').strip()
    audit = SignedAuditLog(path=_required('LB_AUDIT_PATH'), key=_secret('LB_AUDIT_KEY_FILE'))
    gateway = Gateway(injection_classifier=classifier, inspection_timeout=timeout,
                      output_constraints=OutputConstraints(forbidden_literals=literals), audit_log=audit)
    asynchronous = AsyncGateway(gateway, inspection_timeout=timeout)
    try:
        builder = build_openai_app
        options = {}
        if os.environ.get('LB_POLICY_PATH'):
            from firewall.observe.app import build_observed_app
            builder = build_observed_app
            slack_url = None
            if os.environ.get('LB_SLACK_WEBHOOK_FILE'):
                slack_url = _secret('LB_SLACK_WEBHOOK_FILE').decode('ascii').strip()
            options = dict(policy_path=os.environ['LB_POLICY_PATH'],
                           database=os.environ.get('LB_TRACE_DATABASE', 'traces.sqlite3'),
                           capture_content=os.environ.get('LB_CAPTURE_CONTENT') == 'true', slack_url=slack_url)
        return builder(**options, gateway=asynchronous, actor_resolver=resolver,
            upstream_base_url=upstream, upstream_authorization=upstream_auth)
    except Exception:
        audit.close()
        asynchronous._executor.shutdown(wait=False, cancel_futures=True)
        raise


def main():
    from aiohttp import web
    web.run_app(create_app(), host=os.environ.get('LB_BIND', '127.0.0.1'),
                port=int(os.environ.get('LB_PORT', '8080')), access_log=None,
                shutdown_timeout=15)


if __name__ == '__main__':
    main()
