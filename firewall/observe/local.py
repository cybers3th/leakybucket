"""Persistent local defaults independent of the caller's working directory."""
import json
import os
from pathlib import Path

DEFAULT_POLICY = 'version: 1\nrules: []\npricing: {}\nalerts:\n  latency_ms: 5000\n  cost_usd: 0.10\n'


def state_directory():
    return Path(os.environ.get('LB_STATE_DIR') or Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'leakybucket').expanduser().absolute()


def config_directory():
    return Path(os.environ.get('LB_CONFIG_DIR') or Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'leakybucket').expanduser().absolute()


def default_policy():
    configured = os.environ.get('LB_POLICY_PATH')
    if configured:
        return Path(configured).expanduser().absolute()
    directory = config_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / 'policy.yaml'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path
    with os.fdopen(fd, 'w') as stream:
        stream.write(DEFAULT_POLICY)
    return path


def resolve_policy(value):
    if value is None:
        return default_policy()
    path = Path(value).expanduser()
    if path.exists() or path.is_absolute():
        return path.absolute()
    if path == Path('deploy/policy.yaml'):
        source = Path(__file__).resolve().parents[2] / 'deploy/policy.yaml'
        if source.is_file():
            return source
    return path.absolute()


def connection(directory):
    path = directory / 'connection.json'
    if not path.exists():
        return {}
    if path.stat().st_size > 8192:
        raise ValueError('Local connection file is too large')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) - {'url', 'token_file', 'policy_path', 'upstream_url', 'inspection_mode',
                                                        'classifier_url', 'classifier_model', 'classifier_token_file',
                                                        'inspection_timeout_seconds'} or any(not isinstance(v, str) for v in data.values()):
        raise ValueError('Invalid local connection file')
    if data.get('inspection_mode', 'rules') not in ('rules', 'semantic_and_rules'):
        raise ValueError('Invalid saved inspection mode')
    return data


def inspection_settings(saved, *, rules_only=False):
    fields = {'classifier_url': 'LB_CLASSIFIER_URL', 'classifier_model': 'LB_CLASSIFIER_MODEL',
              'classifier_token_file': 'LB_CLASSIFIER_TOKEN_FILE',
              'inspection_timeout_seconds': 'LB_INSPECTION_TIMEOUT_SECONDS'}
    if rules_only:
        for key in ('LB_CLASSIFIER_URL', 'LB_CLASSIFIER_MODEL', 'LB_CLASSIFIER_TOKEN_FILE'):
            os.environ.pop(key, None)
        os.environ['LB_ALLOW_RULES_ONLY'] = 'true'
        return {'inspection_mode': 'rules'}
    selected = {key: os.environ.get(env) or saved.get(key) for key, env in fields.items()}
    required = ('classifier_url', 'classifier_model', 'classifier_token_file')
    semantic = saved.get('inspection_mode') == 'semantic_and_rules' or any(selected[key] for key in required)
    if not semantic and saved and 'inspection_mode' not in saved:
        raise ValueError('This older profile has no saved inspection mode. Reapply the original classifier settings, or explicitly use --rules-only to select rules-only inspection.')
    if not semantic:
        os.environ.setdefault('LB_ALLOW_RULES_ONLY', 'true')
        return {'inspection_mode': 'rules'}
    if not all(selected[key] for key in required):
        raise ValueError('Semantic inspection requires a classifier URL, model and credential-file reference. Restore these settings or explicitly use --rules-only.')
    token_file = Path(selected['classifier_token_file']).expanduser().absolute()
    if not token_file.is_file():
        raise ValueError('The saved semantic classifier credential file is missing. Restore it or explicitly use --rules-only.')
    selected['classifier_token_file'] = str(token_file)
    for key, value in selected.items():
        if value is not None:
            os.environ[fields[key]] = value
    os.environ['LB_ALLOW_RULES_ONLY'] = 'false'
    return {'inspection_mode': 'semantic_and_rules', **{key: value for key, value in selected.items() if value is not None}}


def save_connection(directory, url, token_file, policy_path=None, upstream_url=None, inspection=None):
    path = directory / 'connection.json'
    temporary = directory / 'connection.json.new'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        data = {'url': url, 'token_file': str(token_file)}
        if policy_path is not None:
            data['policy_path'] = str(policy_path)
        if upstream_url is not None:
            data['upstream_url'] = upstream_url
        if inspection is not None:
            data.update(inspection)
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
