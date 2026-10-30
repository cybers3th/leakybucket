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
    if not isinstance(data, dict) or set(data) - {'url', 'token_file', 'policy_path', 'upstream_url'} or any(not isinstance(v, str) for v in data.values()):
        raise ValueError('Invalid local connection file')
    return data


def save_connection(directory, url, token_file, policy_path=None, upstream_url=None):
    path = directory / 'connection.json'
    temporary = directory / 'connection.json.new'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        data = {'url': url, 'token_file': str(token_file)}
        if policy_path is not None:
            data['policy_path'] = str(policy_path)
        if upstream_url is not None:
            data['upstream_url'] = upstream_url
        json.dump(data, stream)
    temporary.replace(path)
