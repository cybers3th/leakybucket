"""Operations commands for the local trace service."""
import argparse
import asyncio
import json
import os
import secrets
import sys
import urllib.parse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def bootstrap(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_mode & 0o022:
        raise ValueError('State directory must not be a symlink or writable by other users')
    for name in ('service-token', 'audit-key'):
        path = directory / name
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise ValueError('Existing secrets must be private regular files')
            continue
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(secrets.token_urlsafe(48) + '\n')
    return directory


def main(argv=None):
    from .local import connection, resolve_policy, save_connection, state_directory

    parser = argparse.ArgumentParser(prog='leakybucket')
    try:
        installed_version = version('leakybucket-firewall')
    except PackageNotFoundError:
        installed_version = 'source checkout'
    parser.add_argument('--version', action='version', version='LeakyBucket ' + installed_version)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('start', help='Initialize and start the local service')
    start.add_argument('--policy', default=os.environ.get('LB_POLICY_PATH'))
    start.add_argument('--bootstrap-dir', '--state-dir', dest='bootstrap_dir', help='Override the persistent state directory')
    start.add_argument('--foreground', action='store_true', help='Stay in the foreground (containers and service managers)')
    start.add_argument('--upstream-url', help='OpenAI-compatible provider base URL')
    stop = commands.add_parser('stop', help='Stop the local background service')
    stop.add_argument('--state-dir', default=None)
    policy = commands.add_parser('policy', help='Validate a policy without starting the service')
    actions = policy.add_subparsers(dest='action', required=True)
    validate = actions.add_parser('validate')
    validate.add_argument('path', nargs='?', help='Default: persistent user policy')
    for name in ('traces', 'trace', 'watch', 'status', 'doctor', 'chat'):
        command = commands.add_parser(name, help={'traces': 'List recent requests', 'trace': 'Inspect a request and its spans',
                                                  'watch': 'Watch completed requests live', 'status': 'Show service health',
                                                  'doctor': 'Diagnose service, policy and model-provider readiness',
                                                  'chat': 'Send a prompt through the firewall'}[name])
        command.add_argument('--state-dir')
        command.add_argument('--url', default=os.environ.get('LB_URL'))
        command.add_argument('--token-file', default=os.environ.get('LB_SERVICE_TOKEN_FILE'))
        command.add_argument('--ca-file', default=os.environ.get('LB_CA_FILE'))
        command.add_argument('--json', action='store_true', help='Emit machine-readable JSON')
        if name == 'chat':
            command.add_argument('prompt', nargs='?', help='Prompt text; reads stdin when piped')
            command.add_argument('--model', required=True)
            command.add_argument('--max-tokens', type=int, default=256, help='Response token cap (1–4096, default 256)')
        if name == 'trace':
            command.add_argument('id', nargs='?', default='latest')
        if name == 'watch':
            command.add_argument('--count', type=int, help='Stop after this many completed requests')
        if name == 'traces':
            for option in ('model', 'since', 'until', 'min-cost', 'limit', 'offset'):
                command.add_argument('--' + option)
    args = parser.parse_args(argv)
    try:
        from .client import TraceClient, print_trace, safe, summary

        if args.command == 'stop':
            from .service import stop as stop_service
            stop_service(Path(args.state_dir).expanduser().absolute() if args.state_dir else state_directory())
            return
        if args.command in ('traces', 'trace', 'watch', 'status', 'doctor', 'chat'):
            directory = Path(args.state_dir).expanduser().absolute() if args.state_dir else state_directory()
            saved = connection(directory)
            if args.command == 'doctor':
                from .doctor import diagnose
                report = diagnose(directory, saved, url=args.url, token_file=args.token_file, ca_file=args.ca_file)
                if args.json:
                    print(json.dumps(report, ensure_ascii=True))
                else:
                    print('Service: ' + safe(report['service']['state']))
                    print('Inspection: ' + safe(report['service'].get('inspection_mode', 'unknown until the service starts')))
                    print('Policy: ' + safe(report['policy']['state']))
                    print('Provider: ' + safe(report['provider']['state']) + ' (' + safe(report['provider']['url']) + ')')
                    for model in report['provider']['models']:
                        print('  Model: ' + safe(model))
                    for step in report['next_steps']:
                        print('Next: ' + safe(step))
                    print('Model discovery does not guarantee a successful chat request.')
                if not report['ready']:
                    parser.exit(1)
                return
            token_file = Path(args.token_file or saved.get('token_file') or directory / 'service-token')
            if not token_file.exists() and not args.token_file:
                raise ValueError('Local service is not initialized. Run leakybucket start first.')
            client = TraceClient(args.url or saved.get('url') or 'http://127.0.0.1:8080', token_file, args.ca_file)
            if args.command == 'chat':
                prompt = args.prompt
                if prompt is None:
                    if sys.stdin.isatty():
                        raise ValueError('Provide a prompt or pipe text into leakybucket chat --model MODEL.')
                    prompt = sys.stdin.read(50001)
                if not prompt.strip() or len(prompt) > 50000 or not 1 <= len(args.model) <= 256:
                    raise ValueError('Provide a nonempty prompt up to 50000 characters and a model name up to 256 characters.')
                if not 1 <= args.max_tokens <= 4096:
                    raise ValueError('Max tokens must be between 1 and 4096')
                result = client.chat(args.model, prompt, args.max_tokens)
                if args.json:
                    print(json.dumps({'trace_id': client.last_trace_id, 'response': result}, ensure_ascii=True))
                else:
                    for choice in result['choices']:
                        for line in (choice['message'].get('content') or '').splitlines():
                            print(safe(line, 50000))
                    if client.last_trace_id:
                        print('Trace: ' + safe(client.last_trace_id))
            elif args.command == 'watch':
                if args.count is not None and args.count < 1:
                    raise ValueError('Count must be positive')
                asyncio.run(client.watch(as_json=args.json, count=args.count))
            elif args.command == 'trace':
                if args.id == 'TRACE_ID':
                    raise ValueError('TRACE_ID is a placeholder. Run leakybucket trace for the latest request, or use an ID from leakybucket traces.')
                trace_id = args.id
                if trace_id == 'latest':
                    rows = client.get('/api/traces?limit=1')['traces']
                    if not rows:
                        print('No traces yet. Send a model request through the proxy first.')
                        return
                    trace_id = rows[0]['id']
                if not 1 <= len(trace_id) <= 128:
                    raise ValueError('Invalid trace ID')
                print_trace(client.get('/api/traces/' + urllib.parse.quote(trace_id, safe='')), args.json)
            elif args.command == 'status':
                result = client.get('/api/status')
                if args.json:
                    print(json.dumps(result, ensure_ascii=True))
                else:
                    print('LeakyBucket is running at ' + safe(client.base_url))
                    for key, value in result.items():
                        print(safe(key.replace('_', ' ')) + ': ' + safe(value))
            else:
                filters = {key: getattr(args, key) for key in ('model', 'since', 'until', 'min_cost', 'limit', 'offset')
                           if getattr(args, key) is not None}
                result = client.get('/api/traces?' + urllib.parse.urlencode(filters))
                if args.json:
                    print(json.dumps(result, ensure_ascii=True))
                elif not result['traces']:
                    print('No traces match these filters. Send a model request through the proxy to create one.')
                else:
                    print(f"{'TRACE':32}  {'MODEL':28}  HTTP        LATENCY     TOKENS  COST")
                    for trace in result['traces']:
                        print(summary(trace))
            return
        from .policy import load_policy
        directory = Path(args.bootstrap_dir).expanduser().absolute() if args.command == 'start' and args.bootstrap_dir else state_directory()
        saved = connection(directory)
        requested = args.path if args.command == 'policy' else args.policy
        path = resolve_policy(requested or os.environ.get('LB_POLICY_PATH') or saved.get('policy_path'))
        compiled = load_policy(path)
        if args.command == 'policy':
            print(f'Valid policy: {len(compiled.rules)} rules; sha256={compiled.digest}')
            print('Policy: ' + safe(path))
            return
        os.environ['LB_POLICY_PATH'] = str(path)
        directory = bootstrap(Path(args.bootstrap_dir).expanduser().absolute() if args.bootstrap_dir else state_directory())
        for key, value in {
            'LB_SERVICE_TOKEN_FILE': directory / 'service-token',
            'LB_AUDIT_KEY_FILE': directory / 'audit-key',
            'LB_AUDIT_PATH': directory / 'audit.jsonl',
            'LB_TRACE_DATABASE': directory / 'traces.sqlite3',
            'LB_USER': 'operator', 'LB_TENANT': 'local', 'LB_SESSION_ID': 'local-service',
        }.items():
            os.environ.setdefault(key, str(value))
        if args.upstream_url:
            os.environ['LB_UPSTREAM_URL'] = args.upstream_url
        os.environ.setdefault('LB_UPSTREAM_URL', saved.get('upstream_url', 'http://127.0.0.1:11434/v1'))
        if not os.environ.get('LB_CLASSIFIER_URL'):
            os.environ.setdefault('LB_ALLOW_RULES_ONLY', 'true')
        if (directory / 'upstream-token').is_file():
            os.environ.setdefault('LB_UPSTREAM_TOKEN_FILE', str(directory / 'upstream-token'))
        port = int(os.environ.get('LB_PORT', '8080'))
        if not 1 <= port <= 65535:
            raise ValueError('LB_PORT must be between 1 and 65535')
        bind = os.environ.get('LB_BIND', '127.0.0.1')
        if not args.foreground and bind not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Local background mode requires a loopback bind; use --foreground for managed deployments')
        url = f'http://[::1]:{port}' if bind == '::1' else f'http://127.0.0.1:{port}'
        if args.foreground:
            save_connection(directory, url, os.environ['LB_SERVICE_TOKEN_FILE'], path, os.environ['LB_UPSTREAM_URL'])
            from firewall.serve.__main__ import main as serve
            serve()
        else:
            from .service import start as start_service
            if start_service(directory, url, os.environ['LB_SERVICE_TOKEN_FILE']):
                save_connection(directory, url, os.environ['LB_SERVICE_TOKEN_FILE'], path, os.environ['LB_UPSTREAM_URL'])
            elif (args.upstream_url and args.upstream_url != saved.get('upstream_url') or args.policy and str(path) != saved.get('policy_path')):
                raise ValueError('Stop the running service with leakybucket stop before applying changed provider or policy settings.')
    except FileNotFoundError as exc:
        missing = ascii(str(Path(exc.filename).absolute())) if exc.filename else 'a required file'
        parser.exit(2, f'File not found: {missing}.\nUse leakybucket policy validate for the default policy, or supply an absolute path.\n')
    except KeyboardInterrupt:
        return
    except (ValueError, OSError, ImportError, RuntimeError) as exc:
        from .client import safe
        parser.exit(2, f'Error: {safe(str(exc), 600)}\n')
