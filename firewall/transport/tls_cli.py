"""Explicit TLS inspection proxy with operator-provisioned scope and CA."""
import argparse
import asyncio
import os
from pathlib import Path
import stat

from firewall import Gateway
from firewall.enforcement.output_validators import OutputConstraints
from firewall.ml.semantic import LocalSemanticClassifier
from firewall.serve.async_gateway import AsyncGateway
from firewall.serve.signed_audit import SignedAuditLog
from firewall.transport.tls_gateway import CustomProvider, TLSInspectionGateway, ensure_tls_runtime
from firewall.util.json import strict_json_loads


def private_file(path):
    source = Path(path)
    if not source.is_file() or source.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError('CA keys and credentials must be private files with mode 0600 or stricter')
    if source.stat().st_size > 1_048_576:
        raise ValueError('Secret file exceeds bounds')
    return source.read_bytes()


def load_config(path):
    source = Path(path)
    if source.stat().st_size > 65_536:
        raise ValueError('Proxy configuration exceeds bounds')
    config = strict_json_loads(source.read_bytes())
    required = {'providers', 'tenant', 'proxy_username', 'proxy_password_file', 'ca_dir', 'audit_path', 'audit_key_file'}
    optional = {'listen_host', 'listen_port', 'rules_only', 'semantic', 'protected_literals_file', 'upstream_ca_file'}
    if not isinstance(config, dict) or not required <= set(config) or set(config) - required - optional:
        raise ValueError('Missing or unknown TLS proxy configuration fields')
    providers = []
    for item in config['providers']:
        if not isinstance(item, dict) or set(item) - {'host', 'paths', 'ports', 'approved_ips'}:
            raise ValueError('Invalid custom provider configuration')
        providers.append(CustomProvider(item['host'], frozenset(item['paths']),
            frozenset(item.get('ports', [443])), frozenset(item.get('approved_ips', []))))
    if not providers:
        raise ValueError('At least one exact provider hostname and path is required')
    private_file(Path(config['ca_dir']) / 'mitmproxy-ca.pem')
    password = private_file(config['proxy_password_file']).decode('ascii').strip()
    if len(password) < 32 or not password.isascii() or any(c.isspace() for c in password):
        raise ValueError('Provision a random proxy password of at least 32 ASCII characters')
    username = config['proxy_username']
    if not isinstance(username, str) or not username or any(c in username for c in ':\r\n'):
        raise ValueError('Invalid proxy username')
    if not config.get('semantic') and config.get('rules_only') is not True:
        raise ValueError('Configure semantic classification or explicitly select rules_only')
    port = config.get('listen_port', 8081)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid listen port')
    # Remote deployment requires a separately authenticated, encrypted ingress.
    if config.get('listen_host', '127.0.0.1') not in {'127.0.0.1', '::1'}:
        raise ValueError('The explicit proxy launcher binds only to loopback')
    return config, providers, password


async def serve(path):
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster
    ensure_tls_runtime()
    config, providers, password = load_config(path)
    classifier = None
    if semantic := config.get('semantic'):
        classifier = LocalSemanticClassifier(semantic['endpoint'], semantic['model'],
            api_key=private_file(semantic['token_file']).decode('ascii').strip())
    literals = ()
    if file := config.get('protected_literals_file'):
        literals = tuple(line for line in private_file(file).decode().splitlines() if line)
    audit = SignedAuditLog(path=config['audit_path'], key=private_file(config['audit_key_file']))
    gateway = AsyncGateway(Gateway(injection_classifier=classifier, audit_log=audit,
        output_constraints=OutputConstraints(forbidden_literals=literals)))
    master = None
    try:
        opts = options.Options(confdir=config['ca_dir'], listen_host=config.get('listen_host', '127.0.0.1'),
            listen_port=config.get('listen_port', 8081), ssl_insecure=False, upstream_cert=False,
            rawtcp=False, websocket=False, http3=False)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        opts.update(connection_strategy='lazy', proxyauth=config['proxy_username'] + ':' + password,
            body_size_limit='256k', stream_large_bodies=None, tcp_timeout=30,
            tls_version_client_min='TLS1_2', tls_version_server_min='TLS1_2',
            validate_inbound_headers=True)
        if config.get('upstream_ca_file'):
            opts.update(ssl_verify_upstream_trusted_ca=config['upstream_ca_file'])
        master.addons.add(TLSInspectionGateway(providers, gateway, config['tenant'], config['proxy_username']))
        await master.run()
    finally:
        if master:
            master.shutdown()
        await gateway.close()


def main():
    parser = argparse.ArgumentParser(description='Scoped custom-JSON TLS inspection gateway')
    commands = parser.add_subparsers(dest='command', required=True)
    initialize = commands.add_parser('init-ca', help='Generate an isolated interception CA; does not install trust')
    initialize.add_argument('directory', type=Path)
    run = commands.add_parser('run', help='Run using an operator-provisioned configuration')
    run.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'init-ca':
        from mitmproxy.certs import CertStore
        args.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        previous = os.umask(0o077)
        try:
            CertStore.create_store(args.directory, 'mitmproxy', 3072)
        finally:
            os.umask(previous)
        print(args.directory / 'mitmproxy-ca-cert.pem')
    else:
        asyncio.run(serve(args.config))


if __name__ == '__main__':
    main()
