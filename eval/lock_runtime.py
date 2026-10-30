"""Freeze installed runtime dependencies and published PyPI artifact hashes.

Run in the tested release environment. This records its active dependency closure;
it is not a cross-platform resolver. Development tools are excluded.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.metadata as metadata
from email.parser import BytesParser
import hashlib
from zipfile import ZipFile
import json
from pathlib import Path
import platform
import sys
import tomllib
import urllib.request

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def installed_closure(requirements):
    queue = list(requirements)
    visited = {}
    while queue:
        requirement = queue.pop()
        name = canonicalize_name(requirement.name)
        version = metadata.version(name)
        if not requirement.specifier.contains(version, prereleases=True):
            raise ValueError(f'Installed {name} does not satisfy {requirement.specifier}')
        extras = set(requirement.extras)
        if name in visited and extras <= visited[name]:
            continue
        visited.setdefault(name, set()).update(extras)
        for value in metadata.distribution(name).requires or []:
            child = Requirement(value)
            if child.marker and not any(child.marker.evaluate({'extra': extra}) for extra in extras | {''}):
                continue
            queue.append(child)
    return {name: metadata.version(name) for name in sorted(visited)}


def artifact_hashes(item):
    name, version = item
    url = f'https://pypi.org/pypi/{name}/{version}/json'
    with urllib.request.urlopen(url, timeout=30) as response:
        release = json.loads(response.read(4_194_305))
    if canonicalize_name(release['info']['name']) != name or release['info']['version'] != version:
        raise ValueError('Package metadata identity mismatch')
    hashes = sorted({artifact['digests']['sha256'] for artifact in release['urls']})
    if not hashes or any(len(value) != 64 or any(c not in '0123456789abcdef' for c in value) for value in hashes):
        raise ValueError('Missing or malformed artifact hashes')
    return name, version, hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extra', action='append', default=[])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--wheel', action='append', default=[], type=Path)
    parser.add_argument('--audit-output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    project = tomllib.loads((root/'pyproject.toml').read_text())['project']
    required = list(project['dependencies'])
    for extra in args.extra:
        required.extend(project['optional-dependencies'][extra])
    requirements = [Requirement(value) for value in required]
    requirements = [value for value in requirements if not value.marker or value.marker.evaluate()]
    closure = installed_closure(requirements)
    local = {}
    for path in args.wheel:
        with ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
            if len(names) != 1:
                raise ValueError('Ambiguous local wheel metadata')
            package = BytesParser().parsebytes(archive.read(names[0]))
        name = canonicalize_name(package['Name'])
        if closure.get(name) != package['Version']:
            raise ValueError('Local wheel does not match the tested installed version')
        local[name] = (path.resolve().relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
    with ThreadPoolExecutor(max_workers=8) as executor:
        artifacts = list(executor.map(artifact_hashes, ((name, version) for name, version in closure.items() if name not in local)))
    artifacts.extend((name, closure[name], [digest]) for name, (_, digest) in local.items())
    artifacts.sort()
    lines = [f'# Tested runtime: CPython {sys.version_info.major}.{sys.version_info.minor} / {platform.system()}.',
             '# Frozen installed dependency closure; hashes from PyPI HTTPS metadata.',
             '# Regenerate in the reviewed release environment with eval.lock_runtime.', '']
    for name, version, hashes in artifacts:
        pin = './' + local[name][0] if name in local else name + '==' + version
        lines.append(pin + ' \\')
        lines.extend('    --hash=sha256:' + value + (' \\' if index < len(hashes)-1 else '')
                     for index, value in enumerate(hashes))
        lines.append('')
    args.output.write_text('\n'.join(lines))
    if args.audit_output:
        audit = ['# Audit inventory only; do not install this file.',
                 '# The local mitmproxy wheel changes dependency metadata only; audit its identical upstream code.']
        for name, version in closure.items():
            if name in local:
                if name != 'mitmproxy' or version != '12.3.0+leakybucket.2':
                    raise ValueError('Unknown local code provenance')
                version = '12.3.0'
            audit.append(name + '==' + version)
        args.audit_output.write_text('\n'.join(audit) + '\n')
    print(f'Pinned {len(closure)} runtime dependencies')


if __name__ == '__main__':
    main()
