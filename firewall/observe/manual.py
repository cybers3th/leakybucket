"""Bundled terminal manual and per-user man-page installation."""
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.resources import as_file, files
from pathlib import Path

_HEADER = '.\\" Generated from leakybucket.txt; managed by leakybucket man --install.\n'


def manual_text():
    return files('firewall.observe').joinpath('man/leakybucket.txt').read_text(encoding='utf-8')


def roff_page(text):
    lines = [_HEADER.rstrip(), '.TH LEAKYBUCKET 1 "October 2026" "LeakyBucket 1.1" "User Commands"', '.nh']
    body = False
    for line in text.splitlines():
        if line and line == line.upper() and not line.startswith(' '):
            if body:
                lines.append('.fi')
            lines.extend(('.SH ' + line, '.nf'))
            body = True
            continue
        escaped = line.removeprefix('    ').replace('\\', r'\e').replace('-', r'\-')
        if escaped.startswith(('.', "'")):
            escaped = r'\&' + escaped
        lines.append(escaped)
    if body:
        lines.append('.fi')
    return '\n'.join(lines) + '\n'


def show_manual(*, plain=False):
    viewer = shutil.which('man')
    if plain or not sys.stdout.isatty() or viewer is None:
        print(manual_text(), end='')
        return
    resource = files('firewall.observe').joinpath('man/leakybucket.1')
    with as_file(resource) as page:
        result = subprocess.run([viewer, '-l', str(page)], check=False)
    if result.returncode != 0:
        print(manual_text(), end='')


def install_manual():
    base = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share').expanduser().absolute()
    directory = base / 'man/man1'
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / 'leakybucket.1'
    content = files('firewall.observe').joinpath('man/leakybucket.1').read_text(encoding='utf-8')
    if destination.exists() and not destination.read_text(encoding='utf-8').startswith(_HEADER):
        raise ValueError('An unmanaged leakybucket.1 already exists; refusing to overwrite it')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        temporary.replace(destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
