"""Repack the pinned upstream wheel with a tested security dependency fixes.

Only package metadata changes. Upstream executable code and licensing are preserved.
The local version prevents confusing this artifact with an unmodified PyPI release.
"""
import base64
import csv
import hashlib
import io
from pathlib import Path
import re
import urllib.request
from zipfile import ZipFile, ZipInfo, ZIP_STORED

UPSTREAM_URL = 'https://files.pythonhosted.org/packages/e8/aa/a1ef423def5e405455cca69e938b0961c36091f5ac69bc4d15809b93df29/mitmproxy-12.3.0-py3-none-any.whl'
UPSTREAM_SHA256 = '29fd9e934bad86a321ff345ec141f894dbcc1ec9e3bf5deffba9ac2ea9db3c61'
LOCAL_VERSION = '12.3.0+leakybucket.2'


def build():
    with urllib.request.urlopen(UPSTREAM_URL, timeout=60) as response:
        original = response.read(8_388_609)
    if len(original) > 8_388_608 or hashlib.sha256(original).hexdigest() != UPSTREAM_SHA256:
        raise ValueError('Upstream wheel digest mismatch')
    files = {}
    original_payload = {}
    old = 'mitmproxy-12.3.0.dist-info/'
    new = 'mitmproxy-' + LOCAL_VERSION + '.dist-info/'
    with ZipFile(io.BytesIO(original)) as source:
        for entry in source.namelist():
            if entry.endswith('/') or entry == old + 'RECORD':
                continue
            name = entry.replace(old, new, 1) if entry.startswith(old) else entry
            content = source.read(entry)
            if not entry.startswith(old):
                original_payload[entry] = content
            if entry == old + 'METADATA':
                content, versions = re.subn(rb'(?m)^Version: 12\.3\.0$',
                    ('Version: '+LOCAL_VERSION).encode(), content)
                content, dependencies = re.subn(rb'(?mi)^Requires-Dist: Brotli[^\r\n]*$',
                    b'Requires-Dist: Brotli>=1.2.1,<1.3', content)
                content, tornado_dependencies = re.subn(rb'(?mi)^Requires-Dist: tornado[^\r\n]*$',
                    b'Requires-Dist: tornado>=6.6,<6.7', content)
                if versions != 1 or dependencies != 1 or tornado_dependencies != 1:
                    raise ValueError('Unexpected upstream metadata; manual review required')
            files[name] = content
    record = io.StringIO(newline='')
    writer = csv.writer(record, lineterminator='\n')
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + digest, len(content)])
    writer.writerow([new+'RECORD', '', ''])
    files[new+'RECORD'] = record.getvalue().encode()
    directory = Path(__file__).resolve().parent.parent / '.tls-dependencies'
    directory.mkdir(exist_ok=True)
    wheel = directory / ('mitmproxy-'+LOCAL_VERSION+'-py3-none-any.whl')
    with ZipFile(wheel, 'w', compression=ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            info = ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = ZIP_STORED
            archive.writestr(info, content)
    with ZipFile(wheel) as repacked:
        for name, content in original_payload.items():
            if repacked.read(name) != content:
                raise ValueError('Executable source changed during repackaging')
    print(wheel)
    print('sha256:' + hashlib.sha256(wheel.read_bytes()).hexdigest())
    return wheel


if __name__ == '__main__':
    build()
