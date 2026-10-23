#!/usr/bin/env python3
"""Add guided single-node/HA setup and optional PostgreSQL HA dependencies to a verified application tar."""
import argparse
import email.parser
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

from install import INSTALLER_VERSION

HERE = Path(__file__).resolve().parent
ETCD_VERSION = 'v3.6.7'
ETCD_SHA256 = 'cf8af880c5a01ee5363cefa14a3e0cb7e5308dcf4ed17a6973099c9a7aee5a9a'
FILES = ('install.py', 'build_bundle.py', 'cluster.py', 'cluster_node.py', 'build_cluster.py',
    'repair-litellm-ca.sh', 'reset-litellm.sh', 'README.md', 'GUIDE.md', 'RUNBOOK.md', 'CLUSTER.md', 'CHANGELOG.md', 'UPDATE.md')


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def payload(out):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or sys.version_info[:2] != (3, 12):
        raise ValueError('Build the PostgreSQL payload on connected Linux x86_64 with CPython 3.12 and pip')
    out.mkdir(parents=True, exist_ok=False)
    wheels = out / 'wheels'
    wheels.mkdir()
    # These two pure-Python packages are published as sdists. All native
    # dependencies must have compatible upstream wheels.
    subprocess.run([sys.executable, '-m', 'pip', 'wheel', '--index-url', 'https://pypi.org/simple',
        '--wheel-dir', str(wheels), '--only-binary=:all:', '--no-binary=python-etcd,ydiff',
        'patroni==4.1.5', 'psycopg[binary]', 'python-etcd==0.4.5', 'ydiff==1.3.0'], check=True)
    rows = []
    for wheel in sorted(wheels.glob('*.whl')):
        import build_bundle
        if not build_bundle.wheel_score(wheel.name, '3.12', 'amd64'):
            raise ValueError('Wheel is not compatible with RHEL 9/CPython 3.12: ' + wheel.name)
        with zipfile.ZipFile(wheel) as archive:
            metadata = [n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
            if len(metadata) != 1:
                raise ValueError('Invalid wheel metadata: ' + wheel.name)
            data = email.parser.Parser().parsestr(archive.read(metadata[0]).decode())
        rows.append(data['Name'] + '==' + data['Version'] + ' --hash=sha256:' + sha(wheel))
    (out / 'requirements.txt').write_text('\n'.join(rows) + '\n')
    url = 'https://github.com/etcd-io/etcd/releases/download/' + ETCD_VERSION + '/etcd-' + ETCD_VERSION + '-linux-amd64.tar.gz'
    request = urllib.request.Request(url, headers={'User-Agent': 'litellm-cluster-bundler'})
    with urllib.request.urlopen(request, timeout=120) as response, open(out / 'etcd.tar.gz', 'wb') as target:
        shutil.copyfileobj(response, target)
    if sha(out / 'etcd.tar.gz') != ETCD_SHA256:
        raise ValueError('Official etcd archive does not match its pinned SHA-256')
    manifest = {'format': 1, 'platform': 'linux/x86_64', 'python': '3.12', 'etcd_version': ETCD_VERSION,
        'etcd_sha256': ETCD_SHA256, 'etcd_source': url, 'patroni': '4.1.5',
        'wheels': sorted(w.name for w in wheels.glob('*.whl')),
        'note': 'python-etcd 0.4.5 and ydiff 1.3.0 built from PyPI sdists; other packages use upstream wheels'}
    (out / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    files = sorted(x for x in out.rglob('*') if x.is_file())
    (out / 'SHA256SUMS').write_text(''.join(sha(x) + '  ' + x.relative_to(out).as_posix() + '\n' for x in files))


def installer_bytes():
    import build_bundle as b
    return b.embed_builder((HERE / 'install.py').read_text()).encode()


def combine(source, destination, infrastructure):
    replacements = {name: (HERE / name).read_bytes() for name in FILES}
    replacements['install.py'] = installer_bytes()
    replacements['PART.json'] = (json.dumps({'format': 1, 'part': 'installer', 'name': 'part-installer',
        'installer_version': INSTALLER_VERSION, 'files': list(FILES)}, indent=2) + '\n').encode()
    replacements['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
        for name, data in sorted(replacements.items())).encode()
    partial = destination.with_name(destination.name + '.partial')
    try:
        with tarfile.open(source, 'r:*') as old, tarfile.open(partial, 'w') as new:
            members = old.getmembers()
            roots = {m.name.split('/')[0] for m in members if m.name.strip('./')}
            if len(roots) != 1:
                raise ValueError('Expected one bundle root')
            root = next(iter(roots))
            for m in members:
                path = Path(m.name)
                if path.is_absolute() or '..' in path.parts or m.issym() or m.islnk():
                    raise ValueError('Unsafe source archive member: ' + m.name)
                rel = '/'.join(path.parts[1:])
                if rel in replacements or rel == 'parts/part-installer' or rel.startswith('parts/part-installer/'):
                    continue
                if rel == 'infrastructure' or rel.startswith('infrastructure/'):
                    continue
                if rel == 'BUNDLE.json':
                    meta = json.load(old.extractfile(m))
                    meta.update(cluster_installer=INSTALLER_VERSION, managed_postgresql_payload=infrastructure is not None)
                    body = (json.dumps(meta, indent=2) + '\n').encode()
                    entry = tarfile.TarInfo(m.name)
                    entry.size, entry.mode = len(body), 0o644
                    new.addfile(entry, io.BytesIO(body))
                else:
                    new.addfile(m, old.extractfile(m) if m.isfile() else None)
            for name, body in replacements.items():
                entry = tarfile.TarInfo(root + '/' + name)
                entry.size, entry.mode = len(body), 0o644
                new.addfile(entry, io.BytesIO(body))
            if infrastructure:
                new.add(str(infrastructure), arcname=root + '/infrastructure')
        os.replace(partial, destination)
        destination.with_name(destination.name + '.sha256').write_text(sha(destination) + '  ' + destination.name + '\n')
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True, help='Verified existing application tar')
    p.add_argument('--out', type=Path, required=True, help='New cluster-enabled tar')
    p.add_argument('--without-managed-postgresql', action='store_true', help='Omit Patroni/etcd; single-node local PostgreSQL and external services remain available')
    p.add_argument('--infrastructure', type=Path, help='Reuse a verified offline infrastructure directory')
    a = p.parse_args()
    try:
        if a.bundle.resolve() == a.out.resolve():
            raise ValueError('Output must differ from source')
        sidecar = a.bundle.with_name(a.bundle.name + '.sha256')
        if not sidecar.is_file() or sha(a.bundle) != sidecar.read_text().split()[0]:
            raise ValueError('Source application bundle needs its matching SHA-256 sidecar')
        with tempfile.TemporaryDirectory(prefix='litellm-cluster-build-') as temp:
            infra = None
            if not a.without_managed_postgresql:
                infra = a.infrastructure
                if infra:
                    from cluster_node import verify_infrastructure
                    verify_infrastructure(infra.resolve())
                else:
                    infra = Path(temp) / 'infrastructure'
                    payload(infra)
            a.out.parent.mkdir(parents=True, exist_ok=True)
            combine(a.bundle, a.out, infra)
        print('Created ' + str(a.out) + ' and its SHA-256 sidecar')
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
