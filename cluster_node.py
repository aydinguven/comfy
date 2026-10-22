#!/usr/bin/env python3
"""Private cluster worker. Secrets are read from a root-only file, never argv."""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = Path('/var/lib/litellm-cluster')
SECRET_FILE = ROOT / 'node.json'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(argv, **options):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **options)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def identity(d):
    return {'owner': d['owner'], 'plan_id': d['plan_id'], 'bundle_sha256': d['bundle_sha256'],
            'secret_digest': hashlib.sha256(json.dumps(d['secrets'], sort_keys=True).encode()).hexdigest()}


def guard(d):
    import install as i
    p, n = d['plan'], d['node']
    osr = i.os_release()
    require(osr.get('ID') == 'rhel' and osr.get('VERSION_ID', '').startswith('9.'), 'RHEL 9 is required')
    require(platform.machine() == 'x86_64', 'Infrastructure payload targets x86_64')
    require(socket.gethostname().split('.')[0] == n['name'].split('.')[0], 'Wrong host for this plan')
    addresses = json.loads(run(['ip', '-j', '-4', 'addr', 'show', 'dev', n['interface']]).stdout)
    require(n['address'] in {a['local'] for entry in addresses for a in entry.get('addr_info', [])},
            'Configured address is not assigned to its interface')
    owner = ROOT / 'ownership.json'
    if owner.exists():
        require(json.loads(owner.read_text()) == identity(d), 'Cluster plan, bundle or secrets changed; use an explicit migration')
        return
    reserve = 4 if 'managed' in (p['services']['postgresql'], p['services']['redis']) else 2
    require(i.mem_gib() + 0.5 >= p['gateway']['workers'] * 4 + reserve, 'Insufficient RAM for workers and infrastructure')
    require(shutil.disk_usage('/var/lib').free >= 20 * 1024 ** 3, 'Need at least 20 GiB free under /var/lib')
    require(not i.STATE_PATH.exists(), 'Existing LiteLLM deployment needs an explicit migration')
    services, ports = ['litellm'], [4000]
    data = []
    if p['services']['postgresql'] == 'managed':
        services += ['postgresql', 'litellm-postgres', 'litellm-etcd']
        ports += [2379, 2380, 5432, 6432, 8008]
        data += ['/var/lib/pgsql/data', '/var/lib/litellm-etcd']
    if p['services']['redis'] == 'managed':
        services += ['redis', 'redis-sentinel', 'litellm-redis', 'litellm-sentinel']
        ports += [6379, 26379]
        data += ['/var/lib/litellm-redis']
    if p['services']['haproxy']:
        services += ['litellm-haproxy']
        ports += [443]
    if p['services'].get('vip'):
        services += ['keepalived']
        require(not Path('/etc/keepalived/keepalived.conf').exists(), 'Existing Keepalived configuration must be migrated explicitly')
    for path in data:
        require(not Path(path).exists() or not any(Path(path).iterdir()), 'Existing database data: ' + path)
    for name in services:
        require(subprocess.run(['systemctl', 'is-active', name], capture_output=True).returncode != 0,
                'Conflicting existing service: ' + name)
    for port in ports:
        with socket.socket() as sock:
            try:
                sock.bind(('0.0.0.0', port))
            except OSError:
                raise RuntimeError('An existing process owns port ' + str(port))


def claim(d):
    path = ROOT / 'ownership.json'
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(identity(d), f)


def verify_infrastructure(folder):
    folder = Path(folder)
    entries = {}
    for line in (folder / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        raw = folder / name.strip()
        require(not raw.is_symlink(), 'Symlink in infrastructure manifest')
        target = raw.resolve()
        require(folder.resolve() in target.parents and target.is_file(), 'Unsafe infrastructure path')
        require(sha(target) == digest, 'Infrastructure checksum mismatch: ' + name)
        entries[name.strip()] = digest
    require({'MANIFEST.json', 'requirements.txt', 'etcd.tar.gz'}.issubset(entries), 'Incomplete infrastructure manifest')
    meta = json.loads((folder / 'MANIFEST.json').read_text())
    require(meta['platform'] == 'linux/x86_64' and meta['python'] == '3.12', 'Wrong infrastructure platform')
    require(set('wheels/' + w for w in meta['wheels']).issubset(entries), 'Unverified wheelhouse entries')
    require({w.name for w in (folder / 'wheels').iterdir()} == set(meta['wheels']), 'Unexpected wheelhouse files')
    return meta


def install_etcd_archive(archive_path, dest):
    """Never truncate a running executable during a retry."""
    dest.mkdir(exist_ok=True)
    with tarfile.open(archive_path) as archive:
        for executable in ('etcd', 'etcdctl'):
            members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith('/' + executable)]
            require(len(members) == 1, 'Expected one etcd executable')
            path = dest / ('litellm-' + executable)
            require(not path.is_symlink(), 'Unexpected etcd executable symlink')
            with tempfile.NamedTemporaryFile(dir=dest, prefix='.litellm-etcd-', delete=False) as target:
                temp = Path(target.name)
                with archive.extractfile(members[0]) as source:
                    shutil.copyfileobj(source, target)
            try:
                if path.exists() and sha(path) == sha(temp):
                    continue
                require(subprocess.run(['systemctl', 'is-active', 'litellm-etcd'], capture_output=True).returncode != 0,
                        'Running etcd binary differs; use an explicit infrastructure upgrade')
                temp.chmod(0o755)
                os.replace(temp, path)
                run(['restorecon', str(path)])
            finally:
                temp.unlink(missing_ok=True)


def packages(d):
    folder = ROOT / 'infrastructure'
    meta = verify_infrastructure(folder)
    require(sha(folder / 'etcd.tar.gz') == meta['etcd_sha256'], 'Unexpected etcd archive')
    dest = Path('/usr/local/libexec')
    install_etcd_archive(folder / 'etcd.tar.gz', dest)
    require(meta['etcd_version'].lstrip('v') in run([str(dest / 'litellm-etcd'), '--version']).stdout, 'Wrong etcd version')
    venv = Path('/opt/litellm-patroni')
    if not (venv / 'bin/python').exists():
        run(['python3.12', '-m', 'venv', str(venv)])
    run([str(venv / 'bin/python'), '-m', 'pip', 'install', '--no-index', '--require-hashes',
         '--find-links', str(folder / 'wheels'), '-r', str(folder / 'requirements.txt')], timeout=600)
    run([str(venv / 'bin/python'), '-m', 'pip', 'check'])


def firewall(d):
    p = d['plan']
    ports = [4000]
    mappings = []
    if p['services']['postgresql'] == 'managed':
        ports += [2379, 2380, 5432, 8008]
        mappings += [('postgresql_etc_t', '/etc/litellm-cluster/postgres(/.*)?')]
    if p['services']['redis'] == 'managed':
        ports += [6379, 26379]
        mappings += [('redis_conf_t', '/etc/litellm-cluster/redis(/.*)?'),
                     ('redis_var_lib_t', '/var/lib/litellm-redis(/.*)?')]
    rules = set()
    for n in p['nodes']:
        for port in ports:
            rules.add('rule family="ipv4" source address="' + n['address'] + '/32" port port="' + str(port) + '" protocol="tcp" accept')
        if p['services'].get('vip'):
            rules.add('rule family="ipv4" source address="' + n['address'] + '/32" protocol value="vrrp" accept')
    sources, port = (p['client_cidrs'], 443) if p['services']['haproxy'] else (p['answers']['lb_cidrs'], 4000)
    for cidr in sources:
        ipaddress.ip_network(cidr, strict=True)
        rules.add('rule family="ipv4" source address="' + cidr + '" port port="' + str(port) + '" protocol="tcp" accept')
    for rule in sorted(rules):
        run(['firewall-cmd', '--permanent', '--add-rich-rule=' + rule])
    run(['firewall-cmd', '--reload'])
    for label, pattern in mappings:
        r = subprocess.run(['semanage', 'fcontext', '-a', '-t', label, pattern], capture_output=True)
        if r.returncode:
            run(['semanage', 'fcontext', '-m', '-t', label, pattern])
    paths = ['/etc/litellm-cluster']
    if p['services']['redis'] == 'managed':
        paths += ['/var/lib/litellm-redis']
    if p['services']['postgresql'] == 'managed':
        paths += ['/var/lib/pgsql', '/var/run/postgresql']
    run(['restorecon', '-RF'] + paths)


def context():
    ctx = ssl.create_default_context(cafile=str(ROOT / 'ca.crt'))
    ctx.load_cert_chain(str(ROOT / 'node.crt'), str(ROOT / 'node.key'))
    return ctx


def database(d):
    if not importlib.util.find_spec('psycopg'):
        os.execv('/opt/litellm-patroni/bin/python', ['/opt/litellm-patroni/bin/python', __file__, 'database', str(SECRET_FILE)])
    import psycopg
    from psycopg import sql
    leader, deadline = None, time.monotonic() + 600
    while time.monotonic() < deadline:
        healthy = []
        for n in d['plan']['nodes']:
            try:
                with urllib.request.urlopen('https://' + n['address'] + ':8008/patroni', context=context(), timeout=5) as response:
                    status = json.load(response)
                if status.get('state') == 'running':
                    healthy.append((n, status))
            except (OSError, ValueError):
                pass
        leaders = [n for n, s in healthy if s.get('role') in ('master', 'primary')]
        if len(healthy) == 3 and len(leaders) == 1:
            leader = leaders[0]
            break
        time.sleep(3)
    require(leader, 'PostgreSQL needs one primary and two healthy replicas')
    a, s = d['plan']['answers'], d['secrets']
    with psycopg.connect(host=leader['address'], port=5432, user='postgres', password=s['postgres'],
            dbname='postgres', sslmode='verify-full', sslrootcert=str(ROOT / 'ca.crt'), connect_timeout=10,
            autocommit=True) as conn:
        count, deadline = 0, time.monotonic() + 120
        while time.monotonic() < deadline:
            count = conn.execute("select count(*) from pg_stat_replication where state='streaming' and sync_state in ('sync','quorum')").fetchone()[0]
            if count:
                break
            time.sleep(2)
        require(count >= 1, 'No synchronous PostgreSQL standby')
        if not conn.execute('select 1 from pg_roles where rolname=%s', (a['pg_user'],)).fetchone():
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(a['pg_user']), sql.Literal(s['database'])))
        if not conn.execute('select 1 from pg_database where datname=%s', (a['pg_db'],)).fetchone():
            conn.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(sql.Identifier(a['pg_db']), sql.Identifier(a['pg_user'])))
        owner = conn.execute('select pg_get_userbyid(datdba) from pg_database where datname=%s', (a['pg_db'],)).fetchone()[0]
        require(owner == a['pg_user'], 'Unexpected application database owner')


def redis_check(d):
    common = ['redis-cli', '--tls', '--cacert', str(ROOT / 'ca.crt'), '--raw']
    deadline = time.monotonic() + 180
    s = d['secrets']
    while time.monotonic() < deadline:
        try:
            answers = []
            for n in d['plan']['nodes']:
                argv = common + ['-h', n['address'], '-p', '26379', 'SENTINEL']
                result = run(argv + ['get-master-addr-by-name', 'litellm'], env=dict(os.environ, REDISCLI_AUTH=s['sentinel']), timeout=10).stdout.splitlines()
                require(len(result) == 2, 'Sentinel has not discovered a master')
                answers.append(tuple(result))
                ck = run(argv + ['ckquorum', 'litellm'], env=dict(os.environ, REDISCLI_AUTH=s['sentinel']), timeout=10).stdout
                require(ck.startswith('OK'), 'Sentinel quorum unavailable')
            require(len(set(answers)) == 1, 'Sentinels disagree on the primary')
            address, port = answers[0]
            require(address in {n['address'] for n in d['plan']['nodes']} and port == '6379', 'Unexpected Redis primary')
            result = run(common + ['-h', address, '-p', port, 'SET', 'litellm:installer-health', 'ok', 'EX', '30'],
                         env=dict(os.environ, REDISCLI_AUTH=s['redis']), timeout=10).stdout.strip()
            require(result == 'OK', 'Redis primary is not writable')
            return
        except (RuntimeError, subprocess.SubprocessError):
            time.sleep(3)
    raise RuntimeError('Redis/Sentinel did not become healthy')


def gateway(d):
    import install as i
    p, a, s = d['plan'], dict(d['plan']['answers']), d['secrets']
    a.update(mode=p['gateway']['mode'], workers=p['gateway']['workers'], ca_source=str(ROOT / 'ca.crt'), cluster_host_network=True)
    i.RUNTIME['mode'] = a['mode']
    i.SOURCES.update(paths=[str(ROOT / 'application.tar')], pins=[], version=p['gateway']['version'])
    require(sha(ROOT / 'application.tar') == d['bundle_sha256'], 'Application archive checksum mismatch')
    releases, _, _ = i.find_releases(a['mode'])
    require(len(releases) == 1, 'Expected one complete matching application release')
    rel = i.materialize(releases[0])
    state = i.load_json(i.STATE_PATH)
    require(not state.get('mode') or state['mode'] == a['mode'], 'Cannot change an installed runtime')
    if a['mode'] == 'container' and int(Path('/proc/sys/user/max_user_namespaces').read_text()) < 15000:
        Path('/etc/sysctl.d/90-litellm-userns.conf').write_text('user.max_user_namespaces = 15000\n')
        run(['sysctl', '-w', 'user.max_user_namespaces=15000'])
    facts = {'cpus': os.cpu_count() or 1, 'mem_gib': i.mem_gib(), 'podman': i.podman_version(), 'firewalld': True}
    node = {'storage': 'home', 'tls_cert': str(ROOT / 'node.crt'), 'tls_key': str(ROOT / 'node.key')}
    ref = i.prepare_runtime(rel, state, node, facts)
    has_ca, changed = i.install_support_files(a, node)
    changed |= i.write_config(a, has_ca)
    nm = i.native_info(rel) if a['mode'] == 'native' else None
    if nm:
        changed |= i.write_file(i.SRV / 'native.env', i.render_native_env(nm), 0o644, owner=False)
    values = {i.SECRET_MASTER: s['master'], i.SECRET_SALT: s['salt'], i.SECRET_DB: i.database_url(a, s['database']), i.SECRET_REDIS: s['redis']}
    if a.get('redis_sentinel_auth'):
        values[i.SECRET_SENTINEL] = s['sentinel']
    secret_changed = False
    for key, value in values.items():
        if i.read_secret(key) != value:
            i.store_secret(key, value)
            secret_changed = True
    a['master_fp'], a['salt_fp'] = i.fingerprint(s['master']), i.fingerprint(s['salt'])
    i.save_json(i.ANSWERS_PATH, a)
    require(i.run_probe_any(a, ref, has_ca, i.secret_names(a), nm), 'Gateway dependency probe failed')
    if i.service_active() and changed:
        raise RuntimeError('Running gateway configuration changed; use an explicit rolling upgrade')
    i.apply_and_start(a, state, facts, ref, has_ca, i.secret_names(a), nm, changed or secret_changed)
    state.update(i.release_state(rel, ref))
    state['mode'] = a['mode']
    i.save_json(i.STATE_PATH, state)
    i.cleanup_staging()


def health(d):
    services = []
    if d['plan']['services']['postgresql'] == 'managed':
        services += ['litellm-postgres', 'litellm-etcd']
    if d['plan']['services']['redis'] == 'managed':
        services += ['litellm-redis', 'litellm-sentinel']
        redis_check(d)
    if d['plan']['services']['haproxy'] or d['plan']['services']['postgresql'] == 'managed':
        services += ['litellm-haproxy']
    if d['plan']['services'].get('vip'):
        services += ['keepalived']
    for name in services:
        run(['systemctl', 'is-active', name])
    for path in ('/health/readiness', '/v1/models'):
        request = urllib.request.Request('https://' + d['node']['address'] + ':4000' + path,
                        headers={'Authorization': 'Bearer ' + d['secrets']['master']})
        with urllib.request.urlopen(request, context=context(), timeout=15) as response:
            require(response.status == 200, 'Gateway health check failed')


def main():
    require(os.geteuid() == 0, 'Worker must run as root')
    require(len(sys.argv) == 3 and Path(sys.argv[2]).resolve() == SECRET_FILE, 'Invalid worker invocation')
    require(not SECRET_FILE.is_symlink() and SECRET_FILE.stat().st_uid == 0 and SECRET_FILE.stat().st_mode & 0o077 == 0,
            'Unsafe node-secret permissions')
    d = json.loads(SECRET_FILE.read_text())
    operations = {'guard': guard, 'claim': claim, 'packages': packages, 'firewall': firewall,
                  'database': database, 'redis-check': redis_check, 'gateway': gateway, 'check': health}
    require(sys.argv[1] in operations, 'Unknown worker phase')
    try:
        operations[sys.argv[1]](d)
        print(sys.argv[1] + ': OK')
        return 0
    except Exception as exc:
        message = str(exc)
        for value in d['secrets'].values():
            for variant in (value, urllib.parse.quote(value, safe='')):
                message = message.replace(variant, '[redacted]')
        (ROOT / 'last-error.txt').write_text(sys.argv[1] + ': ' + message + '\n')
        (ROOT / 'last-error.txt').chmod(0o600)
        print(sys.argv[1] + ': FAILED; inspect /var/lib/litellm-cluster/last-error.txt and service journals as root', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
