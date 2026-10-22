#!/usr/bin/env python3
"""Bootstrap three RHEL gateways from node 1. This is not a rolling-upgrade tool."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('/var/lib/litellm-cluster')
OWNER = 'litellm-cluster-v1'
NAMES = ['idmvllmgwp1', 'idmvllmgwp2', 'idmvllmgwp3']


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(data, f, indent=2)
        f.write('\n')


def plan_id(p):
    return hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()


def host(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', value)


def validate(p):
    require(p.get('schema') == 1, 'Unsupported plan schema')
    nodes, services, a = p['nodes'], p['services'], p['answers']
    require(len(nodes) == 3, 'Exactly three nodes are required')
    for n in nodes:
        require(host(n['name']), 'Invalid node name')
        require(ipaddress.ip_address(n['address']).version == 4, 'Use IPv4 node addresses')
        require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', n['interface']), 'Invalid interface')
    require(len({n['name'] for n in nodes}) == 3 and len({n['address'] for n in nodes}) == 3, 'Duplicate nodes')
    for kind in ('postgresql', 'redis'):
        require(services[kind] in ('managed', 'external'), 'Invalid ' + kind + ' choice')
    require(type(services['haproxy']) is bool, 'HAProxy must be a boolean')
    require(p['gateway']['mode'] in ('native', 'container'), 'Invalid runtime')
    require(re.fullmatch(r'v\d+\.\d+\.\d+', p['gateway']['version']), 'Pin an exact LiteLLM release')
    require(p['gateway']['version'] != 'v1.107.0', 'Blocked release')
    require(type(p['gateway']['workers']) is int and 1 <= p['gateway']['workers'] <= 64, 'Invalid workers')
    require(host(a['fqdn']) and host(a['pg_host']), 'Invalid service hostname')
    for key in ('pg_db', 'pg_user'):
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', a[key]), 'Invalid database identifier')
    require(a['pg_sslmode'] in ('verify-full', 'verify-ca') and 1 <= a['pg_port'] <= 65535, 'Invalid PostgreSQL TLS/port')
    require(a['node_count'] == 3 and a['host_port'] == 4000 and a['node_tls'] is True, 'Three TLS backends on port 4000 required')
    require(a['redis_auth'] is True and a['redis_tls'] is True, 'Redis needs password and TLS')
    require(a['redis_topology'] in ('standalone', 'sentinel', 'cluster') and a['redis_nodes'], 'Invalid Redis topology')
    for name, port in a['redis_nodes']:
        require(host(name) and 1 <= port <= 65535, 'Invalid Redis endpoint')
    require(a['redis_topology'] != 'standalone' or len(a['redis_nodes']) == 1, 'Use one standalone endpoint')
    if services['postgresql'] == 'managed':
        require((a['pg_host'], a['pg_port'], a['pg_sslmode']) == ('localhost', 6432, 'verify-full'), 'Managed PostgreSQL uses localhost:6432 with verified TLS')
    if services['redis'] == 'managed':
        require(a['redis_topology'] == 'sentinel' and a.get('redis_service_name') == 'litellm'
            and a.get('redis_sentinel_auth') is True and a['redis_nodes'] == [[n['address'], 26379] for n in nodes],
            'Incorrect managed Sentinel endpoints')
    require(p['client_cidrs'] and a['lb_cidrs'], 'Client and load-balancer CIDRs required')
    for cidr in p['client_cidrs'] + a['lb_cidrs'] + a['admin_cidrs']:
        require(ipaddress.ip_network(cidr, strict=True).version == 4, 'This implementation uses IPv4 CIDRs')
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', p['ssh_user']), 'Invalid SSH user')
    vip = services.get('vip')
    if vip:
        require(services['haproxy'], 'VIP needs managed HAProxy')
        vi = ipaddress.ip_interface(vip['address'])
        require(vi.version == 4 and vi.network.prefixlen < 32, 'VIP needs IPv4 prefix')
        require(str(vi.ip) not in {n['address'] for n in nodes}, 'VIP conflicts with node IP')
        require(all(ipaddress.ip_address(n['address']) in vi.network for n in nodes), 'VIP requires shared subnet')
        require(1 <= vip['router_id'] <= 255, 'Invalid VRRP router ID')
    return p


def wizard():
    import install as i
    p = {'schema': 1, 'nodes': [], 'services': {}, 'tls': {}}
    print('Run on node 1. Nodes 2/3 need verified SSH keys and root/passwordless sudo.')
    for default in NAMES:
        name = i.ask('Node hostname', default, i.v_host)
        p['nodes'].append({'name': name, 'address': i.ask('IPv4 address for ' + name),
                           'interface': i.ask('Interface on ' + name, 'ens192')})
    p['ssh_user'] = i.ask('SSH user on nodes 2/3', 'root')
    p['identity_file'] = i.ask('SSH private key path (optional)', optional=True)
    for kind, description in [('postgresql', 'PostgreSQL 16 + Patroni + etcd quorum'), ('redis', 'Redis 7 + Sentinel quorum')]:
        p['services'][kind] = i.ask_choice(kind, [('external', 'Use existing HA service'),
            ('managed', 'Installer-managed ' + description)], 'external' if kind == 'postgresql' else 'managed')
    p['services']['haproxy'] = i.ask_yes('Manage HAProxy HTTPS frontend on all nodes?', True)
    p['services']['vip'] = None
    if p['services']['haproxy'] and i.ask_yes('Manage a floating VIP with Keepalived?', True):
        p['services']['vip'] = {'address': i.ask('Unused VIP address/prefix'),
            'router_id': int(i.ask('Unused VRRP router ID', '51', i.v_int(1, 255)))}
    p['gateway'] = {'mode': i.ask_choice('LiteLLM runtime', [('container', 'Rootless Podman'), ('native', 'Python 3.12 + systemd')], 'container'),
        'version': i.ask('Exact LiteLLM release', 'v1.106.2'), 'workers': int(i.ask('Workers per node', '1', i.v_int(1, 64)))}
    p['client_cidrs'] = i.split_list(i.ask('Client CIDRs allowed to reach HAProxy', check=i.v_cidrs))
    a = {'fqdn': i.ask('Gateway DNS name', check=i.v_host), 'host_port': 4000, 'workers': p['gateway']['workers'],
        'node_count': 3, 'node_tls': True, 'lb_cidrs': [n['address'] + '/32' for n in p['nodes']], 'admin_cidrs': [],
        'retention': i.ask('Log retention', '90d', i.v_retention), 'pg_db': 'litellm', 'pg_user': 'litellm',
        'pg_bouncer_tx': False, 'redis_username': '', 'redis_auth': True, 'redis_tls': True, 'model_urls': []}
    if not p['services']['haproxy']:
        a['lb_cidrs'] = i.split_list(i.ask('External load-balancer source CIDRs', check=i.v_cidrs))
    if p['services']['postgresql'] == 'managed':
        a.update(pg_host='localhost', pg_port=6432, pg_sslmode='verify-full')
    else:
        a.update(pg_host=i.ask('Existing writable PostgreSQL endpoint', check=i.v_host), pg_port=int(i.ask('PostgreSQL port', '5432', i.v_int(1, 65535))),
            pg_db=i.ask('Database', 'litellm', i.v_ident), pg_user=i.ask('Database owner', 'litellm', i.v_ident), pg_sslmode='verify-full')
        a['pg_bouncer_tx'] = i.ask_yes('PgBouncer transaction pooling?', False)
    if p['services']['redis'] == 'managed':
        a.update(redis_topology='sentinel', redis_nodes=[[n['address'], 26379] for n in p['nodes']], redis_service_name='litellm', redis_sentinel_auth=True)
    else:
        a['redis_topology'] = i.ask_choice('Existing Redis topology', [('standalone', 'Single endpoint'), ('sentinel', 'Sentinel'), ('cluster', 'Redis Cluster')], 'sentinel')
        a['redis_nodes'] = i.parse_hostports(i.ask('Redis or Sentinel hosts:ports', check=i.v_hostports))
        a['redis_service_name'] = i.ask('Sentinel master name', 'litellm', i.v_ident) if a['redis_topology'] == 'sentinel' else ''
        a['redis_sentinel_auth'] = a['redis_topology'] == 'sentinel' and i.ask_yes('Sentinel password required?', True)
        a['redis_username'] = i.ask('Redis ACL username (empty = default)', optional=True, check=i.v_ident)
    p['tls']['external_ca'] = i.ask('PEM trust bundle for external services', check=i.v_pem_cert,
        optional=p['services']['postgresql'] == p['services']['redis'] == 'managed')
    p['tls'].update(frontend_cert='', frontend_key='')
    if p['services']['haproxy'] and i.ask_yes('Use an existing client-facing TLS certificate?', True):
        p['tls']['frontend_cert'] = i.ask('Frontend full-chain PEM certificate', check=i.v_pem_cert)
        p['tls']['frontend_key'] = i.ask('Frontend private key PEM', check=i.v_pem_key)
    p['answers'] = a
    return validate(p)


def new_secrets(p):
    import getpass
    s = {k: secrets.token_urlsafe(36) for k in ('postgres', 'replication', 'database', 'redis', 'sentinel')}
    s.update(master='sk-' + secrets.token_hex(32), salt='sk-' + secrets.token_hex(32))
    for kind, key, prompt in [('postgresql', 'database', 'Existing PostgreSQL application password'), ('redis', 'redis', 'Existing Redis password')]:
        if p['services'][kind] == 'external':
            s[key] = getpass.getpass(prompt + ': ')
            require(s[key], 'Password is required')
    if p['services']['redis'] == 'external' and p['answers'].get('redis_sentinel_auth'):
        s['sentinel'] = getpass.getpass('Existing Sentinel password: ')
        require(s['sentinel'], 'Sentinel password required')
    return s


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True)


def pki(p, work):
    ca = work / 'ca'
    ca.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (ca / 'ca.crt').exists():
        require(not any((work / n['name'] / 'node.crt').exists() for n in p['nodes']), 'Recover the original controller CA')
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '3650', '-subj', '/CN=LiteLLM cluster CA',
            '-keyout', str(ca / 'ca.key'), '-out', str(ca / 'ca.crt')])
    run(['openssl', 'x509', '-in', str(ca / 'ca.crt'), '-checkend', '604800', '-noout'])
    for n in p['nodes']:
        d = work / n['name']
        d.mkdir(mode=0o700, exist_ok=True)
        if not (d / 'node.crt').exists():
            san = ['DNS:' + n['name'], 'IP:' + n['address'], 'DNS:localhost', 'IP:127.0.0.1', 'DNS:' + p['answers']['fqdn']]
            if p['services'].get('vip'):
                san.append('IP:' + str(ipaddress.ip_interface(p['services']['vip']['address']).ip))
            (d / 'extensions').write_text('subjectAltName=' + ','.join(san) + '\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n')
            run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=' + n['name'], '-keyout', str(d / 'node.key'), '-out', str(d / 'node.csr')])
            run(['openssl', 'x509', '-req', '-in', str(d / 'node.csr'), '-CA', str(ca / 'ca.crt'), '-CAkey', str(ca / 'ca.key'),
                '-set_serial', str(secrets.randbits(128)), '-days', '365', '-extfile', str(d / 'extensions'), '-out', str(d / 'node.crt')])
        run(['openssl', 'x509', '-in', str(d / 'node.crt'), '-checkend', '604800', '-noout'])
        run(['openssl', 'verify', '-CAfile', str(ca / 'ca.crt'), str(d / 'node.crt')])
        trust = (ca / 'ca.crt').read_bytes()
        if p['tls'].get('external_ca'):
            trust += b'\n' + Path(p['tls']['external_ca']).read_bytes()
        (d / 'ca.crt').write_bytes(trust)
        (d / 'client.pem').write_bytes((d / 'node.crt').read_bytes() + (d / 'node.key').read_bytes())
        cert, key = p['tls'].get('frontend_cert'), p['tls'].get('frontend_key')
        if cert and key:
            run(['openssl', 'x509', '-in', cert, '-checkhost', p['answers']['fqdn'], '-noout'])
            run(['openssl', 'x509', '-in', cert, '-checkend', '604800', '-noout'])
            require(run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout']).stdout == run(['openssl', 'pkey', '-in', key, '-pubout']).stdout, 'Frontend certificate/key mismatch')
        (d / 'frontend.pem').write_bytes(Path(cert).read_bytes() + Path(key).read_bytes() if cert and key else (d / 'client.pem').read_bytes())
        for name in ('node.key', 'client.pem', 'frontend.pem'):
            (d / name).chmod(0o600)
    (ca / 'ca.key').chmod(0o600)


def etcd_config(p, n):
    b = '/etc/litellm-cluster/etcd'
    tls = {'cert-file': b + '/node.crt', 'key-file': b + '/node.key', 'client-cert-auth': True, 'trusted-ca-file': b + '/ca.crt'}
    return {'name': n['name'], 'data-dir': '/var/lib/litellm-etcd', 'listen-client-urls': 'https://' + n['address'] + ':2379',
        'advertise-client-urls': 'https://' + n['address'] + ':2379', 'listen-peer-urls': 'https://' + n['address'] + ':2380',
        'initial-advertise-peer-urls': 'https://' + n['address'] + ':2380',
        'initial-cluster': ','.join(x['name'] + '=https://' + x['address'] + ':2380' for x in p['nodes']),
        'initial-cluster-state': 'new', 'initial-cluster-token': plan_id(p)[:24], 'client-transport-security': tls,
        'peer-transport-security': tls, 'auto-compaction-mode': 'periodic', 'auto-compaction-retention': '1h'}


def patroni_config(p, n, s):
    b = '/etc/litellm-cluster/postgres'
    hba = ['local all postgres peer', 'hostssl all all 127.0.0.1/32 scram-sha-256']
    for x in p['nodes']:
        for db, user in [('replication', 'replicator'), ('all', 'postgres'), ('all', p['answers']['pg_user'])]:
            hba.append('hostssl ' + db + ' ' + user + ' ' + x['address'] + '/32 scram-sha-256')
    def auth(user, password):
        return {'username': user, 'password': password, 'sslmode': 'verify-full', 'sslrootcert': b + '/ca.crt'}
    return {'scope': 'litellm', 'namespace': '/litellm/', 'name': n['name'],
        'restapi': {'listen': n['address'] + ':8008', 'connect_address': n['address'] + ':8008', 'certfile': b + '/node.crt',
            'keyfile': b + '/node.key', 'cafile': b + '/ca.crt', 'verify_client': 'required'},
        'ctl': {'cacert': b + '/ca.crt', 'certfile': b + '/node.crt', 'keyfile': b + '/node.key'},
        'etcd3': {'hosts': [x['address'] + ':2379' for x in p['nodes']], 'protocol': 'https', 'cacert': b + '/ca.crt', 'cert': b + '/node.crt', 'key': b + '/node.key'},
        'bootstrap': {'dcs': {'ttl': 30, 'loop_wait': 10, 'retry_timeout': 10, 'maximum_lag_on_failover': 1048576,
            'synchronous_mode': True, 'synchronous_mode_strict': True, 'synchronous_node_count': 1,
            'postgresql': {'use_pg_rewind': True, 'parameters': {'wal_level': 'replica', 'hot_standby': 'on',
                'max_wal_senders': 10, 'max_replication_slots': 10, 'password_encryption': 'scram-sha-256', 'ssl': 'on',
                'ssl_cert_file': b + '/node.crt', 'ssl_key_file': b + '/node.key', 'ssl_ca_file': b + '/ca.crt'}}},
            'initdb': [{'encoding': 'UTF8'}, 'data-checksums']},
        'postgresql': {'listen': n['address'] + ':5432', 'connect_address': n['address'] + ':5432', 'data_dir': '/var/lib/pgsql/data',
            'bin_dir': '/usr/bin', 'pg_hba': hba, 'parameters': {'unix_socket_directories': '/var/run/postgresql'},
            'authentication': {'superuser': auth('postgres', s['postgres']), 'replication': auth('replicator', s['replication'])}},
        'watchdog': {'mode': 'off'}}


def redis_quote(v):
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r') + '"'


def redis_config(p, n, s, sentinel=False):
    b = '/etc/litellm-cluster/redis'
    lines = ['bind 127.0.0.1 ' + n['address'], 'protected-mode yes', 'port 0', 'tls-port ' + ('26379' if sentinel else '6379'),
        'tls-cert-file ' + b + '/node.crt', 'tls-key-file ' + b + '/node.key', 'tls-ca-cert-file ' + b + '/ca.crt',
        'tls-auth-clients no', 'tls-replication yes', 'daemonize no', 'logfile ""', 'dir /var/lib/litellm-redis',
        'requirepass ' + redis_quote(s['sentinel'] if sentinel else s['redis'])]
    if sentinel:
        lines += ['sentinel monitor litellm ' + p['nodes'][0]['address'] + ' 6379 2', 'sentinel auth-pass litellm ' + redis_quote(s['redis']),
            'sentinel down-after-milliseconds litellm 10000', 'sentinel failover-timeout litellm 60000', 'sentinel parallel-syncs litellm 1',
            'sentinel announce-ip ' + n['address'], 'sentinel announce-port 26379']
    else:
        lines += ['appendonly yes', 'masterauth ' + redis_quote(s['redis']), 'replica-announce-ip ' + n['address'],
            'replica-announce-port 6379', 'min-replicas-to-write 1', 'min-replicas-max-lag 10']
        if n['name'] != p['nodes'][0]['name']:
            lines.append('replicaof ' + p['nodes'][0]['address'] + ' 6379')
    return '\n'.join(lines) + '\n'


def haproxy_config(p):
    b = '/etc/haproxy/litellm'
    lines = ['global', '  log stdout format raw local0', '  user haproxy', '  group haproxy', '  maxconn 8192',
        'defaults', '  log global', '  timeout connect 10s', '  timeout client 660s', '  timeout server 660s']
    if p['services']['postgresql'] == 'managed':
        lines += ['listen postgres_primary', '  bind 127.0.0.1:6432', '  mode tcp', '  option httpchk GET /primary',
            '  http-check expect status 200', '  default-server inter 2s fall 3 rise 2 on-marked-down shutdown-sessions']
        for n in p['nodes']:
            lines.append('  server ' + n['name'] + ' ' + n['address'] + ':5432 check port 8008 check-ssl verify required verifyhost '
                + n['name'] + ' ca-file ' + b + '/ca.crt crt ' + b + '/client.pem')
    if p['services']['haproxy']:
        lines += ['frontend litellm_https', '  bind :443 ssl crt ' + b + '/frontend.pem ssl-min-ver TLSv1.2', '  mode http',
            '  http-request del-header X-Forwarded-For', '  option forwardfor', '  http-request set-header X-Forwarded-Proto https',
            '  default_backend litellm_nodes', 'backend litellm_nodes', '  mode http', '  balance leastconn',
            '  option httpchk GET /health/readiness', '  http-check expect status 200', '  default-server inter 5s fall 3 rise 2']
        for n in p['nodes']:
            lines.append('  server ' + n['name'] + ' ' + n['address'] + ':4000 ssl verify required verifyhost ' + n['name'] + ' ca-file ' + b + '/ca.crt check')
    return '\n'.join(lines) + '\n'


def keepalived_config(p, n):
    index = [x['name'] for x in p['nodes']].index(n['name'])
    vip = p['services']['vip']
    lines = ['global_defs {', '  enable_script_security', '  script_user root', '}', 'vrrp_script check_litellm {',
        '  script "/etc/keepalived/check-litellm"', '  interval 2', '  fall 3', '  rise 2', '}', 'vrrp_instance LITELLM {',
        '  state BACKUP', '  interface ' + n['interface'], '  virtual_router_id ' + str(vip['router_id']),
        '  priority ' + str(150 - 10 * index), '  advert_int 1', '  nopreempt', '  unicast_src_ip ' + n['address'], '  unicast_peer {']
    lines += ['    ' + x['address'] for x in p['nodes'] if x['name'] != n['name']]
    lines += ['  }', '  virtual_ipaddress {', '    ' + vip['address'] + ' dev ' + n['interface'], '  }', '  track_script {', '    check_litellm', '  }', '}']
    return '\n'.join(lines) + '\n'


def unit(description, user, command, writable):
    return ('[Unit]\nDescription=' + description + '\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nUser='
        + user + '\nExecStart=' + command + '\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=120\nNoNewPrivileges=true\n'
        'ProtectHome=true\nProtectSystem=strict\nReadWritePaths=' + writable + '\n[Install]\nWantedBy=multi-user.target\n')


def stage(p, s, work, bundle):
    pki(p, work)
    checksum = sha(bundle)
    for n in p['nodes']:
        d = work / n['name']
        save(d / 'node.json', {'owner': OWNER, 'plan_id': plan_id(p), 'plan': p, 'node': n, 'secrets': s, 'bundle_sha256': checksum})
        files = {}
        if p['services']['postgresql'] == 'managed':
            files['etcd.json'], files['postgres.json'] = json.dumps(etcd_config(p, n), indent=2), json.dumps(patroni_config(p, n, s), indent=2)
            files['litellm-etcd.service'] = unit('LiteLLM etcd', 'litellm-etcd', '/usr/local/libexec/litellm-etcd --config-file /etc/litellm-cluster/etcd/etcd.json', '/var/lib/litellm-etcd')
            files['litellm-postgres.service'] = unit('LiteLLM PostgreSQL/Patroni', 'postgres', '/opt/litellm-patroni/bin/patroni /etc/litellm-cluster/postgres/postgres.json', '/var/lib/pgsql /var/run/postgresql')
        if p['services']['redis'] == 'managed':
            files['redis.conf'], files['sentinel.conf'] = redis_config(p, n, s), redis_config(p, n, s, True)
            for role in ('redis', 'sentinel'):
                files['litellm-' + role + '.service'] = unit('LiteLLM Redis ' + role, 'redis', '/usr/bin/redis-server /etc/litellm-cluster/redis/' + role + '.conf'
                    + (' --sentinel' if role == 'sentinel' else ''), '/var/lib/litellm-redis /etc/litellm-cluster/redis')
        if p['services']['haproxy'] or p['services']['postgresql'] == 'managed':
            files['haproxy.cfg'] = haproxy_config(p)
            files['litellm-haproxy.service'] = ('[Unit]\nDescription=LiteLLM HAProxy\nAfter=network-online.target\nWants=network-online.target\n'
                '[Service]\nType=notify\nExecStart=/usr/sbin/haproxy -Ws -f /etc/haproxy/litellm-cluster.cfg -p /run/litellm-haproxy.pid\n'
                'ExecReload=/bin/kill -USR2 $MAINPID\nRestart=on-failure\nKillMode=mixed\nTimeoutStopSec=660\n[Install]\nWantedBy=multi-user.target\n')
        if p['services'].get('vip'):
            files['keepalived.conf'] = keepalived_config(p, n)
            files['check-litellm'] = ('#!/bin/sh\n/usr/bin/systemctl is-active --quiet litellm-haproxy.service || exit 1\n'
                'exec /usr/bin/curl --silent --fail --max-time 3 --cacert /var/lib/litellm-cluster/ca.crt https://' + n['address'] + ':4000/health/readiness >/dev/null\n')
        for name, text in files.items():
            (d / name).write_text(text + ('' if text.endswith('\n') else '\n'))
            (d / name).chmod(0o600)


def task(name, module, data, **options):
    return dict({'name': name, 'ansible.builtin.' + module: data}, **options)


def play(name, tasks, serial=None):
    result = {'name': name, 'hosts': 'gateways', 'become': True, 'gather_facts': False, 'any_errors_fatal': True, 'tasks': tasks}
    if serial:
        result['serial'] = serial
    return result


def copy(src, dest, owner='root', mode='0600', force=True):
    return task('Stage ' + dest, 'copy', {'src': str(src), 'dest': dest, 'owner': owner, 'group': owner, 'mode': mode, 'force': force}, no_log=True)


def service(name):
    return task('Start ' + name, 'systemd', {'name': name, 'enabled': True, 'state': 'started', 'daemon_reload': True})


def directory(path, owner='root', mode='0700'):
    return task('Create ' + path, 'file', {'path': path, 'state': 'directory', 'mode': mode, 'owner': owner, 'group': owner})


def inventory(p):
    hosts = {}
    for index, n in enumerate(p['nodes']):
        v = {'ansible_host': n['address'], 'ansible_user': p['ssh_user'], 'node_address': n['address'], 'ansible_python_interpreter': '/usr/bin/python3',
            'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes -o BatchMode=yes'}
        if index == 0:
            v['ansible_connection'] = 'local'
        if p.get('identity_file'):
            v['ansible_ssh_private_key_file'] = p['identity_file']
        hosts[n['name']] = v
    return {'all': {'children': {'gateways': {'hosts': hosts}}}}


def playbook(p, work, bundle, infrastructure):
    pg, redis = p['services']['postgresql'] == 'managed', p['services']['redis'] == 'managed'
    proxy, vip = pg or p['services']['haproxy'], p['services'].get('vip')
    remote, src = '/var/lib/litellm-cluster', str(work) + '/{{ inventory_hostname }}/'
    def worker(phase, **kw):
        return task(phase, 'command', {'argv': ['python3', remote + '/cluster_node.py', phase, remote + '/node.json']}, no_log=True, **kw)
    pre = [task('Check root and RHEL on every node', 'command', {'argv': ['python3', '-c',
        "import os; s=open('/etc/os-release').read(); assert os.geteuid()==0 and ('ID=\"rhel\"' in s or 'ID=rhel\\n' in s) and 'VERSION_ID=\"9.' in s"]}, changed_when=False),
        directory(remote), task('Check ownership before replacing private staging', 'command', {'argv': ['python3', '-c',
            "import json,pathlib,sys; p=pathlib.Path('/var/lib/litellm-cluster/ownership.json'); d=json.loads(p.read_text()) if p.exists() else {}; sys.exit(0 if not d or (d.get('owner')==sys.argv[1] and d.get('plan_id')==sys.argv[2]) else 1)", OWNER, plan_id(p)]}, changed_when=False),
        copy(HERE / 'cluster_node.py', remote + '/cluster_node.py'), copy(HERE / 'install.py', remote + '/install.py'), copy(src + 'node.json', remote + '/node.json'),
        worker('guard', changed_when=False), worker('claim')]
    result = [play('Preflight all three hosts', pre)]
    packages = ['python3.12', 'python3.12-pip', 'openssl', 'curl', 'firewalld', 'chrony', 'policycoreutils-python-utils']
    packages += ['podman', 'passt', 'container-selinux'] if p['gateway']['mode'] == 'container' else ['nodejs']
    packages += ['haproxy'] if proxy else []
    packages += ['keepalived'] if vip else []
    setup = [task('Install entitled RHEL packages', 'dnf', {'name': packages, 'state': 'present'}), service('firewalld'), service('chronyd')]
    for selected, stream, executable, version in [(pg, 'postgresql:16/server', '/usr/bin/postgres', ' 16.'), (redis, 'redis:7', '/usr/bin/redis-server', 'v=7.')]:
        if selected:
            setup += [task('Install ' + stream + ' without resetting existing streams', 'command', {'argv': ['dnf', '-y', 'module', 'install', stream], 'creates': executable}),
                task('Verify ' + stream, 'command', {'argv': [executable, '--version']}, register='package_version', changed_when=False,
                    failed_when=repr(version) + ' not in package_version.stdout')]
    if pg:
        setup += [task('Create etcd account', 'user', {'name': 'litellm-etcd', 'system': True, 'create_home': False, 'shell': '/sbin/nologin'}),
            task('Stage offline infrastructure', 'copy', {'src': str(infrastructure) + '/', 'dest': remote + '/infrastructure/', 'mode': 'preserve'}), worker('packages')]
    if proxy:
        setup += [task('Enable SELinux HAProxy backend connections', 'command', {'argv': ['setsebool', '-P', 'haproxy_connect_any', 'on']})]
    result += [play('Install selected prerequisites', setup)]
    config = [directory('/etc/litellm-cluster', mode='0755'), copy(bundle, remote + '/application.tar'),
        copy(src + 'ca.crt', remote + '/ca.crt', mode='0644'), copy(src + 'node.crt', remote + '/node.crt', mode='0644'), copy(src + 'node.key', remote + '/node.key')]
    roles = [('etcd', 'litellm-etcd', '/var/lib/litellm-etcd'), ('postgres', 'postgres', '/var/lib/pgsql/data')] if pg else []
    if redis:
        roles += [('redis', 'redis', '/var/lib/litellm-redis')]
    for role, owner, data in roles:
        config += [directory(data, owner), directory('/etc/litellm-cluster/' + role, owner)]
        for name in ['ca.crt', 'node.crt', 'node.key'] + (['redis.conf', 'sentinel.conf'] if role == 'redis' else [role + '.json']):
            config += [copy(src + name, '/etc/litellm-cluster/' + role + '/' + name, owner, force=name not in ('redis.conf', 'sentinel.conf'))]
        for sr in (['redis', 'sentinel'] if role == 'redis' else [role]):
            config += [copy(src + 'litellm-' + sr + '.service', '/etc/systemd/system/litellm-' + sr + '.service', mode='0644')]
    if pg:
        config += [directory('/var/run/postgresql', 'postgres', '0755')]
    if proxy:
        config += [directory('/etc/haproxy/litellm', 'haproxy')]
        config += [copy(src + name, '/etc/haproxy/litellm/' + name, 'haproxy') for name in ('ca.crt', 'client.pem', 'frontend.pem')]
        config += [copy(src + 'haproxy.cfg', '/etc/haproxy/litellm-cluster.cfg', mode='0644'), copy(src + 'litellm-haproxy.service', '/etc/systemd/system/litellm-haproxy.service', mode='0644')]
    config += [worker('firewall')]
    result += [play('Stage services and scoped firewall rules', config)]
    if pg:
        result += [play('Form etcd quorum', [service('litellm-etcd'), task('Wait for etcd quorum', 'command', {'argv': [
            '/usr/local/libexec/litellm-etcdctl', '--endpoints=https://{{ node_address }}:2379', '--cacert=/etc/litellm-cluster/etcd/ca.crt',
            '--cert=/etc/litellm-cluster/etcd/node.crt', '--key=/etc/litellm-cluster/etcd/node.key', 'endpoint', 'health']},
            register='etcd_health', retries=30, delay=2, until='etcd_health.rc == 0', changed_when=False)]),
            play('Form Patroni primary and replicas', [service('litellm-postgres'), worker('database', run_once=True)])]
    if redis:
        result += [play('Start Redis replicas', [service('litellm-redis')]), play('Form Sentinel quorum', [service('litellm-sentinel'), worker('redis-check', run_once=True)])]
    if proxy:
        result += [play('Start primary routing and optional HTTPS balancing', [task('Validate HAProxy', 'command', {'argv': ['haproxy', '-c', '-f', '/etc/haproxy/litellm-cluster.cfg']}, changed_when=False), service('litellm-haproxy')])]
    result += [play('Install and health-check gateways sequentially', [worker('gateway')], serial=1)]
    if vip:
        result += [play('Activate VIP after all gateways are healthy', [copy(src + 'keepalived.conf', '/etc/keepalived/keepalived.conf', mode='0644'),
            copy(src + 'check-litellm', '/etc/keepalived/check-litellm', mode='0755'), task('Validate Keepalived', 'command',
                {'argv': ['keepalived', '--config-test', '-f', '/etc/keepalived/keepalived.conf']}, changed_when=False), service('keepalived')])]
    result += [play('Final authenticated health verification', [worker('check')])]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='Saved public plan; otherwise start wizard')
    parser.add_argument('--bundle', type=Path, help='Verified application/cluster tar')
    parser.add_argument('--infrastructure', type=Path, help='Offline PostgreSQL HA payload')
    parser.add_argument('--plan-only', action='store_true', help='Save/validate plan; remote nodes unchanged')
    parser.add_argument('--yes', action='store_true', help='Skip only the final apply prompt')
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'Run as root on node 1')
        os.umask(0o077)
        p = validate(json.loads(args.config.read_text())) if args.config else wizard()
        require(socket.gethostname().split('.')[0] == p['nodes'][0]['name'].split('.')[0], 'Run on ' + p['nodes'][0]['name'])
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not ROOT.is_symlink() and ROOT.stat().st_uid == 0, 'Controller state must be root-owned')
        ROOT.chmod(0o700)
        saved = ROOT / 'cluster.json'
        if saved.exists():
            require(plan_id(json.loads(saved.read_text())) == plan_id(p), 'Topology differs; use an explicit migration')
        save(saved, p)
        print(json.dumps({'nodes': p['nodes'], 'gateway': p['gateway'], 'services': p['services'], 'client_cidrs': p['client_cidrs'],
            'SELinux': 'haproxy_connect_any enabled when a local proxy is selected', 'scope': 'fresh bootstrap; foreign data/services refused'}, indent=2))
        if args.plan_only:
            print('Plan saved to ' + str(saved) + '; remote nodes unchanged.')
            return 0
        require(args.bundle and args.bundle.is_file(), 'Supply --bundle /absolute/path/application.tar')
        require(shutil.which('ansible-playbook') and shutil.which('openssl'), 'Install ansible-core and openssl on node 1')
        infra = args.infrastructure.resolve() if args.infrastructure else HERE / 'infrastructure'
        if p['services']['postgresql'] == 'managed':
            from cluster_node import verify_infrastructure
            verify_infrastructure(infra)
        import install as i
        if not args.yes and not i.ask_yes('Apply this plan to ALL THREE nodes?', False):
            return 0
        secret_path = ROOT / 'secrets.json'
        if secret_path.exists():
            require(not secret_path.is_symlink() and secret_path.stat().st_uid == 0 and secret_path.stat().st_mode & 0o077 == 0, 'Unsafe secrets permissions')
            s = json.loads(secret_path.read_text())
        else:
            s = new_secrets(p)
            save(secret_path, s)
            print('Back up ' + str(secret_path) + ' and the controller CA to your vault.')
        work = ROOT / 'work'
        work.mkdir(mode=0o700, exist_ok=True)
        stage(p, s, work, args.bundle.resolve())
        save(work / 'inventory.json', inventory(p))
        save(work / 'playbook.json', playbook(p, work, args.bundle.resolve(), infra))
        env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING='True', ANSIBLE_DISPLAY_ARGS_TO_STDOUT='False', ANSIBLE_LOCAL_TEMP=str(ROOT / 'ansible-tmp'))
        r = subprocess.run(['ansible-playbook', '-i', str(work / 'inventory.json'), str(work / 'playbook.json')], env=env)
        require(r.returncode == 0, 'Deployment failed. Fix the failed phase and rerun the SAME plan and secrets.')
        print('All selected services passed health checks. Gateway: https://' + p['answers']['fqdn'] + '/ui')
        return 0
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print('Cluster installer: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
