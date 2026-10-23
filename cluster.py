#!/usr/bin/env python3
"""Guided RHEL LiteLLM bootstrap: one node or three-node HA. Not a migration tool."""
import argparse
from copy import deepcopy
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = Path('/var/lib/litellm-cluster')
OWNER = 'litellm-cluster-v1'
NAMES = ['idmvllmgwp1', 'idmvllmgwp2', 'idmvllmgwp3']


def is_ha(p):
    return len(p['nodes']) == 3


def needs_proxy(p):
    return p['services']['haproxy'] or (is_ha(p) and p['services']['postgresql'] == 'managed')


def same_host(left, right):
    return left.rstrip('.').split('.')[0].casefold() == right.rstrip('.').split('.')[0].casefold()


def interactive():
    return sys.stdin.isatty()


def ipv4_error(value):
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            return 'Use an assigned, routable IPv4 address.'
    except ValueError:
        return 'Enter an IPv4 address, for example 192.0.2.10.'


def parse_cidrs(value):
    result = []
    for item in re.split(r'[,\s]+', value.strip()):
        if not item:
            continue
        network = ipaddress.IPv4Network(item, strict=True)
        if network.prefixlen and (network.network_address.is_unspecified or network.is_multicast
                or network.is_loopback or network.is_link_local):
            raise ValueError('Use your real client network. 0.0.0.0/24 covers only 0.0.0.x; it does not mean all clients.')
        result.append(str(network))
    require(result, 'Enter at least one client IP or network.')
    return list(dict.fromkeys(result))


def cidrs_error(value):
    try:
        parse_cidrs(value)
    except ValueError as exc:
        return str(exc) + ' Use an individual IP (/32), or a network such as 192.0.2.0/24.'


def ask_cidrs(prompt, default=None):
    import install as i
    while True:
        result = parse_cidrs(i.ask(prompt, default, cidrs_error))
        if '0.0.0.0/0' not in result or i.ask_yes('This allows every IPv4 client. Is that intended?', False):
            return result


def local_facts():
    result = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global'],
                            check=True, capture_output=True, text=True)
    return {'hostname': socket.gethostname(), 'interfaces': json.loads(result.stdout)}


def address_interface(facts, address):
    return next((entry['ifname'] for entry in facts['interfaces']
        if any(a.get('local') == address for a in entry.get('addr_info', []))), None)


def suggested_address(name, facts=None):
    try:
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(name, None, socket.AF_INET)})
        addresses = [a for a in addresses if not ipv4_error(a)]
        if facts:
            addresses = [a for a in addresses if address_interface(facts, a)]
        if len(addresses) == 1:
            return addresses[0]
    except OSError:
        pass
    if facts:
        addresses = [a['local'] for entry in facts['interfaces'] for a in entry.get('addr_info', [])
                     if a.get('local') and not ipv4_error(a['local'])]
        if len(addresses) == 1:
            return addresses[0]
    return None


def login_user():
    return os.environ.get('SUDO_USER') or getpass.getuser()


def default_key():
    paths = [Path.home() / '.ssh' / name for name in ('litellm_cluster', 'id_ed25519', 'id_rsa')]
    return str(next((p for p in paths if p.is_file()), paths[0]))


def vip_error(value, nodes):
    try:
        vip = ipaddress.IPv4Interface(value)
        require(vip.network.prefixlen < 32 and not ipv4_error(str(vip.ip)), 'Use an IPv4 VIP with its subnet prefix.')
        require(vip.ip not in (vip.network.network_address, vip.network.broadcast_address), 'VIP cannot be the network or broadcast address.')
        require(str(vip.ip) not in {n['address'] for n in nodes}, 'Reserve a separate unused VIP; do not use a node address.')
        require(all(ipaddress.IPv4Address(n['address']) in vip.network for n in nodes), 'VIP and all nodes must share a subnet.')
    except ValueError as exc:
        return str(exc)


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
    require(len(nodes) in (1, 3), 'Choose one node or three-node HA')
    for n in nodes:
        require(host(n['name']), 'Invalid node name')
        require(not ipv4_error(n['address']), 'Use assigned IPv4 node addresses')
        require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', n['interface']), 'Invalid interface')
    require(len({n['name'].rstrip('.').split('.')[0].casefold() for n in nodes}) == len(nodes)
        and len({n['address'] for n in nodes}) == len(nodes), 'Duplicate nodes (hostname case is ignored)')
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
    require(a['node_count'] == len(nodes) and a['host_port'] == 4000 and a['node_tls'] is True, 'Node count must match the plan; TLS backends use port 4000')
    require(a['redis_auth'] is True and a['redis_tls'] is True, 'Redis needs password and TLS')
    require(a['redis_topology'] in ('standalone', 'sentinel', 'cluster') and a['redis_nodes'], 'Invalid Redis topology')
    for name, port in a['redis_nodes']:
        require(host(name) and 1 <= port <= 65535, 'Invalid Redis endpoint')
    require(a['redis_topology'] != 'standalone' or len(a['redis_nodes']) == 1, 'Use one standalone endpoint')
    if services['postgresql'] == 'managed':
        port = 6432 if is_ha(p) else 5432
        require((a['pg_host'], a['pg_port'], a['pg_sslmode']) == ('localhost', port, 'verify-full'), 'Managed PostgreSQL uses localhost:' + str(port) + ' with verified TLS')
    if services['redis'] == 'managed':
        if is_ha(p):
            require(a['redis_topology'] == 'sentinel' and a.get('redis_service_name') == 'litellm'
                and a.get('redis_sentinel_auth') is True and a['redis_nodes'] == [[n['address'], 26379] for n in nodes],
                'Incorrect managed Sentinel endpoints')
        else:
            require(a['redis_topology'] == 'standalone' and a['redis_nodes'] == [['localhost', 6379]]
                and not a.get('redis_sentinel_auth'), 'Single-node managed Redis uses localhost:6379 without Sentinel')
    direct = not is_ha(p) and not services['haproxy'] and p.get('frontend') == 'direct'
    require(p['client_cidrs'] and (a['lb_cidrs'] or direct), 'Client and load-balancer CIDRs required')
    require(not direct or not a['lb_cidrs'], 'Direct clients must not be trusted as reverse proxies')
    for cidr in p['client_cidrs'] + a['lb_cidrs'] + a['admin_cidrs']:
        parse_cidrs(cidr)
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', p['ssh_user']), 'Invalid SSH user')
    require(p.get('sudo_mode', 'passwordless') in ('password', 'passwordless'), 'Invalid sudo mode')
    vip = services.get('vip')
    if vip:
        require(is_ha(p), 'A floating VIP requires the three-node deployment')
        require(services['haproxy'], 'VIP needs managed HAProxy')
        problem = vip_error(vip['address'], nodes)
        require(not problem, problem)
        require(1 <= vip['router_id'] <= 255, 'Invalid VRRP router ID')
    return p


def wizard(previous=None):
    import install as i
    previous = previous or {}
    old_nodes = previous.get('nodes', [])
    old_services, old_a = previous.get('services', {}), previous.get('answers', {})
    old_gateway, old_tls = previous.get('gateway', {}), previous.get('tls', {})
    p = {'schema': 1, 'nodes': [], 'services': {}, 'tls': {}}
    topology = i.ask_choice('Deployment size', [('single', 'Single node: optional local PostgreSQL/Redis'),
        ('ha', 'Three-node HA: deploy all nodes from this controller')], 'single' if len(old_nodes) == 1 else 'ha')
    count = 1 if topology == 'single' else 3
    print('Single-node bootstrap: all selected services run locally; no automatic failover.' if count == 1 else
        'Three-node bootstrap: SSH as your login user, then sudo. Password-based sudo is supported.')
    print('Press Enter to accept a detected/default value. Hostname comparisons ignore case.')
    try:
        facts = local_facts()
    except (OSError, ValueError, subprocess.SubprocessError):
        facts = {'hostname': socket.gethostname(), 'interfaces': []}
    for index, default in enumerate(NAMES[:count]):
        old = old_nodes[index] if index < len(old_nodes) else {}
        default = old.get('name', facts['hostname'].split('.')[0] if index == 0 else default)
        def name_error(value):
            problem = i.v_host(value)
            if problem:
                return problem
            if index == 0 and not same_host(value, facts['hostname']):
                return 'This controller is ' + facts['hostname'] + '; enter its hostname (case does not matter).'
            if any(same_host(value, n['name']) for n in p['nodes']):
                return 'Each node needs a different hostname.'
        name = i.ask('Node ' + str(index + 1) + ' hostname', default, name_error)
        def address_error(value):
            return ipv4_error(value) or ('Each node needs a different address.' if any(n['address'] == value for n in p['nodes']) else None)
        address = i.ask('IPv4 address for ' + name, old.get('address') or suggested_address(name, facts if index == 0 else None), address_error)
        detected = address_interface(facts, address) if index == 0 else None
        interface = i.ask('Interface on ' + name + ' (auto = detect from its IP)',
            old.get('interface', detected or 'auto'), lambda v: None if re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', v) else 'Invalid interface name.')
        p['nodes'].append({'name': name, 'address': address, 'interface': interface})
    p.update(ssh_user='root', identity_file='', sudo_mode='passwordless')
    if count == 3:
        ask_ssh(p, previous, i)
    for kind, description in [('postgresql', 'PostgreSQL 16 + Patroni + etcd quorum' if count == 3 else 'local PostgreSQL 16'),
            ('redis', 'Redis 7 + Sentinel quorum' if count == 3 else 'local Redis 7')]:
        p['services'][kind] = i.ask_choice(kind, [('external', 'Use existing ' + kind + ' service'),
            ('managed', 'Installer-managed ' + description)], old_services.get(kind, 'external' if kind == 'postgresql' and count == 3 else 'managed'))
    p['services']['haproxy'] = i.ask_yes('Manage HAProxy HTTPS frontend' + (' on all nodes?' if count == 3 else ' on this node?'), old_services.get('haproxy', True))
    p['services']['vip'] = None
    if count == 3 and p['services']['haproxy'] and i.ask_yes('Manage a floating VIP with Keepalived?', bool(old_services.get('vip')) if previous else True):
        old_vip = old_services.get('vip') or {}
        print('Use a reserved, unused IPv4 address/prefix on the subnet shared by all three nodes.')
        p['services']['vip'] = {'address': i.ask('Unused VIP address/prefix', old_vip.get('address'), lambda v: vip_error(v, p['nodes'])),
            'router_id': int(i.ask('Unused VRRP router ID', str(old_vip.get('router_id', 51)), i.v_int(1, 255)))}
    if count == 1:
        p['frontend'] = 'single-node' if p['services']['haproxy'] else i.ask_choice('Client access',
            [('direct', 'Direct HTTPS to LiteLLM on port 4000'), ('external', 'Existing external load balancer')], previous.get('frontend', 'direct'))
        print('Single-node deployment: point gateway DNS at this host or your selected external load balancer.')
    elif not p['services']['vip']:
        p['frontend'] = i.ask_choice('How will clients reach the cluster?',
            [('external', 'Existing external load balancer'), ('single-node', 'One node for initial testing; client address is not HA')], previous.get('frontend', 'external'))
        if p['frontend'] == 'single-node':
            print('Point the gateway DNS at node 1 for testing. Losing node 1 interrupts this client address.')
        else:
            print('Point the gateway DNS at your external load balancer, configured for all three nodes.')
    return wizard_services(p, previous, i)


def ask_ssh(p, previous, i):
    p['ssh_user'] = i.ask('SSH login user on nodes 2/3', previous.get('ssh_user', login_user()),
        lambda v: None if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', v) else 'Invalid login user.')
    p['identity_file'] = i.ask('SSH private key path (missing key can be created; type agent to use SSH agent)',
        previous.get('identity_file', default_key()), optional=True)
    if p['identity_file'].casefold() == 'agent':
        p['identity_file'] = ''
    if p['identity_file']:
        p['identity_file'] = str(Path(p['identity_file']).expanduser().absolute())
    p['sudo_mode'] = 'passwordless' if p['ssh_user'] == 'root' else i.ask_choice('How does this user use sudo on nodes 2/3?',
        [('password', 'Prompt securely for the shared sudo password'), ('passwordless', 'Passwordless sudo')], previous.get('sudo_mode', 'password'))
    if p['sudo_mode'] == 'password':
        print('Ansible will prompt once. Both remote nodes must accept that sudo password. It is not saved in the plan.')


def wizard_services(p, previous, i):
    old_services, old_a = previous.get('services', {}), previous.get('answers', {})
    old_gateway, old_tls = previous.get('gateway', {}), previous.get('tls', {})
    p['gateway'] = {'mode': i.ask_choice('LiteLLM runtime', [('container', 'Rootless Podman'), ('native', 'Python 3.12 + systemd')], old_gateway.get('mode', 'container')),
        'version': i.ask('Exact LiteLLM release', old_gateway.get('version', 'v1.106.2'),
            lambda v: None if re.fullmatch(r'v\d+\.\d+\.\d+', v) and v != 'v1.107.0' else 'Enter an exact supported tag, such as v1.106.2.'),
        'workers': int(i.ask('Workers per node', str(old_gateway.get('workers', 1)), i.v_int(1, 64)))}
    client_default = ','.join(previous.get('client_cidrs', [])) or None
    ssh_client = (os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_CLIENT') or '').split()
    if not client_default and ssh_client and not ipv4_error(ssh_client[0]):
        client_default = ssh_client[0] + '/32'
    print('Client access: enter real client IPs (/32) or network CIDRs, separated by commas. 0.0.0.0/24 does NOT mean all clients.')
    p['client_cidrs'] = ask_cidrs('Allowed client IPs/CIDRs', client_default)
    a = {'fqdn': i.ask('Gateway DNS name', old_a.get('fqdn'), i.v_host), 'host_port': 4000, 'workers': p['gateway']['workers'],
        'node_count': len(p['nodes']), 'node_tls': True, 'lb_cidrs': [n['address'] + '/32' for n in p['nodes']], 'admin_cidrs': [],
        'retention': i.ask('Log retention', old_a.get('retention', '90d'), i.v_retention), 'pg_db': 'litellm', 'pg_user': 'litellm',
        'pg_bouncer_tx': False, 'redis_username': '', 'redis_auth': True, 'redis_tls': True, 'model_urls': []}
    if p.get('frontend') == 'direct':
        a['lb_cidrs'] = []
    elif not p['services']['haproxy']:
        a['lb_cidrs'] = ask_cidrs('External load-balancer source CIDRs', ','.join(old_a.get('lb_cidrs', [])) or None)
    if p['services']['postgresql'] == 'managed':
        a.update(pg_host='localhost', pg_port=6432 if is_ha(p) else 5432, pg_sslmode='verify-full')
    else:
        a.update(pg_host=i.ask('Existing writable PostgreSQL endpoint', old_a.get('pg_host') if old_services.get('postgresql') == 'external' else None, i.v_host),
            pg_port=int(i.ask('PostgreSQL port', str(old_a.get('pg_port', 5432)) if old_services.get('postgresql') == 'external' else '5432', i.v_int(1, 65535))),
            pg_db=i.ask('Database', old_a.get('pg_db', 'litellm'), i.v_ident), pg_user=i.ask('Database owner', old_a.get('pg_user', 'litellm'), i.v_ident), pg_sslmode='verify-full')
        a['pg_bouncer_tx'] = i.ask_yes('PgBouncer transaction pooling?', old_a.get('pg_bouncer_tx', False))
    if p['services']['redis'] == 'managed':
        if is_ha(p):
            a.update(redis_topology='sentinel', redis_nodes=[[n['address'], 26379] for n in p['nodes']], redis_service_name='litellm', redis_sentinel_auth=True)
        else:
            a.update(redis_topology='standalone', redis_nodes=[['localhost', 6379]], redis_service_name='', redis_sentinel_auth=False)
    else:
        a['redis_topology'] = i.ask_choice('Existing Redis topology', [('standalone', 'Single endpoint'), ('sentinel', 'Sentinel'), ('cluster', 'Redis Cluster')],
            old_a.get('redis_topology', 'sentinel'))
        old_endpoints = ','.join(str(h) + ':' + str(port) for h, port in old_a.get('redis_nodes', [])) if old_services.get('redis') == 'external' else None
        a['redis_nodes'] = i.parse_hostports(i.ask('Redis or Sentinel hosts:ports', old_endpoints, i.v_hostports))
        a['redis_service_name'] = i.ask('Sentinel master name', old_a.get('redis_service_name') or 'litellm', i.v_ident) if a['redis_topology'] == 'sentinel' else ''
        a['redis_sentinel_auth'] = a['redis_topology'] == 'sentinel' and i.ask_yes('Sentinel password required?', old_a.get('redis_sentinel_auth', True))
        a['redis_username'] = i.ask('Redis ACL username (empty = default)', old_a.get('redis_username', ''), optional=True, check=i.v_ident)
    p['tls']['external_ca'] = ''
    if 'external' in (p['services']['postgresql'], p['services']['redis']):
        p['tls']['external_ca'] = i.ask('PEM trust bundle for existing PostgreSQL/Redis', old_tls.get('external_ca'), i.v_pem_cert)
    p['tls'].update(frontend_cert='', frontend_key='')
    if p['services']['haproxy']:
        supplied = i.ask_choice('Client-facing TLS certificate', [('generated', 'Generate internal certificate; clients must trust the cluster CA'),
            ('existing', 'Use an existing certificate and private key')], 'existing' if old_tls.get('frontend_cert') else 'generated')
        if supplied == 'existing':
            p['tls']['frontend_cert'] = i.ask('Frontend full-chain PEM certificate', old_tls.get('frontend_cert'), i.v_pem_cert)
            p['tls']['frontend_key'] = i.ask('Frontend private key PEM', old_tls.get('frontend_key'), i.v_pem_key)
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
    require(not sentinel or is_ha(p), 'Sentinel is only used by the three-node deployment')
    lines = ['bind 127.0.0.1' + (' ' + n['address'] if is_ha(p) else ''), 'protected-mode yes', 'port 0', 'tls-port ' + ('26379' if sentinel else '6379'),
        'tls-cert-file ' + b + '/node.crt', 'tls-key-file ' + b + '/node.key', 'tls-ca-cert-file ' + b + '/ca.crt',
        'tls-auth-clients no', 'tls-replication yes', 'daemonize no', 'logfile ""', 'dir /var/lib/litellm-redis',
        'requirepass ' + redis_quote(s['sentinel'] if sentinel else s['redis'])]
    if sentinel:
        lines += ['sentinel monitor litellm ' + p['nodes'][0]['address'] + ' 6379 2', 'sentinel auth-pass litellm ' + redis_quote(s['redis']),
            'sentinel down-after-milliseconds litellm 10000', 'sentinel failover-timeout litellm 60000', 'sentinel parallel-syncs litellm 1',
            'sentinel announce-ip ' + n['address'], 'sentinel announce-port 26379']
    elif is_ha(p):
        lines += ['appendonly yes', 'masterauth ' + redis_quote(s['redis']), 'replica-announce-ip ' + n['address'],
            'replica-announce-port 6379', 'min-replicas-to-write 1', 'min-replicas-max-lag 10']
        if n['name'] != p['nodes'][0]['name']:
            lines.append('replicaof ' + p['nodes'][0]['address'] + ' 6379')
    else:
        lines += ['appendonly yes', 'min-replicas-to-write 0']
    return '\n'.join(lines) + '\n'


def single_postgres_config(p):
    b = '/etc/litellm-cluster/postgres'
    config = "\n".join(["data_directory = '/var/lib/pgsql/data'", "listen_addresses = '127.0.0.1'", 'port = 5432',
        "unix_socket_directories = '/var/run/postgresql'", "hba_file = '" + b + "/pg_hba.conf'", "ssl = on",
        "ssl_cert_file = '" + b + "/node.crt'", "ssl_key_file = '" + b + "/node.key'", "ssl_ca_file = '" + b + "/ca.crt'",
        "password_encryption = 'scram-sha-256'", 'synchronous_standby_names = \'\'']) + '\n'
    hba = 'local all postgres peer\nhostssl ' + p['answers']['pg_db'] + ' ' + p['answers']['pg_user'] + ' 127.0.0.1/32 scram-sha-256\n'
    return config, hba


def haproxy_config(p):
    b = '/etc/haproxy/litellm'
    lines = ['global', '  log stdout format raw local0', '  user haproxy', '  group haproxy', '  maxconn 8192',
        'defaults', '  log global', '  timeout connect 10s', '  timeout client 660s', '  timeout server 660s']
    if is_ha(p) and p['services']['postgresql'] == 'managed':
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
            if is_ha(p):
                files['etcd.json'], files['postgres.json'] = json.dumps(etcd_config(p, n), indent=2), json.dumps(patroni_config(p, n, s), indent=2)
                files['litellm-etcd.service'] = unit('LiteLLM etcd', 'litellm-etcd', '/usr/local/libexec/litellm-etcd --config-file /etc/litellm-cluster/etcd/etcd.json', '/var/lib/litellm-etcd')
                files['litellm-postgres.service'] = unit('LiteLLM PostgreSQL/Patroni', 'postgres', '/opt/litellm-patroni/bin/patroni /etc/litellm-cluster/postgres/postgres.json', '/var/lib/pgsql /var/run/postgresql')
            else:
                files['postgresql.conf'], files['pg_hba.conf'] = single_postgres_config(p)
                files['litellm-postgres.service'] = unit('LiteLLM local PostgreSQL', 'postgres',
                    '/usr/bin/postgres -D /var/lib/pgsql/data -c config_file=/etc/litellm-cluster/postgres/postgresql.conf',
                    '/var/lib/pgsql /var/run/postgresql').replace('[Service]\n', '[Service]\nRuntimeDirectory=postgresql\nRuntimeDirectoryMode=0755\n')
        if p['services']['redis'] == 'managed':
            files['redis.conf'] = redis_config(p, n, s)
            if is_ha(p):
                files['sentinel.conf'] = redis_config(p, n, s, True)
            for role in (('redis', 'sentinel') if is_ha(p) else ('redis',)):
                files['litellm-' + role + '.service'] = unit('LiteLLM Redis ' + role, 'redis', '/usr/bin/redis-server /etc/litellm-cluster/redis/' + role + '.conf'
                    + (' --sentinel' if role == 'sentinel' else ''), '/var/lib/litellm-redis /etc/litellm-cluster/redis')
        if needs_proxy(p):
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


def ensure_tools(p):
    import install as i
    required = {'ansible-playbook': 'ansible-core', 'openssl': 'openssl'}
    if is_ha(p):
        required.update(ssh='openssh-clients', **{'ssh-copy-id': 'openssh-clients'})
    packages = sorted({package for command, package in required.items() if not shutil.which(command)})
    if packages:
        require(interactive() and shutil.which('dnf'), 'Install controller prerequisites: ' + ' '.join(packages))
        require(i.ask_yes('Install missing controller packages from your RHEL repositories: ' + ', '.join(packages) + '?', True), 'Controller prerequisites are required')
        subprocess.run(['dnf', '-y', 'install'] + packages, check=True)
    require(all(shutil.which(command) for command in required), 'Controller prerequisites are still missing')


def ssh_command(p, node, batch=True):
    argv = ['ssh', '-o', 'StrictHostKeyChecking=' + ('yes' if batch else 'ask'),
        '-o', 'ConnectTimeout=10', '-o', 'BatchMode=' + ('yes' if batch else 'no')]
    if p.get('identity_file'):
        argv += ['-i', p['identity_file']]
    return argv + [p['ssh_user'] + '@' + node['address']]


def prepare_ssh(p):
    if not is_ha(p):
        return
    import install as i
    key = Path(p['identity_file']) if p.get('identity_file') else None
    if key and not key.is_file():
        require(interactive(), 'SSH key is missing: ' + str(key))
        require(i.ask_yes('Create a dedicated RSA 3072 SSH key at ' + str(key) + ' for unattended deployment?', True), 'Supply an existing SSH key or agent')
        key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '3072', '-f', str(key), '-N', ''], check=True)
        key.chmod(0o600)
    for node in p['nodes'][1:]:
        result = subprocess.run(ssh_command(p, node) + ['true'], capture_output=True, text=True)
        if result.returncode:
            print('SSH key access to ' + node['name'] + ' is not ready: ' + result.stderr.strip())
            require(interactive() and key, 'Prepare verified SSH key/agent access as ' + p['ssh_user'] + ' to ' + node['address'])
            public_key = Path(str(key) + '.pub')
            require(public_key.is_file(), 'Public key missing: ' + str(public_key) + '; supply its public key before copying it')
            require(i.ask_yes('Install this public key for ' + p['ssh_user'] + '@' + node['address'] + '? Verify the displayed host fingerprint against its console.', True), 'SSH setup cancelled')
            # The user answers OpenSSH host-key and password prompts directly.
            subprocess.run(['ssh-copy-id', '-o', 'StrictHostKeyChecking=ask', '-i', str(public_key),
                            p['ssh_user'] + '@' + node['address']], check=True)
            subprocess.run(ssh_command(p, node) + ['true'], check=True)


def inspect_nodes(p, locked=False):
    """Read addressing before provisioning; resolve 'auto' only for an unapplied plan."""
    import install as i
    script = ("import json,socket,subprocess; print(json.dumps({'hostname':socket.gethostname(),"
        "'interfaces':json.loads(subprocess.check_output(['ip','-j','-4','addr','show','scope','global'],text=True))}))")
    for index, node in enumerate(p['nodes']):
        if index == 0:
            facts = local_facts()
        else:
            result = subprocess.run(ssh_command(p, node) + ['python3 -c ' + shlex.quote(script)],
                                    check=True, capture_output=True, text=True)
            facts = json.loads(result.stdout)
        require(same_host(facts['hostname'], node['name']), node['address'] + ' reports hostname ' + facts['hostname'] + ', expected ' + node['name'])
        detected = address_interface(facts, node['address'])
        require(detected, node['address'] + ' is not assigned to ' + node['name'])
        if node['interface'] == 'auto':
            require(not locked, 'A deployed plan cannot contain an unresolved interface')
            node['interface'] = detected
        elif node['interface'] != detected:
            require(not locked and interactive(), node['name'] + ' uses interface ' + detected + ', not ' + node['interface'])
            require(i.ask_yes(node['name'] + ': address is on ' + detected + '. Correct interface ' + node['interface'] + '?', True), 'Correct the interface before deployment')
            node['interface'] = detected
        print('Verified ' + node['name'] + ' (' + facts['hostname'] + '): ' + node['address'] + ' on ' + detected)
    return validate(p)


def choose_bundle(explicit=None):
    import install as i
    if explicit:
        path = explicit.expanduser().resolve()
    else:
        candidates = sorted({p.resolve() for folder in (HERE, HERE.parent)
            for p in folder.glob('*.tar') if p.with_name(p.name + '.sha256').is_file()},
            key=lambda p: p.stat().st_mtime, reverse=True)
        remembered = ROOT / 'bundle.json'
        if remembered.is_file():
            old = Path(json.loads(remembered.read_text())['path'])
            if old.is_file():
                candidates = [old] + [p for p in candidates if p != old]
        require(interactive(), 'Supply --bundle /absolute/path/cluster.tar')
        path = Path(i.ask('Cluster bundle tar path', str(candidates[0]) if candidates else None,
            lambda value: None if Path(value).expanduser().is_file() else 'File not found.')).expanduser().resolve()
    require(path.is_file(), 'Bundle file not found: ' + str(path))
    sidecar = path.with_name(path.name + '.sha256')
    require(sidecar.is_file(), 'Keep the matching SHA-256 sidecar next to ' + path.name)
    expected = sidecar.read_text().split()
    require(expected and re.fullmatch(r'[0-9a-fA-F]{64}', expected[0]), 'Invalid SHA-256 sidecar')
    print('Verifying bundle SHA-256: ' + path.name)
    require(sha(path) == expected[0].lower(), 'Bundle checksum mismatch; replace it with a verified download')
    return path


def verify_bundle_plan(p, bundle):
    with tarfile.open(bundle, 'r:*') as archive:
        manifests = [m for m in archive.getmembers() if m.isfile() and m.name.count('/') == 1 and m.name.endswith('/BUNDLE.json')]
        require(len(manifests) == 1 and manifests[0].size < 1024 * 1024, 'Expected one valid bundle manifest')
        meta = json.load(archive.extractfile(manifests[0]))
    parts = {part['part'] for part in meta['parts'] if part.get('litellm_version') == p['gateway']['version']
             and part.get('platform') == 'linux/amd64'}
    needed = {'image'} if p['gateway']['mode'] == 'container' else {'litellm', 'python', 'prisma'}
    require(needed <= parts, 'This bundle does not contain ' + p['gateway']['version'] + ' for ' + p['gateway']['mode'] + '. Select a bundled release/runtime.')


def locked_state():
    return any((ROOT / name).exists() for name in ('ownership.json', 'secrets.json', 'work'))


def select_plan(config=None):
    import install as i
    if config:
        return validate(json.loads(config.read_text()))
    saved = ROOT / 'cluster.json'
    if saved.is_file():
        previous = json.loads(saved.read_text())
        try:
            validate(previous)
        except ValueError as exc:
            if locked_state() or not interactive():
                raise
            print('The saved draft needs correction: ' + str(exc))
            if i.ask_yes('Edit this draft now?', True):
                return wizard(previous)
            return None
        if not interactive():
            return previous
        options = [('resume', 'Resume the saved cluster plan')]
        if not locked_state():
            options.append(('edit', 'Edit the saved draft; provisioning has not started'))
        options.append(('cancel', 'Exit'))
        choice = i.ask_choice('A saved plan was found at ' + str(saved), options, 'resume')
        if choice == 'cancel':
            return None
        return wizard(previous) if choice == 'edit' else previous
    return wizard()


def summary(p):
    print(json.dumps({'deployment': 'three-node HA' if is_ha(p) else 'single node; no automatic failover',
        'nodes': p['nodes'], 'ssh_user': p['ssh_user'] if is_ha(p) else 'not used (local connection)',
        'sudo': p.get('sudo_mode', 'legacy; selected at apply') if is_ha(p) else 'controller already runs as root via sudo',
        'gateway': p['gateway'], 'services': p['services'], 'client_cidrs': p['client_cidrs'],
        'gateway_dns': p['answers']['fqdn'], 'frontend': 'VIP' if p['services'].get('vip') else p.get('frontend', 'external load balancer required'),
        'SELinux': 'haproxy_connect_any enabled when a local proxy is selected',
        'scope': 'fresh bootstrap; foreign data/services refused'}, indent=2))


def playbook_command(p, work):
    argv = ['ansible-playbook', '-i', str(work / 'inventory.json'), str(work / 'playbook.json')]
    sudo_mode = p.get('sudo_mode')
    if is_ha(p) and sudo_mode is None and p['ssh_user'] != 'root' and interactive():
        import install as i
        sudo_mode = i.ask_choice('Sudo on nodes 2/3', [('password', 'Prompt for shared sudo password'),
            ('passwordless', 'Passwordless sudo')], 'password')
    if is_ha(p) and sudo_mode == 'password' and p['ssh_user'] != 'root':
        argv.append('--ask-become-pass')
    return argv


def playbook(p, work, bundle, infrastructure):
    pg, redis = p['services']['postgresql'] == 'managed', p['services']['redis'] == 'managed'
    ha = is_ha(p)
    proxy, vip = needs_proxy(p), p['services'].get('vip')
    remote, src = '/var/lib/litellm-cluster', str(work) + '/{{ inventory_hostname }}/'
    def worker(phase, **kw):
        return task(phase, 'command', {'argv': ['python3', remote + '/cluster_node.py', phase, remote + '/node.json']}, no_log=True, **kw)
    pre = [task('Check root and RHEL on every node', 'command', {'argv': ['python3', '-c',
        "import os; s=open('/etc/os-release').read(); assert os.geteuid()==0 and ('ID=\"rhel\"' in s or 'ID=rhel\\n' in s) and 'VERSION_ID=\"9.' in s"]}, changed_when=False),
        directory(remote), task('Check ownership before replacing private staging', 'command', {'argv': ['python3', '-c',
            "import json,pathlib,sys; p=pathlib.Path('/var/lib/litellm-cluster/ownership.json'); d=json.loads(p.read_text()) if p.exists() else {}; sys.exit(0 if not d or (d.get('owner')==sys.argv[1] and d.get('plan_id')==sys.argv[2]) else 1)", OWNER, plan_id(p)]}, changed_when=False),
        copy(HERE / 'cluster_node.py', remote + '/cluster_node.py'), copy(HERE / 'install.py', remote + '/install.py'), copy(src + 'node.json', remote + '/node.json'),
        worker('guard', changed_when=False), worker('claim')]
    result = [play('Preflight all three hosts' if ha else 'Preflight local host', pre)]
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
    if pg and ha:
        setup += [task('Create etcd account', 'user', {'name': 'litellm-etcd', 'system': True, 'create_home': False, 'shell': '/sbin/nologin'}),
            task('Stage offline infrastructure', 'copy', {'src': str(infrastructure) + '/', 'dest': remote + '/infrastructure/', 'mode': 'preserve'}), worker('packages')]
    if proxy:
        setup += [task('Enable SELinux HAProxy backend connections', 'command', {'argv': ['setsebool', '-P', 'haproxy_connect_any', 'on']})]
    result += [play('Install selected prerequisites', setup)]
    config = [directory('/etc/litellm-cluster', mode='0755'), copy(bundle, remote + '/application.tar'),
        copy(src + 'ca.crt', remote + '/ca.crt', mode='0644'), copy(src + 'node.crt', remote + '/node.crt', mode='0644'), copy(src + 'node.key', remote + '/node.key')]
    roles = [('postgres', 'postgres', '/var/lib/pgsql/data')] if pg else []
    if pg and ha:
        roles.insert(0, ('etcd', 'litellm-etcd', '/var/lib/litellm-etcd'))
    if redis:
        roles += [('redis', 'redis', '/var/lib/litellm-redis')]
    for role, owner, data in roles:
        config += [directory(data, owner), directory('/etc/litellm-cluster/' + role, owner)]
        settings = ['redis.conf'] + (['sentinel.conf'] if ha else []) if role == 'redis' else (
            ['postgresql.conf', 'pg_hba.conf'] if role == 'postgres' and not ha else [role + '.json'])
        for name in ['ca.crt', 'node.crt', 'node.key'] + settings:
            config += [copy(src + name, '/etc/litellm-cluster/' + role + '/' + name, owner, force=name not in ('redis.conf', 'sentinel.conf'))]
        for sr in (['redis', 'sentinel'] if role == 'redis' and ha else [role]):
            config += [copy(src + 'litellm-' + sr + '.service', '/etc/systemd/system/litellm-' + sr + '.service', mode='0644')]
    if pg:
        config += [directory('/var/run/postgresql', 'postgres', '0755')]
    if proxy:
        config += [directory('/etc/haproxy/litellm', 'haproxy')]
        config += [copy(src + name, '/etc/haproxy/litellm/' + name, 'haproxy') for name in ('ca.crt', 'client.pem', 'frontend.pem')]
        config += [copy(src + 'haproxy.cfg', '/etc/haproxy/litellm-cluster.cfg', mode='0644'), copy(src + 'litellm-haproxy.service', '/etc/systemd/system/litellm-haproxy.service', mode='0644')]
    config += [worker('firewall')]
    result += [play('Stage services and scoped firewall rules', config)]
    if pg and ha:
        result += [play('Form etcd quorum', [service('litellm-etcd'), task('Wait for etcd quorum', 'command', {'argv': [
            '/usr/local/libexec/litellm-etcdctl', '--endpoints=https://{{ node_address }}:2379', '--cacert=/etc/litellm-cluster/etcd/ca.crt',
            '--cert=/etc/litellm-cluster/etcd/node.crt', '--key=/etc/litellm-cluster/etcd/node.key', 'endpoint', 'health']},
            register='etcd_health', retries=30, delay=2, until='etcd_health.rc == 0', changed_when=False)]),
            play('Form Patroni primary and replicas', [service('litellm-postgres'), worker('database', run_once=True)])]
    elif pg:
        result += [play('Initialize local PostgreSQL', [worker('init-postgres'), service('litellm-postgres'),
            worker('database', run_once=True)])]
    if redis:
        result += [play('Start Redis replicas' if ha else 'Start local Redis', [service('litellm-redis')])]
        if ha:
            result += [play('Form Sentinel quorum', [service('litellm-sentinel'), worker('redis-check', run_once=True)])]
        else:
            result += [play('Verify local Redis', [worker('redis-check')])]
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
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, help='Saved public plan; otherwise resume or start wizard')
    parser.add_argument('--bundle', type=Path, help='Cluster tar; otherwise find it interactively')
    parser.add_argument('--infrastructure', type=Path, help='Offline PostgreSQL HA payload')
    parser.add_argument('--plan-only', action='store_true', help='Save/validate draft; remote nodes unchanged')
    parser.add_argument('--yes', action='store_true', help='Skip only the final apply prompt')
    args = parser.parse_args(argv)
    try:
        import install as i
        if os.geteuid() != 0:
            require(interactive() and shutil.which('sudo'), 'Run with sudo on node 1')
            if not i.ask_yes('Restart this installer with sudo on node 1?', True):
                return 0
            os.execvp('sudo', ['sudo', sys.executable, str(HERE / 'cluster.py')] + argv)
        os.umask(0o077)
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not ROOT.is_symlink() and ROOT.stat().st_uid == 0, 'Controller state must be root-owned')
        ROOT.chmod(0o700)
        p = select_plan(args.config)
        if p is None:
            return 0
        require(same_host(socket.gethostname(), p['nodes'][0]['name']), 'Run on ' + p['nodes'][0]['name'])
        saved = ROOT / 'cluster.json'
        locked = locked_state()
        if locked:
            require(saved.is_file() and plan_id(json.loads(saved.read_text())) == plan_id(p),
                'Provisioning already started. Resume the SAME saved plan; topology changes require an explicit migration')
        else:
            save(saved, p)
        if args.plan_only:
            summary(p)
            print('Draft saved to ' + str(saved) + '; auto interfaces will be detected at apply. Remote nodes unchanged.')
            return 0
        ensure_tools(p)
        bundle = choose_bundle(args.bundle)
        infra = args.infrastructure.resolve() if args.infrastructure else HERE / 'infrastructure'
        while True:
            verify_bundle_plan(p, bundle)
            if is_ha(p) and p['services']['postgresql'] == 'managed':
                from cluster_node import verify_infrastructure
                verify_infrastructure(infra)
            prepare_ssh(p)
            inspect_nodes(p, locked=locked)
            if not locked:
                save(saved, p)
            summary(p)
            if args.yes:
                break
            choices = [('apply', 'Apply this plan to ' + ('ALL THREE nodes' if is_ha(p) else 'THIS node only'))]
            if not locked:
                choices.append(('edit', 'Edit answers before provisioning'))
            choices.append(('exit', 'Save and exit'))
            choice = i.ask_choice('Review the plan', choices, 'exit')
            if choice == 'exit':
                print('Plan saved. Run this command again to resume.')
                return 0
            if choice == 'apply':
                break
            p = wizard(deepcopy(p))
            save(saved, p)
        save(ROOT / 'bundle.json', {'path': str(bundle)})
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
        stage(p, s, work, bundle)
        save(work / 'inventory.json', inventory(p))
        save(work / 'playbook.json', playbook(p, work, bundle, infra))
        env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING='True', ANSIBLE_DISPLAY_ARGS_TO_STDOUT='False', ANSIBLE_LOCAL_TEMP=str(ROOT / 'ansible-tmp'))
        if p.get('sudo_mode') == 'passwordless':
            env['ANSIBLE_BECOME_ASK_PASS'] = 'False'
        r = subprocess.run(playbook_command(p, work), env=env)
        require(r.returncode == 0, 'Deployment failed. Fix the failed phase and rerun; choose Resume saved plan. Keep the SAME bundle and secrets.')
        port = ':4000' if p.get('frontend') == 'direct' else ''
        print('All selected services passed health checks. Gateway: https://' + p['answers']['fqdn'] + port + '/ui')
        return 0
    except KeyboardInterrupt:
        print('\nCoordinator cancelled. Remote actions already started may finish. Rerun to resume the saved plan.', file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, KeyError, OSError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        print('Cluster installer: ' + str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(str(exc.stderr)[-2000:], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
