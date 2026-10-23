"""Regression checks for the RHEL bootstrap failures and node-1 datastores."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import http.server
import socket
import ssl
import threading
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import cluster
import cluster_node
import install
from test_cluster import plan, single_plan


def central_plan():
    p = plan()
    p['datastores'] = 'node1'
    p['answers'].update(pg_host=p['nodes'][0]['address'], pg_port=5432,
        redis_topology='standalone', redis_nodes=[[p['nodes'][0]['address'], 6379]],
        redis_service_name='', redis_sentinel_auth=False)
    return p


class NodeOneDatastores(unittest.TestCase):
    def test_endpoints_are_shared_and_legacy_ha_is_unchanged(self):
        p = central_plan()
        cluster.validate(p)
        self.assertFalse(cluster.datastore_ha(p))
        self.assertTrue(cluster.datastore_ha(plan()))
        for endpoint in ('localhost', p['nodes'][1]['address']):
            with self.subTest(endpoint=endpoint):
                p['answers']['pg_host'] = endpoint
                with self.assertRaises(ValueError):
                    cluster.validate(p)

    def test_only_node_one_gets_database_files_and_service_plays(self):
        p = central_plan()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for n in p['nodes']:
                (root / n['name']).mkdir()
            bundle = root / 'application.tar'
            bundle.write_bytes(b'fixture')
            with patch.object(cluster, 'pki'):
                cluster.stage(p, {'redis': 'fake-password'}, root, bundle)
            for index, n in enumerate(p['nodes']):
                node = root / n['name']
                self.assertEqual((node / 'postgresql.conf').exists(), index == 0)
                self.assertEqual((node / 'redis.conf').exists(), index == 0)
                self.assertTrue((node / 'haproxy.cfg').exists())
                self.assertFalse((node / 'postgres.json').exists())
                self.assertFalse((node / 'etcd.json').exists())
                self.assertFalse((node / 'sentinel.conf').exists())
            cfg, hba = cluster.single_postgres_config(p)
            self.assertIn("listen_addresses = '127.0.0.1,192.0.2.10'", cfg)
            for n in p['nodes']:
                self.assertIn(n['address'] + '/32 scram-sha-256', hba)
            self.assertNotIn('0.0.0.0/0', hba)
            redis = (root / p['nodes'][0]['name'] / 'redis.conf').read_text()
            self.assertIn('min-replicas-to-write 0', redis)
            self.assertNotIn('replicaof', redis)
        plays = cluster.playbook(p, Path('/work'), Path('/bundle'), Path('/infra'))
        by_name = {x['name']: x for x in plays}
        for name in ('Initialize local PostgreSQL', 'Start local Redis', 'Verify local Redis'):
            self.assertEqual(by_name[name]['hosts'], p['nodes'][0]['name'])
        self.assertEqual(by_name['Install and health-check gateways sequentially']['hosts'], 'gateways')
        output = json.dumps(plays)
        self.assertNotIn('Form etcd', output)
        self.assertNotIn('Form Sentinel', output)
        self.assertNotIn('patroni', output)
        for play in plays:
            for task in play['tasks']:
                if '/etc/litellm-cluster/postgres/' in task['name'] or '/etc/litellm-cluster/redis/' in task['name']:
                    self.assertIn(p['nodes'][0]['name'], task['when'])

    def test_service_placement_and_firewall_ports(self):
        p = central_plan()
        for index, n in enumerate(p['nodes']):
            d = {'plan': p, 'node': n}
            self.assertEqual(cluster_node.managed_here(d, 'postgresql'), index == 0)
            self.assertEqual(cluster_node.managed_here(d, 'redis'), index == 0)
            with patch.object(cluster_node, 'run') as run, patch.object(cluster_node.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                cluster_node.firewall(d)
            calls = [call.args[0] for call in run.call_args_list]
            rules = '\n'.join(' '.join(call) for call in calls if call[0] == 'firewall-cmd')
            for port in (5432, 6379):
                self.assertEqual('port="' + str(port) + '"' in rules, index == 0)
            self.assertNotIn('26379', rules)
            if index == 0:
                self.assertEqual(rules.count('port="5432"'), 3)
                self.assertEqual(rules.count('port="6379"'), 3)
            with patch.object(cluster_node, 'ensure_package') as packages:
                cluster_node.package_versions(d)
                self.assertEqual(packages.call_count, 2 if index == 0 else 0)

    def test_wizard_third_option_is_node_one_placement(self):
        answers = ['3'] + [''] * 12
        answers += ['', '', '', 'n', '2', '', '', '', '198.51.100.42', 'gateway.example.test', '', '']
        facts = {'hostname': 'IDMVLLMGWP1', 'interfaces': [{'ifname': 'ens192', 'addr_info': [{'local': '192.0.2.10'}]}]}
        with patch.object(cluster, 'local_facts', return_value=facts), patch.object(cluster, 'login_user', return_value='tcmb'), \
                patch.object(cluster, 'default_key', return_value='/root/.ssh/fixture'), \
                patch.object(cluster, 'suggested_address', side_effect=['192.0.2.10', '192.0.2.11', '192.0.2.12']), \
                patch('builtins.input', side_effect=answers), patch.object(install, 'log'), contextlib.redirect_stdout(io.StringIO()) as output:
            p = cluster.wizard()
        self.assertEqual(p['datastores'], 'node1')
        self.assertEqual(p['answers']['pg_host'], '192.0.2.10')
        self.assertEqual(p['answers']['redis_nodes'], [['192.0.2.10', 6379]])
        self.assertEqual(p['ssh_user'], 'tcmb')
        self.assertIn('NO automatic failover', output.getvalue())


class BootstrapFailures(unittest.TestCase):
    def test_rhel_services_allow_normal_selinux_transition_and_keep_sandbox(self):
        for user in ('postgres', 'redis'):
            unit = cluster.unit('fixture', user, '/bin/fixture', '/var/lib/fixture')
            self.assertIn('NoNewPrivileges=false', unit)
            self.assertIn('ProtectSystem=strict', unit)
            self.assertIn('ProtectHome=true', unit)
        self.assertIn('NoNewPrivileges=true', cluster.unit('fixture', 'litellm-etcd', '/bin/fixture', '/var/lib/fixture'))

    def test_package_switch_is_allowed_only_with_empty_data(self):
        with tempfile.TemporaryDirectory() as td:
            exe, data = Path(td) / 'postgres', Path(td) / 'data'
            exe.touch()
            data.mkdir()
            old = SimpleNamespace(stdout='postgres (PostgreSQL) 13.23')
            new = SimpleNamespace(stdout='postgres (PostgreSQL) 16.10')
            with patch.object(cluster_node, 'run', side_effect=[old, SimpleNamespace(stdout=''), new]) as run:
                cluster_node.ensure_package('postgresql', 'postgresql:16/server', str(exe), ' 16.', str(data))
                self.assertEqual(run.call_args_list[1].args[0], ['dnf', '-y', 'module', 'switch-to', 'postgresql:16/server'])
            (data / 'PG_VERSION').write_text('13\n')
            with patch.object(cluster_node, 'run', return_value=old) as run, self.assertRaises(RuntimeError):
                cluster_node.ensure_package('postgresql', 'postgresql:16/server', str(exe), ' 16.', str(data))
            self.assertEqual(run.call_count, 1)
            with patch.object(cluster_node, 'run', return_value=new) as run:
                cluster_node.ensure_package('postgresql', 'postgresql:16/server', str(exe), ' 16.', str(data))
            self.assertEqual(run.call_count, 1)

    def test_changed_tls_and_unit_files_trigger_restart_but_mutable_redis_is_retained(self):
        plays = cluster.playbook(central_plan(), Path('/work'), Path('/bundle'), Path('/infra'))
        starts = {t['name']: t for p in plays for t in p['tasks'] if 'ansible.builtin.systemd' in t}
        for name in ('litellm-postgres', 'litellm-redis', 'litellm-haproxy'):
            state = starts['Start ' + name]['ansible.builtin.systemd']['state']
            self.assertIn('restarted', state)
            self.assertIn('_ca_crt.changed', state)
        redis = [t['ansible.builtin.copy'] for p in plays for t in p['tasks']
                 if 'ansible.builtin.copy' in t and t['ansible.builtin.copy']['dest'].endswith('/redis.conf')]
        self.assertFalse(redis[0]['force'])

    def test_probe_details_reach_the_worker_exception(self):
        def probe(*args):
            print('[FAIL] postgres.tls: CA cert does not include key usage extension')
            return False
        installer = SimpleNamespace(run_probe_any=probe, secret_names=lambda a: [])
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'postgres.tls'):
            cluster_node.dependency_probe(installer, {}, 'ref', True, None)

    def test_worker_redacts_probe_details_before_saving_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            secret = root / 'node.json'
            secret.write_text(json.dumps({'secrets': {'database': 'fixture secret'}}))
            secret.chmod(0o600)
            with patch.object(cluster_node, 'ROOT', root), patch.object(cluster_node, 'SECRET_FILE', secret), \
                    patch.object(cluster_node.os, 'geteuid', return_value=0), \
                    patch.object(cluster_node, 'gateway', side_effect=RuntimeError('postgres.login: fixture secret / fixture%20secret')), \
                    patch('sys.argv', ['worker', 'gateway', str(secret)]), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cluster_node.main(), 1)
            result = (root / 'last-error.txt').read_text()
            self.assertIn('postgres.login', result)
            self.assertNotIn('fixture', result)
            self.assertEqual((root / 'last-error.txt').stat().st_mode & 0o777, 0o600)

    def test_frontend_rejects_503_and_preserves_sni_verification(self):
        d = {'plan': central_plan(), 'node': central_plan()['nodes'][0], 'secrets': {'master': 'fixture'}}
        def raw(*args, **kwargs):
            return contextlib.nullcontext(SimpleNamespace())
        ctx = SimpleNamespace(load_verify_locations=lambda **kw: None,
            wrap_socket=lambda *args, **kw: contextlib.nullcontext(SimpleNamespace(sendall=lambda b: None)))
        with patch.object(cluster_node.ssl, 'create_default_context', return_value=ctx), \
                patch.object(cluster_node.socket, 'create_connection', side_effect=raw), \
                patch.object(cluster_node.http.client, 'HTTPResponse', return_value=SimpleNamespace(begin=lambda: None, status=503)), \
                patch.object(cluster_node.time, 'monotonic', side_effect=[0, 1, 46]), patch.object(cluster_node.time, 'sleep'), \
                self.assertRaisesRegex(RuntimeError, '503'):
            cluster_node.frontend_health(d)

    def test_real_frontend_tls_waits_for_health_and_rejects_wrong_hostname(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = single_plan()
            cluster.pki(p, root)
            node = root / p['nodes'][0]['name']
            statuses = [503, 200]
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(statuses.pop(0) if statuses else 200)
                    self.end_headers()
                def log_message(self, *args):
                    pass
            server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(node / 'node.crt'), str(node / 'node.key'))
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            real_connect = socket.create_connection
            def connect(address, timeout):
                self.assertEqual(address, ('127.0.0.1', 443))
                return real_connect(('127.0.0.1', server.server_port), timeout=timeout)
            d = {'plan': p, 'node': {'address': '127.0.0.1'}, 'secrets': {'master': 'fixture'}}
            p['answers']['fqdn'] = 'localhost'
            try:
                with patch.object(cluster_node, 'ROOT', root / 'ca'), \
                        patch.object(cluster_node.socket, 'create_connection', side_effect=connect), \
                        patch.object(cluster_node.time, 'sleep'):
                    cluster_node.frontend_health(d)
                    self.assertEqual(statuses, [])
                    p['answers']['fqdn'] = 'wrong.example.test'
                    with patch.object(cluster_node.time, 'monotonic', side_effect=[0, 1, 46]), \
                            self.assertRaisesRegex(RuntimeError, 'certificate verify failed'):
                        cluster_node.frontend_health(d)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
