import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import build_cluster
import cluster
import cluster_node
import install


def plan():
    return {'schema': 1, 'nodes': [{'name': n, 'address': '192.0.2.' + str(10 + i), 'interface': 'ens192'} for i, n in enumerate(cluster.NAMES)],
        'ssh_user': 'root', 'identity_file': '', 'client_cidrs': ['198.51.100.0/24'],
        'services': {'postgresql': 'managed', 'redis': 'managed', 'haproxy': True, 'vip': {'address': '192.0.2.20/24', 'router_id': 51}},
        'gateway': {'version': 'v1.106.2', 'mode': 'container', 'workers': 1},
        'tls': {'external_ca': '', 'frontend_cert': '', 'frontend_key': ''},
        'answers': {'fqdn': 'gateway.example.test', 'host_port': 4000, 'workers': 1, 'node_count': 3, 'node_tls': True,
            'lb_cidrs': ['192.0.2.10/32', '192.0.2.11/32', '192.0.2.12/32'], 'admin_cidrs': [], 'retention': '90d',
            'pg_host': 'localhost', 'pg_port': 6432, 'pg_db': 'litellm', 'pg_user': 'litellm', 'pg_sslmode': 'verify-full',
            'pg_bouncer_tx': False, 'redis_topology': 'sentinel', 'redis_nodes': [['192.0.2.' + str(10 + i), 26379] for i in range(3)],
            'redis_service_name': 'litellm', 'redis_sentinel_auth': True, 'redis_username': '', 'redis_auth': True, 'redis_tls': True, 'model_urls': []}}


class Validation(unittest.TestCase):
    def test_both_postgresql_paths(self):
        p = plan()
        cluster.validate(p)
        p['services']['postgresql'] = 'external'
        p['answers'].update(pg_host='existing.example.test', pg_port=5432)
        cluster.validate(p)

    def test_invalid_nodes_and_managed_endpoints(self):
        changes = [lambda p: p['nodes'][1].update(address=p['nodes'][0]['address']),
            lambda p: p['answers'].update(pg_host='wrong.example.test'),
            lambda p: p['answers'].update(redis_nodes=[['192.0.2.10', 26379]]),
            lambda p: p['services'].update(haproxy=False),
            lambda p: p['gateway'].update(version='v1.107.0'),
            lambda p: p['nodes'][0].update(name='bad\nname')]
        for change in changes:
            p = plan()
            change(p)
            with self.subTest(p=p), self.assertRaises(ValueError):
                cluster.validate(p)

    def test_ssh_host_verification_and_local_controller(self):
        inv = cluster.inventory(plan())['all']['children']['gateways']['hosts']
        self.assertEqual(inv['idmvllmgwp1']['ansible_connection'], 'local')
        self.assertNotIn('ansible_connection', inv['idmvllmgwp2'])
        for v in inv.values():
            self.assertIn('StrictHostKeyChecking=yes', v['ansible_ssh_common_args'])


class Rendering(unittest.TestCase):
    def test_database_quorum_and_sync_policy(self):
        p = plan()
        cfg = cluster.patroni_config(p, p['nodes'][0], {'postgres': 'fake', 'replication': 'fake'})
        self.assertEqual(len(cfg['etcd3']['hosts']), 3)
        self.assertTrue(cfg['bootstrap']['dcs']['synchronous_mode'])
        self.assertTrue(cfg['bootstrap']['dcs']['synchronous_mode_strict'])
        self.assertEqual(cfg['bootstrap']['dcs']['synchronous_node_count'], 1)
        self.assertEqual(cfg['restapi']['verify_client'], 'required')
        self.assertEqual(cfg['postgresql']['authentication']['replication']['sslmode'], 'verify-full')
        etcd = cluster.etcd_config(p, p['nodes'][0])
        self.assertEqual(etcd['initial-cluster'].count('https://'), 3)
        self.assertTrue(etcd['peer-transport-security']['client-cert-auth'])

    def test_redis_roles_and_sentinel_quorum(self):
        p, s = plan(), {'redis': 'fake Redis password', 'sentinel': 'fake Sentinel password'}
        primary = cluster.redis_config(p, p['nodes'][0], s)
        replica = cluster.redis_config(p, p['nodes'][1], s)
        sentinel = cluster.redis_config(p, p['nodes'][2], s, True)
        self.assertNotIn('replicaof ', primary)
        self.assertIn('replicaof 192.0.2.10 6379', replica)
        self.assertIn('sentinel monitor litellm 192.0.2.10 6379 2', sentinel)
        self.assertIn('min-replicas-to-write 1', primary)
        self.assertIn('tls-replication yes', primary)
        self.assertIn('requirepass "fake Redis password"', primary)

    def test_proxy_verifies_tls_and_tracks_primary(self):
        text = cluster.haproxy_config(plan())
        self.assertIn('bind 127.0.0.1:6432', text)
        self.assertIn('GET /primary', text)
        self.assertIn('GET /health/readiness', text)
        self.assertEqual(text.count('verify required'), 6)
        self.assertNotIn('verify none', text)

    def test_order_and_mutable_redis_configuration(self):
        plays = cluster.playbook(plan(), Path('/work'), Path('/bundle.tar'), Path('/infra'))
        names = [x['name'] for x in plays]
        self.assertLess(names.index('Form etcd quorum'), names.index('Form Patroni primary and replicas'))
        self.assertLess(names.index('Form Patroni primary and replicas'), names.index('Install and health-check gateways sequentially'))
        self.assertLess(names.index('Install and health-check gateways sequentially'), names.index('Activate VIP after all gateways are healthy'))
        self.assertEqual(next(x for x in plays if x['name'].startswith('Install and health-check'))['serial'], 1)
        copies = [t['ansible.builtin.copy'] for x in plays for t in x['tasks'] if 'ansible.builtin.copy' in t]
        mutable = [x for x in copies if x['dest'].endswith(('redis.conf', 'sentinel.conf'))]
        self.assertEqual(len(mutable), 2)
        self.assertTrue(all(x['force'] is False for x in mutable))

    def test_optional_infrastructure_omitted(self):
        p = plan()
        p['services'] = {'postgresql': 'external', 'redis': 'external', 'haproxy': False, 'vip': None}
        output = json.dumps(cluster.playbook(p, Path('/work'), Path('/bundle.tar'), Path('/infra')))
        for forbidden in ('postgresql:16', 'redis:7', 'litellm-etcd', 'keepalived.conf'):
            self.assertNotIn(forbidden, output)

    def test_vip_priorities_and_peers(self):
        p = plan()
        for index, n in enumerate(p['nodes']):
            text = cluster.keepalived_config(p, n)
            self.assertIn('state BACKUP', text)
            self.assertIn('nopreempt', text)
            self.assertIn('priority ' + str(150 - 10 * index), text)
            self.assertEqual(text.count('    192.0.2.'), 3)


class ContainerNetworking(unittest.TestCase):
    def test_local_database_proxy_is_reachable(self):
        a = {'host_port': 4000, 'workers': 1, 'node_tls': True, 'cluster_host_network': True}
        text = install.render_unit(a, 'localhost/litellm:test', True, [])
        self.assertIn('Network=host', text)
        self.assertNotIn('PublishPort=', text)
        a['cluster_host_network'] = False
        self.assertIn('PublishPort=4000:4000', install.render_unit(a, 'localhost/litellm:test', True, []))

    def test_probe_network_matches_runtime(self):
        a = plan()['answers']
        a['cluster_host_network'] = True
        with patch.object(install, 'step'), patch.object(install, 'run') as run, patch.object(install, 'report_probe', return_value=True):
            self.assertTrue(install.run_probe(a, 'localhost/litellm:test', True, []))
            self.assertIn('--network=host', run.call_args.args[0])

    def test_migration_network_matches_runtime(self):
        with patch.object(install, 'step'), patch.object(install, 'good'), patch.object(install, 'run') as run:
            run.return_value.returncode = 0
            install.migrate('localhost/litellm:test', True, host_network=True)
            self.assertIn('--network=host', run.call_args.args[0])


class Bundling(unittest.TestCase):
    def test_retry_does_not_replace_running_etcd_executables(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive_path = root / 'etcd.tar.gz'
            with tarfile.open(archive_path, 'w:gz') as archive:
                for name in ('etcd', 'etcdctl'):
                    data = ('fake-' + name).encode()
                    member = tarfile.TarInfo('etcd-v3.6.7-linux-amd64/' + name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            dest = root / 'bin'
            with patch.object(cluster_node, 'run'), patch.object(cluster_node.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
                cluster_node.install_etcd_archive(archive_path, dest)
            inode = (dest / 'litellm-etcd').stat().st_ino
            with patch.object(cluster_node, 'run'), patch.object(cluster_node.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                cluster_node.install_etcd_archive(archive_path, dest)
            self.assertEqual((dest / 'litellm-etcd').stat().st_ino, inode)
            (dest / 'litellm-etcd').write_bytes(b'different-running-binary')
            with patch.object(cluster_node, 'run'), patch.object(cluster_node.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                with self.assertRaises(RuntimeError):
                    cluster_node.install_etcd_archive(archive_path, dest)
            self.assertEqual((dest / 'litellm-etcd').read_bytes(), b'different-running-binary')

    def test_preserves_payload_refreshes_installer_checksums(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old, new = root / 'old.tar', root / 'new.tar'
            entries = {'bundle/install.py': b'old', 'bundle/PART.json': b'old', 'bundle/SHA256SUMS': b'old',
                'bundle/BUNDLE.json': b'{"parts":[]}', 'bundle/parts/image/data': b'keep-identical'}
            with tarfile.open(old, 'w') as archive:
                for name, data in entries.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            (root / 'install.py').write_bytes(b'new')
            with patch.object(build_cluster, 'HERE', root), patch.object(build_cluster, 'FILES', ('install.py',)), patch.object(build_cluster, 'installer_bytes', return_value=b'new'):
                build_cluster.combine(old, new, None)
            with tarfile.open(new) as archive:
                self.assertEqual(archive.extractfile('bundle/parts/image/data').read(), b'keep-identical')
                self.assertEqual(archive.extractfile('bundle/install.py').read(), b'new')
                self.assertIn(hashlib.sha256(b'new').hexdigest() + '  install.py', archive.extractfile('bundle/SHA256SUMS').read().decode())
                self.assertEqual(json.load(archive.extractfile('bundle/BUNDLE.json'))['cluster_installer'], '2026-10-22.5')
            self.assertEqual(new.with_name('new.tar.sha256').read_text().split()[0], build_cluster.sha(new))

    def test_rejects_corruption_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'SHA256SUMS').write_text('0' * 64 + '  ../outside\n')
            with self.assertRaises(RuntimeError):
                cluster_node.verify_infrastructure(root)
            (root / 'payload').write_text('corrupt')
            (root / 'SHA256SUMS').write_text('0' * 64 + '  payload\n')
            with self.assertRaises(RuntimeError):
                cluster_node.verify_infrastructure(root)
            (root / 'link').symlink_to(root / 'payload')
            (root / 'SHA256SUMS').write_text(cluster_node.sha(root / 'payload') + '  link\n')
            with self.assertRaises(RuntimeError):
                cluster_node.verify_infrastructure(root)

    def test_secret_file_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'secret.json'
            cluster.save(path, {'fake': 'test-only'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.chmod(0o644)
            cluster.save(path, {'fake': 'updated'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
