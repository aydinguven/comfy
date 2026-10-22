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
    def test_case_insensitive_host_identity_and_duplicates(self):
        self.assertTrue(cluster.same_host('IDMVLLMGWP1.example.test', 'idmvllmgwp1'))
        self.assertFalse(cluster.same_host('idmvllmgwp2', 'idmvllmgwp1'))
        p = plan()
        p['nodes'][1]['name'] = p['nodes'][0]['name'].upper()
        with self.assertRaises(ValueError):
            cluster.validate(p)

    def test_client_network_typo_rejected_but_individual_ip_supported(self):
        self.assertEqual(cluster.parse_cidrs('198.51.100.42, 192.0.2.0/24'), ['198.51.100.42/32', '192.0.2.0/24'])
        for value in ('0.0.0.0/24', '198.51.100.42/24', '127.0.0.1', '224.0.0.0/24', 'bad'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cluster.parse_cidrs(value)

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


class InteractiveBootstrap(unittest.TestCase):
    @staticmethod
    def facts(name, address, interface='ens192'):
        return {'hostname': name, 'interfaces': [{'ifname': interface, 'addr_info': [{'local': address}]}]}

    def test_wizard_detects_controller_login_and_reprompts_bad_client_network(self):
        answers = [''] * 12  # three nodes, then login user, key path and sudo mode
        answers += ['2', '', '', 'n', '2', '', '', '', '0.0.0.0/24', '198.51.100.42', 'gateway.example.test', '', '']
        facts = self.facts('IDMVLLMGWP1', '192.0.2.10')
        with patch.object(cluster, 'local_facts', return_value=facts), patch.object(cluster, 'login_user', return_value='tcmb'), \
                patch.object(cluster, 'default_key', return_value='/root/.ssh/litellm_cluster'), \
                patch.object(cluster, 'suggested_address', side_effect=['192.0.2.10', '192.0.2.11', '192.0.2.12']), \
                patch('builtins.input', side_effect=answers), patch.object(install, 'log'), patch('sys.stdout', new_callable=io.StringIO) as output:
            p = cluster.wizard()
        self.assertEqual(p['nodes'][0]['name'], 'IDMVLLMGWP1')
        self.assertEqual(p['nodes'][1]['interface'], 'auto')
        self.assertEqual(p['ssh_user'], 'tcmb')
        self.assertEqual(p['sudo_mode'], 'password')
        self.assertEqual(p['client_cidrs'], ['198.51.100.42/32'])
        self.assertEqual(p['services']['postgresql'], 'managed')
        self.assertEqual(p['frontend'], 'single-node')
        self.assertEqual(p['tls']['external_ca'], '')
        self.assertIn('does not mean all clients', output.getvalue())

    def test_all_clients_requires_explicit_confirmation(self):
        with patch.object(install, 'ask', side_effect=['0.0.0.0/0', '198.51.100.42']), \
                patch.object(install, 'ask_yes', return_value=False):
            self.assertEqual(cluster.ask_cidrs('Clients'), ['198.51.100.42/32'])

    def test_auto_interface_and_uppercase_remote_hosts(self):
        p = plan()
        p['nodes'][1]['interface'] = p['nodes'][2]['interface'] = 'auto'
        remote = [SimpleNamespace(stdout=json.dumps(self.facts(n['name'].upper(), n['address'], 'ens224')))
                  for n in p['nodes'][1:]]
        with patch.object(cluster, 'local_facts', return_value=self.facts('IDMVLLMGWP1', '192.0.2.10')), \
                patch.object(cluster.subprocess, 'run', side_effect=remote), patch('sys.stdout', new_callable=io.StringIO):
            cluster.inspect_nodes(p)
        self.assertEqual([n['interface'] for n in p['nodes']], ['ens192', 'ens224', 'ens224'])

    def test_worker_accepts_uppercase_hostname_on_owned_retry(self):
        p = plan()
        d = {'owner': cluster.OWNER, 'plan_id': cluster.plan_id(p), 'plan': p, 'node': p['nodes'][0],
             'bundle_sha256': 'test', 'secrets': {'test': 'not-a-real-secret'}}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'ownership.json').write_text(json.dumps(cluster_node.identity(d)))
            with patch.object(cluster_node, 'ROOT', root), patch.object(install, 'os_release', return_value={'ID': 'rhel', 'VERSION_ID': '9.8'}), \
                    patch.object(cluster_node.platform, 'machine', return_value='x86_64'), \
                    patch.object(cluster_node.socket, 'gethostname', return_value='IDMVLLMGWP1'), \
                    patch.object(cluster_node, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.facts('unused', '192.0.2.10')['interfaces']))):
                cluster_node.guard(d)

    def test_shared_sudo_password_is_prompted_not_saved_in_command(self):
        p = plan()
        p.update(ssh_user='tcmb', sudo_mode='password')
        command = cluster.playbook_command(p, Path('/work'))
        self.assertIn('--ask-become-pass', command)
        p['sudo_mode'] = 'passwordless'
        self.assertNotIn('--ask-become-pass', cluster.playbook_command(p, Path('/work')))

    def test_ssh_setup_keeps_host_verification_and_installs_only_public_key(self):
        p = plan()
        p['ssh_user'] = 'tcmb'
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / 'deploy'
            key.write_text('test-only')
            Path(str(key) + '.pub').write_text('test-only-public')
            p['identity_file'] = str(key)
            results = [SimpleNamespace(returncode=1, stderr='Host key verification failed')]
            results += [SimpleNamespace(returncode=0)] * 3
            with patch.object(cluster, 'interactive', return_value=True), patch.object(install, 'ask_yes', return_value=True), \
                    patch.object(cluster.subprocess, 'run', side_effect=results) as run, patch('sys.stdout', new_callable=io.StringIO):
                cluster.prepare_ssh(p)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertIn('StrictHostKeyChecking=yes', calls[0])
            self.assertEqual(calls[1][0], 'ssh-copy-id')
            self.assertIn(str(key) + '.pub', calls[1])
            self.assertIn('StrictHostKeyChecking=ask', calls[1])
            self.assertNotIn(str(key), calls[1])

    def test_plan_only_accepts_case_difference_and_does_not_touch_remote(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = plan()
            p['nodes'][1]['interface'] = 'auto'
            config = root / 'input.json'
            config.write_text(json.dumps(p))
            with patch.object(cluster, 'ROOT', root), patch.object(cluster.os, 'geteuid', return_value=0), \
                    patch.object(cluster.socket, 'gethostname', return_value='IDMVLLMGWP1'), \
                    patch.object(cluster, 'prepare_ssh') as ssh, patch.object(cluster, 'ensure_tools') as tools, \
                    patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(cluster.main(['--config', str(config), '--plan-only']), 0)
                ssh.assert_not_called()
                tools.assert_not_called()
            self.assertEqual(json.loads((root / 'cluster.json').read_text()), p)

    def test_unapplied_invalid_draft_can_be_edited_but_claimed_state_is_locked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = plan()
            p['client_cidrs'] = ['0.0.0.0/24']
            (root / 'cluster.json').write_text(json.dumps(p))
            with patch.object(cluster, 'ROOT', root), patch.object(cluster, 'interactive', return_value=True), \
                    patch.object(install, 'ask_yes', return_value=True), patch.object(cluster, 'wizard', return_value=plan()) as wizard, \
                    patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(cluster.select_plan(), plan())
                wizard.assert_called_once()
                (root / 'secrets.json').write_text('{}')
                with self.assertRaises(ValueError):
                    cluster.select_plan()

    def test_bundle_selection_verifies_sidecar_before_ssh(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'bundle.tar'
            path.write_bytes(b'fake-test-bundle')
            sidecar = path.with_name(path.name + '.sha256')
            sidecar.write_text(cluster.sha(path) + '  bundle.tar\n')
            with patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(cluster.choose_bundle(path), path)
                path.write_bytes(b'corrupt')
                with self.assertRaises(ValueError):
                    cluster.choose_bundle(path)

    def test_full_apply_uses_sudo_prompt_and_saves_no_sudo_credential(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = plan()
            p.update(ssh_user='tcmb', sudo_mode='password')
            config = root / 'input.json'
            config.write_text(json.dumps(p))
            with patch.object(cluster, 'ROOT', root), patch.object(cluster.socket, 'gethostname', return_value='IDMVLLMGWP1'), \
                    patch.object(cluster, 'ensure_tools'), patch.object(cluster, 'choose_bundle', return_value=root / 'bundle.tar'), \
                    patch.object(cluster, 'verify_bundle_plan'), patch.object(cluster_node, 'verify_infrastructure'), \
                    patch.object(cluster, 'prepare_ssh'), patch.object(cluster, 'inspect_nodes'), patch.object(cluster, 'stage'), \
                    patch.object(cluster, 'new_secrets', return_value={'fake_application_secret': 'test-only'}), \
                    patch.object(cluster.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
                    patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(cluster.main(['--config', str(config), '--yes']), 0)
            self.assertIn('--ask-become-pass', run.call_args.args[0])
            inventory = (root / 'work' / 'inventory.json').read_text()
            self.assertNotIn('password', inventory)
            self.assertNotIn('test-only', inventory)
            self.assertEqual(json.loads((root / 'cluster.json').read_text()), p)

    def test_requested_runtime_must_exist_in_bundle_before_provisioning(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'bundle.tar'
            meta = {'parts': [{'part': 'image', 'litellm_version': 'v1.106.2', 'platform': 'linux/amd64'}]}
            body = json.dumps(meta).encode()
            with tarfile.open(path, 'w') as archive:
                member = tarfile.TarInfo('bundle/BUNDLE.json')
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            p = plan()
            cluster.verify_bundle_plan(p, path)
            p['gateway']['mode'] = 'native'
            with self.assertRaises(ValueError):
                cluster.verify_bundle_plan(p, path)


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
                self.assertEqual(json.load(archive.extractfile('bundle/BUNDLE.json'))['cluster_installer'], install.INSTALLER_VERSION)
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
