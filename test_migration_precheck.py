"""Check the diagnostic disclosure boundary and runtime-specific status command."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('migration_precheck', Path(__file__).with_name('migration-precheck.py'))
precheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(precheck)


class MigrationPrecheck(unittest.TestCase):
    def plan(self):
        return {'nodes': [{'name': 'node1', 'address': '192.0.2.10', 'interface': 'ens192', 'password': 'DO-NOT-SHARE'}],
                'services': {'postgresql': 'managed', 'redis': 'managed', 'haproxy': True},
                'gateway': {'mode': 'container', 'workers': 1, 'version': 'v1.106.2', 'master_key': 'DO-NOT-SHARE'},
                'answers': {'fqdn': 'gateway.example.test', 'pg_host': 'localhost', 'pg_port': 5432,
                    'redis_topology': 'standalone', 'redis_nodes': [['localhost', 6379]], 'password': 'DO-NOT-SHARE'},
                'secrets': {'master': 'DO-NOT-SHARE'}}

    def test_nested_secrets_and_credential_urls_are_not_disclosed(self):
        plan = self.plan()
        plan['answers']['pg_host'] = 'postgres://user:DO-NOT-SHARE@localhost'
        output = json.dumps(precheck.public_plan(plan))
        self.assertNotIn('DO-NOT-SHARE', output)
        self.assertNotIn('password', output)
        self.assertNotIn('master', output)
        self.assertIn('192.0.2.10', output)

    def test_plan_only_does_not_query_services_or_change_input(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / 'cluster.json'
            config.write_text(json.dumps(self.plan()))
            original = config.read_bytes()
            with patch.object(precheck, 'service_status') as status, patch.object(precheck, 'readiness') as readiness, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(precheck.main(['--config', str(config), '--plan-only']), 0)
            status.assert_not_called()
            readiness.assert_not_called()
            self.assertEqual(config.read_bytes(), original)
            self.assertEqual(list(Path(td).iterdir()), [config])
            self.assertNotIn('DO-NOT-SHARE', output.getvalue())

    def test_status_uses_user_service_for_rootless_and_suppresses_arbitrary_output(self):
        with patch.object(precheck.subprocess, 'run', return_value=SimpleNamespace(stdout='active\n')) as run:
            self.assertEqual(precheck.service_status('litellm', user=True), 'active')
        self.assertEqual(run.call_args.args[0], ['systemctl', '--user', '-M', 'litellm@', 'is-active', 'litellm'])
        with patch.object(precheck.subprocess, 'run', return_value=SimpleNamespace(stdout='DO-NOT-SHARE\n')):
            self.assertEqual(precheck.service_status('litellm'), 'unknown')

    def test_full_report_selects_only_runtime_mode_from_state(self):
        with tempfile.TemporaryDirectory() as td:
            config, state = Path(td) / 'cluster.json', Path(td) / 'state.json'
            config.write_text(json.dumps(self.plan()))
            state.write_text(json.dumps({'mode': 'native', 'ref': 'DO-NOT-SHARE', 'master': 'DO-NOT-SHARE'}))
            with patch.object(precheck, 'service_status', return_value='active') as status, \
                    patch.object(precheck, 'readiness', return_value={'http_status': 200, 'result': 'ready'}), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(precheck.main(['--config', str(config), '--state', str(state)]), 0)
            self.assertEqual(status.call_args_list[0].kwargs, {'user': False})
            self.assertIn('"runtime_mode": "native"', output.getvalue())
            self.assertNotIn('DO-NOT-SHARE', output.getvalue())

    def test_malformed_json_error_does_not_echo_input(self):
        with tempfile.TemporaryDirectory() as td:
            config = Path(td) / 'cluster.json'
            config.write_text('{"password":"DO-NOT-SHARE" BROKEN}')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(precheck.main(['--config', str(config), '--plan-only']), 1)
            self.assertNotIn('DO-NOT-SHARE', output.getvalue())


if __name__ == '__main__':
    unittest.main()
