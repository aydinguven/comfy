"""Exercise reset ordering with fake services and real moves inside a temporary tree."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Reset(unittest.TestCase):
    def run_fixture(self, scenario='', args=(), confirmation='testnode\n'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        commands = root / 'bin'
        commands.mkdir()
        for path in ('var/lib', 'etc', 'opt', 'srv', 'run/lock'):
            (root / path).mkdir(parents=True)
        original = root / 'var/lib/pgsql/data'
        original.mkdir(parents=True)
        (original / 'PG_VERSION').write_text('16\n')
        state = root / 'var/lib/litellm-cluster'
        state.mkdir()
        (state / 'secrets.json').write_text('{"fake":"fixture-secret"}')
        source = Path(__file__).with_name('reset-litellm.sh').read_text()
        for prefix in ('/var/lib/', '/etc/', '/opt/', '/srv/', '/run/lock/'):
            source = source.replace(prefix, str(root) + prefix)
        # This COPY operates solely in the temporary tree, including its lock.
        # Let ordinary unprivileged developers exercise it too.
        source = source.replace('if (( EUID != 0 )); then', 'if false; then')
        script = root / 'reset-fixture.sh'
        script.write_text(source)
        mocks = {
            'hostname': 'echo TESTNODE',
            'systemctl': '''echo "$*" >>"$TEST_LOG"
if [[ "$1" == stop && "$SCENARIO" == stop-fails ]]; then exit 1; fi
exit 0''',
            'pgrep': 'if [[ "$SCENARIO" == process-check-fails ]]; then exit 2; fi; if [[ "$SCENARIO" == postgres-busy ]]; then echo "123 postgres"; exit 0; fi; exit 1',
            'ss': 'if [[ "$SCENARIO" == listener-busy ]]; then echo "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*"; fi',
            'mountpoint': '[[ "$SCENARIO" == mounted ]]',
        }
        for name, body in mocks.items():
            command = commands / name
            command.write_text('#!/bin/bash\n' + body + '\n')
            command.chmod(0o755)
        env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'], SCENARIO=scenario,
                   TEST_LOG=str(root / 'commands.log'))
        result = subprocess.run(['bash', str(script), *args], input=confirmation,
                                env=env, capture_output=True, text=True)
        return root, original, state, result

    def assert_not_moved(self, root, original, state):
        self.assertTrue((original / 'PG_VERSION').is_file())
        self.assertTrue((state / 'secrets.json').is_file())
        self.assertEqual(list((root / 'var/lib').glob('litellm-reset.*')), [])

    def test_dry_run_has_no_service_or_filesystem_mutations(self):
        root, original, state, result = self.run_fixture(args=('--dry-run',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_not_moved(root, original, state)
        self.assertFalse((root / 'commands.log').exists())
        self.assertFalse((root / 'var/lib/litellm-reset-lock').exists())

    def test_busy_process_listener_or_stop_failure_never_moves_data(self):
        for scenario in ('postgres-busy', 'listener-busy', 'stop-fails', 'process-check-fails'):
            with self.subTest(scenario=scenario):
                root, original, state, result = self.run_fixture(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assert_not_moved(root, original, state)

    def test_mounted_directory_is_refused_before_service_stops(self):
        root, original, state, result = self.run_fixture('mounted')
        self.assertNotEqual(result.returncode, 0)
        self.assert_not_moved(root, original, state)
        self.assertFalse((root / 'commands.log').exists())

    def test_wrong_hostname_cancels_without_stopping_services(self):
        root, original, state, result = self.run_fixture(confirmation='wronghost\n')
        self.assertNotEqual(result.returncode, 0)
        self.assert_not_moved(root, original, state)
        self.assertFalse((root / 'commands.log').exists())

    def test_success_preserves_data_in_private_backup(self):
        root, original, state, result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(original.exists())
        self.assertFalse(state.exists())
        backups = list((root / 'var/lib').glob('litellm-reset.*'))
        self.assertEqual(len(backups), 1)
        backup = backups[0]
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup / str(original).lstrip('/') / 'PG_VERSION').read_text(), '16\n')
        self.assertIn('fixture-secret', (backup / str(state).lstrip('/') / 'secrets.json').read_text())
        self.assertNotIn('fixture-secret', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
