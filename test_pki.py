"""Exercise real OpenSSL strict verification and the controller CA repair."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import cluster
from test_cluster import plan


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
class PKI(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'var/lib/litellm-cluster'
        self.work = self.state / 'work'
        self.ca = self.work / 'ca'

    def openssl(self, *args, check=True):
        return subprocess.run(['openssl', *map(str, args)], check=check,
                              capture_output=True, text=True)

    def generate(self, legacy=False):
        if legacy:
            self.ca.mkdir(parents=True)
            # Reproduce the old CA: critical CA constraint and SKI, no keyUsage.
            self.openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
                '-subj', '/CN=LiteLLM cluster CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'subjectKeyIdentifier=hash', '-keyout', self.ca / 'ca.key', '-out', self.ca / 'ca.crt')
        if legacy:
            self.legacy_nodes()
        else:
            cluster.pki(plan(), self.work)

    def legacy_nodes(self):
        for n in plan()['nodes']:
            node = self.work / n['name']
            node.mkdir()
            self.openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + n['name'],
                '-keyout', node / 'node.key', '-out', node / 'node.csr')
            (node / 'extensions').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\n'
                'extendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n')
            self.openssl('x509', '-req', '-in', node / 'node.csr', '-CA', self.ca / 'ca.crt',
                '-CAkey', self.ca / 'ca.key', '-set_serial', '123', '-days', '365',
                '-extfile', node / 'extensions', '-out', node / 'node.crt')
        self.ca.joinpath('ca.key').chmod(0o600)

    def repair(self, *args):
        source = Path(__file__).with_name('repair-litellm-ca.sh').read_text()
        source = source.replace('/var/lib/litellm-cluster', str(self.state))
        source = source.replace('/etc/litellm-cluster', str(self.root / 'etc/litellm-cluster'))
        # Only the isolated fixture copy bypasses root for developer test runs.
        source = source.replace('if (( EUID != 0 )); then', 'if false; then')
        return subprocess.run(['bash', '-c', source, 'repair-fixture', *args],
                              capture_output=True, text=True)

    def strict_verify(self):
        for cert in self.work.glob('*/node.crt'):
            for purpose in ('sslserver', 'sslclient'):
                self.openssl('verify', '-x509_strict', '-purpose', purpose,
                             '-CAfile', self.ca / 'ca.crt', cert)

    def test_new_ca_and_all_node_certificates_pass_strict_verification(self):
        self.generate()
        self.strict_verify()
        cluster.pki(plan(), self.work)  # Resume reuses and validates the CA.

    def test_legacy_repair_preserves_identity_keys_and_leaf_certificates(self):
        self.generate(legacy=True)
        ca = self.ca / 'ca.crt'
        original = ca.read_bytes()
        identity = self.openssl('x509', '-in', ca, '-pubkey', '-subject', '-serial', '-noout').stdout
        keys_and_leaves = {p: p.read_bytes() for p in self.work.rglob('*')
                           if p.is_file() and p.name in ('ca.key', 'node.key', 'node.crt')}
        with self.assertRaises(subprocess.CalledProcessError):
            self.strict_verify()
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.strict_verify()
        self.assertEqual(identity, self.openssl('x509', '-in', ca, '-pubkey', '-subject', '-serial', '-noout').stdout)
        for path, contents in keys_and_leaves.items():
            self.assertEqual(path.read_bytes(), contents)
        backup = list(self.ca.glob('repair.*/ca.before.crt'))
        self.assertEqual(len(backup), 1)
        self.assertEqual(backup[0].read_bytes(), original)
        self.assertEqual(backup[0].parent.stat().st_mode & 0o777, 0o700)
        repaired = ca.read_bytes()
        self.assertEqual(self.repair().returncode, 0)
        self.assertEqual(ca.read_bytes(), repaired)
        self.assertEqual(len(list(self.ca.glob('repair.*'))), 1)
        cluster.pki(plan(), self.work)  # Repaired CA is usable on installer resume.

    def test_dry_run_does_not_change_files(self):
        self.generate(legacy=True)
        before = {p: p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        self.assertEqual(self.repair('--dry-run').returncode, 0)
        self.assertEqual(before, {p: p.read_bytes() for p in self.state.rglob('*') if p.is_file()})

    def test_mismatched_private_key_is_refused_without_replacing_ca(self):
        self.generate(legacy=True)
        ca = self.ca / 'ca.crt'
        original = ca.read_bytes()
        self.openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', self.ca / 'ca.key')
        result = self.repair()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('do not match', result.stderr)
        self.assertEqual(ca.read_bytes(), original)
        self.assertEqual(list(self.ca.glob('repair.*')), [])

    def test_invalid_node_certificate_aborts_before_replacing_ca(self):
        self.generate(legacy=True)
        ca = self.ca / 'ca.crt'
        original = ca.read_bytes()
        next(self.work.glob('*/node.crt')).write_text('not a certificate\n')
        result = self.repair()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(ca.read_bytes(), original)
        self.assertIn('CA repair failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
