# LiteLLM operations

See CLUSTER.md for single-node/HA setup, bootstrap retries, infrastructure
services and failover checks. Installer 2026-10-23.1 adds the deployment-size
choice through `sudo python3.12 install.py setup` (`cluster` remains an alias).
Single-node services use litellm-postgres, litellm-redis and optional
litellm-haproxy; they have no automatic failover. Resume with the same plan and
bundle. Switching an existing deployment between one and three nodes is a
migration, not a bootstrap retry.

If a gateway dependency probe reports `CA cert does not include key usage
extension`, repair the original controller CA with
[repair-litellm-ca.sh](repair-litellm-ca.sh):

    sudo bash repair-litellm-ca.sh --dry-run
    sudo bash repair-litellm-ca.sh
    sudo python3.12 install.py setup

Choose **Resume saved plan** and retain the same bundle and secrets. The helper
preserves the CA private key, subject and serial, and all existing node
certificates. It archives the original CA certificate in a root-only
`/var/lib/litellm-cluster/work/ca/repair.XXXXXXXX` directory. Before atomically
replacing the controller CA certificate it checks all discovered staged and
local PostgreSQL/Redis node certificates with `openssl verify -x509_strict`
for both TLS server and client use. A validation failure leaves the original
CA certificate in place. A valid deployment is left unchanged. Dry run does
not write files. Run only on the controller, with no installer/CA changes in
progress; the repair lock serializes repair helpers, not installer runs.

Resume restages the repaired CA onto every node in the saved plan and updates
the gateway trust bundle. The helper itself does not contact nodes or restart
services. For an existing live deployment, use a separate maintenance plan;
this procedure targets the failed bootstrap. It is not CA/key rotation or
certificate renewal. Source certificate generation includes the required
extensions; previously published release bundles are unchanged by this source
fix. Run PKI/repair regression tests with `python3 -m unittest -v test_pki`.

For a deliberate fresh start on one host, use [reset-litellm.sh](reset-litellm.sh):

    sudo bash reset-litellm.sh --dry-run
    sudo bash reset-litellm.sh

It asks for the hostname, stops/disables PostgreSQL and LiteLLM's system services,
and archives existing data/configuration under a root-only
`/var/lib/litellm-reset.XXXXXXXX` directory. All PostgreSQL databases under
`/var/lib/pgsql/data` are taken offline, including any unrelated databases there.
It refuses mounted data directories, running PostgreSQL processes and remaining
installation-port listeners before moving data. A refusal after service stops
leaves those services stopped; resolve the reported issue before proceeding.
It keeps packages, SSH keys, firewall rules and cached Podman images. Stop any
rootless/unrelated service reported by the listener check separately after
identifying it. The helper affects only its current host and never contacts
other nodes or external services. Keep the backup until the replacement works;
partially failed moves must be inspected before retrying.

For installer 2026-10-22.6, rerun `sudo python3.12 install.py cluster` on node 1
and choose Resume. Sudo-password prompts are selected in the wizard; an
`ANSIBLE_BECOME_ASK_PASS` environment variable is no longer required. An
unapplied draft can be edited; an attempted deployment retains its plan/secrets.

    sudo python3 install.py status
    sudo python3 install.py check

Answers/state are in /srv/litellm. Installer logs are in
/var/log/litellm-installer.log. Share only redacted logs.

For rolling LiteLLM upgrades, back up the database, read release notes, drain
one gateway from the load balancer and run:

    sudo python3 install.py upgrade --bundle /path/new-bundle.tar --version vX.Y.Z

Confirm health before returning it to traffic and continuing to the next node.
Rollback restores a previous installed application release, not database schema.

Database restores, PostgreSQL major upgrades, etcd membership changes, Redis
topology changes, secret rotation and certificate renewal need separate
procedures. Cluster bootstrap refuses topology changes.

Back up /var/lib/litellm-cluster/cluster.json, secrets.json and work/ca securely.
Keep master/salt keys identical on all nodes and future upgrades.
