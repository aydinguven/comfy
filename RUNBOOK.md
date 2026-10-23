# LiteLLM operations

See CLUSTER.md for single-node/HA setup, bootstrap retries, infrastructure
services and failover checks. Installer 2026-10-23.1 adds the deployment-size
choice through `sudo python3.12 install.py setup` (`cluster` remains an alias).
Single-node services use litellm-postgres, litellm-redis and optional
litellm-haproxy; they have no automatic failover. Resume with the same plan and
bundle. Switching an existing deployment between one and three nodes is a
migration, not a bootstrap retry.

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
