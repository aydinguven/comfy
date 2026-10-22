# LiteLLM operations

See CLUSTER.md for bootstrap retries, infrastructure services and failover checks.

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
