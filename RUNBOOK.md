# LiteLLM operations

See CLUSTER.md for bootstrap retries, infrastructure services and failover checks.

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
