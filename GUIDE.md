# LiteLLM RHEL installer

For guided single-node or three-node deployment, run:

    sudo python3.12 install.py setup

Choose 1 for single node or 2 for three-node HA. See [CLUSTER.md](CLUSTER.md).
Both offer external or installer-managed PostgreSQL and Redis, optional HAProxy,
and both LiteLLM runtime modes. Single-node mode uses local standalone services
and does not configure SSH, Sentinel, Patroni, etcd or Keepalived.

For the legacy gateway-only installer with existing external services, verify
and extract the bundle, then run:

    python3 install.py parts --verify
    sudo python3 install.py install

Single-node mode expects external PostgreSQL and Redis. The application payload
is offline; RHEL packages come from entitled repositories or Satellite. Run the
installer on each node with identical master/salt keys and service settings.
Models are managed in LiteLLM's UI and stored in PostgreSQL.

Build application parts on a connected host:

    python3.12 build_bundle.py --version v1.106.2 --parts all

Use build_cluster.py to add PostgreSQL HA dependencies and the new installer to
an existing verified bundle. RHEL deployment and failover tests remain separate
from archive/configuration verification.
