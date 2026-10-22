# LiteLLM on RHEL 9.8

Offline application bundles and a three-node HA bootstrap installer for
`idmvllmgwp1`, `idmvllmgwp2` and `idmvllmgwp3`.

Run `install.py cluster` on node 1. The wizard offers existing or managed
PostgreSQL and Redis, optional HAProxy and Keepalived, and native Python or
rootless Podman gateways. See [CLUSTER.md](CLUSTER.md) for prerequisites,
deployment commands, recovery and operational limits.

Download the cluster tar and SHA-256 sidecar from this repository's Releases.
RHEL RPMs require entitled repositories or a local Satellite/mirror; they are
not included in the application tar. The installer has configuration and
archive tests; actual RHEL deployment and failover validation remain required.

For individual gateways, see [GUIDE.md](GUIDE.md) and [RUNBOOK.md](RUNBOOK.md).
Run source tests with `python3 -m unittest -v test_cluster`.
