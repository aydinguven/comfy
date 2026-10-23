# LiteLLM on RHEL 9.8

Offline application bundles with guided single-node or three-node HA bootstrap.
The HA defaults are `idmvllmgwp1`, `idmvllmgwp2` and `idmvllmgwp3`.

Run `sudo python3.12 install.py setup` on the target host/controller and choose
**Single node** or **Three-node HA**. `cluster` remains a command alias.
Single-node mode offers local PostgreSQL 16 and Redis 7 or existing external
services, optional HAProxy, and no SSH/VIP/quorum setup. The interactive wizard detects
hostname/IP/interface defaults, supports SSH as your login user followed by sudo,
offers SSH key setup and a secure sudo-password prompt, and lets you edit or
resume a saved plan. Hostname checks ignore case. The wizard offers existing or managed
PostgreSQL and Redis, optional HAProxy and Keepalived, and native Python or
rootless Podman gateways. See [CLUSTER.md](CLUSTER.md) for prerequisites,
deployment commands, recovery and operational limits.

Download the cluster tar and SHA-256 sidecar from this repository's Releases.
RHEL RPMs require entitled repositories or a local Satellite/mirror; they are
not included in the application tar. The installer has configuration and
archive tests; actual RHEL deployment and failover validation remain required.

For individual gateways, see [GUIDE.md](GUIDE.md) and [RUNBOOK.md](RUNBOOK.md).
Run source tests with `python3 -m unittest -v test_cluster`.

For an intentional fresh start on one host, see
[reset-litellm.sh](reset-litellm.sh) and the reset instructions in
[RUNBOOK.md](RUNBOOK.md). Start with `sudo bash reset-litellm.sh --dry-run`.
