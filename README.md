# LiteLLM on RHEL 9.8

Offline application bundles with guided single-node, three-node HA, or three
gateway bootstrap with PostgreSQL and Redis on node 1. Installer **2026-10-23.2**.
The HA defaults are `idmvllmgwp1`, `idmvllmgwp2` and `idmvllmgwp3`.

Run `sudo python3.12 install.py setup` on the target host/controller and choose
**Single node** or **Three-node HA**. `cluster` remains a command alias.
The third choice, **Three LiteLLM gateways: PostgreSQL and Redis on node 1**,
deploys LiteLLM on all three nodes and managed standalone PostgreSQL/Redis only
on node 1. It also offers existing external services. Node 1 is a single point
of failure for managed databases; this option does not provide datastore HA.
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
See [CHANGELOG.md](CHANGELOG.md) for the RHEL bootstrap fixes. Run all regressions
with `python3 -m unittest -v test_cluster test_pki test_reset test_setup`.

For a working single-node deployment that will be expanded later, start with
`sudo python3.12 migration-precheck.py` from
[migration-precheck.py](migration-precheck.py). It reports public settings and
local service/readiness status without changing the deployment. See
[UPDATE.md](UPDATE.md) before planning any migration.

If gateway checks fail with **CA cert does not include key usage extension**,
run [repair-litellm-ca.sh](repair-litellm-ca.sh) on the controller, then resume
the same saved plan. See [RUNBOOK.md](RUNBOOK.md) for the backup and validation
steps. New source installations generate explicit CA extensions and validate
node certificates with strict TLS verification.

For an intentional fresh start on one host, see
[reset-litellm.sh](reset-litellm.sh) and the reset instructions in
[RUNBOOK.md](RUNBOOK.md). Start with `sudo bash reset-litellm.sh --dry-run`.
