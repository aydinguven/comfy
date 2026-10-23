# Guided single-node or three-node installation

Installer **2026-10-23.1** starts with a deployment-size choice. Run:

    sudo python3.12 install.py setup

`install.py cluster` remains an alias for the same wizard.

## Single node

Choose **1 — Single node** to install only on the current host. SSH keys,
remote sudo, nodes 2/3, VIP and Keepalived are not requested or configured.
The wizard still offers native Python/systemd or rootless Podman and a choice
of managed or external PostgreSQL and Redis.

Managed PostgreSQL 16 runs locally on `127.0.0.1:5432`, with TLS, SCRAM,
an application-owned database, local peer authentication for administration,
and no Patroni/etcd or synchronous-standby requirement. Managed Redis 7 is a
local TLS/password service on `127.0.0.1:6379` with AOF and no Sentinel or
replica-write requirement. Database/cache ports are not opened to the network.
Single-node managed services use RHEL RPMs and do not need the Patroni/etcd
offline payload.

Optional HAProxy provides HTTPS on port 443. Without it, choose direct HTTPS
to LiteLLM on port 4000 or your existing external load balancer. Direct mode
allows the selected client CIDRs and does not trust clients as reverse proxies.
Point gateway DNS at the selected host or external load balancer.

This is a standalone deployment: a host failure stops the gateway and its local
services. Existing claimed deployments cannot be converted between one and
three nodes by changing a saved plan; that requires an explicit migration.

## Three-node HA

Run the coordinator on **idmvllmgwp1**. Default hosts are idmvllmgwp1,
idmvllmgwp2 and idmvllmgwp3. The wizard requests actual IPv4 addresses, network
interfaces, SSH identity, service choices and a gateway DNS name.

Installer **2026-10-22.6** adds an interactive setup and fixes case-sensitive
hostname checks. `IDMVLLMGWP1` and `idmvllmgwp1` identify the same host.
The controller hostname, resolvable node IPs and SSH login user are suggested.
Enter `auto` for an interface to detect it over verified SSH before provisioning.

| Component | Existing option | Installer-managed option |
| --- | --- | --- |
| PostgreSQL | HA writable endpoint, database owner and trust bundle | PostgreSQL 16, Patroni, three etcd members, synchronous standby |
| Redis | Standalone endpoint, Sentinel or Redis Cluster, with TLS/password | Redis 7 primary, two replicas, three Sentinels, quorum 2 |
| HTTPS load balancing | External load balancer | HAProxy on all nodes with verified TLS backends |
| Floating address | External load-balancer address | Optional Keepalived unicast VRRP VIP on one shared subnet |
| LiteLLM | — | Rootless Podman or native Python 3.12/systemd |

Managed PostgreSQL always gets a local HAProxy listener on localhost:6432,
including when public HAProxy is off. It selects the Patroni primary using
its authenticated TLS /primary endpoint and passes PostgreSQL TLS through.
Cluster containers, probes and migrations use host networking to reach this
local proxy. Single-node deployments retain their existing networking.

## Build

On connected Linux x86_64 with CPython 3.12 and pip, download the existing
application tar and its SHA-256 sidecar, then run this version of the source:

    python3.12 build_cluster.py \
      --bundle /path/litellm-rhel9.8-x86_64.tar \
      --out /path/litellm-rhel9.8-x86_64-cluster.tar

The builder retains the application payload, refreshes installer files, and adds
Patroni 4.1.5, its wheel closure, psycopg, python-etcd and etcd v3.6.7. The etcd
archive is checked against its pinned official release digest. The pure-Python
python-etcd 0.4.5 and ydiff 1.3.0 packages are built from PyPI source
distributions; other packages require binary wheels.
Resolved versions/hashes are frozen into the offline payload; pip requires those
hashes during installation. Use --infrastructure to reuse a verified directory.

--without-managed-postgresql omits the Patroni/etcd payload, while retaining the
external PostgreSQL, single-node local PostgreSQL, Redis, HAProxy and VIP
options. Three-node managed PostgreSQL cannot be selected without its offline
Patroni/etcd payload.

**RHEL RPMs are not embedded.** Nodes require entitled BaseOS/AppStream or
Satellite repositories/local mirrors. The controller requires ansible-core and
openssl from its repositories. Managed Redis uses redis:7, managed PostgreSQL
uses postgresql:16/server. The installer never resets an existing module stream.

## Deploy from node 1

Use fresh RHEL 9.8 x86_64 hosts with synchronized clocks, correct DNS and at least
20 GiB free under /var/lib. The preflight reserves 4 GiB per gateway worker plus
infrastructure overhead; size disk and memory for database/cache growth.

The coordinator runs with sudo on node 1. SSH can use your normal login account
(for example `tcmb`) and sudo on nodes 2/3; root SSH is not required. The wizard
offers a secure shared sudo-password prompt or passwordless sudo. Password mode
passes `--ask-become-pass` to Ansible; no environment variable is needed and the
password is not written to the plan, inventory or command line. Both remote
nodes must accept that shared sudo password.

The wizard can create a dedicated RSA 3072 key and run `ssh-copy-id` interactively.
Verify displayed SSH host fingerprints independently against the host console
before accepting them; deployment then requires strict host-key checking.
With passwordless sudo, you can also prepare access beforehand:

    ssh -o BatchMode=yes USER@NODE sudo -n true

Verify and extract the new bundle, then run its installer on idmvllmgwp1:

    sha256sum -c litellm-rhel9.8-x86_64-cluster.tar.sha256
    tar -xf litellm-rhel9.8-x86_64-cluster.tar
    cd litellm-rhel9.8-x86_64
    sudo python3.12 install.py cluster

The wizard finds/suggests the tar in this directory or its parent and checks its
SHA-256 sidecar before SSH setup. Keep both files together. You can still pass
`--bundle /absolute/path/cluster.tar`. Missing controller prerequisites can be
installed interactively from entitled RHEL repositories. If started without
sudo, cluster mode offers to restart with sudo.

The wizard offers both PostgreSQL choices and optional Redis/HAProxy/VIP. It
displays the plan before applying it, with options to apply, edit or save/exit.
Only builtin Ansible modules are used; no Galaxy dependencies are needed.
`--plan-only` validates/saves a draft without changing remote nodes or setting up
SSH. Interfaces marked `auto` are resolved at apply. `--yes` skips only the final
review, and does not answer SSH, sudo, package-installation or credential prompts.

Client access accepts comma/space-separated IPv4 addresses or CIDRs. A single
IP becomes `/32`. The SSH client's address is suggested when available; replace
it if the gateway clients use other networks. Invalid inputs are re-prompted
immediately. `0.0.0.0/24` is rejected because it covers only `0.0.0.x`; allowing
all IPv4 addresses (`0.0.0.0/0`) needs an explicit confirmation. No floating VIP
means the wizard asks whether an external load balancer or a single-node testing
address will serve clients. Single-node DNS does not provide a HA client address.
Managed-only services no longer prompt for an external-service CA bundle.

Public plan: /var/lib/litellm-cluster/cluster.json. Shared credentials:
/var/lib/litellm-cluster/secrets.json (root-only). Back up the credentials and
work/ca directory to a vault. Reuse them to resume a failed bootstrap:

    sudo python3 install.py cluster \
      --config /var/lib/litellm-cluster/cluster.json \
      --bundle /absolute/path/litellm-rhel9.8-x86_64-cluster.tar

Alternatively rerun `sudo python3.12 install.py cluster` and choose **Resume**.
Unapplied drafts may be edited with existing answers prefilled. Once provisioning
has started, plans/credentials remain locked for safe retries. Ctrl-C cancels the
coordinator and tells you how to resume; remote actions already started may finish.

All nodes pass ownership, data/port conflict, addressing, OS and SSH/sudo checks
before provisioning. Then the installer stages packages and verified payloads,
forms etcd and Patroni quorums, verifies Redis/Sentinel, starts routing, installs
and migrates gateways sequentially, and enables the VIP after all gateways are
healthy. Health includes authenticated /v1/models, not only an open port.

An identical retry preserves Redis/Sentinel's rewritten failover configuration
and existing keys/CA. Foreign data and services are refused. Running gateway
configuration changes require an explicit rolling upgrade. This command is for
fresh bootstrap, not migration, PostgreSQL major upgrades, or cluster resizing.

## TLS, firewall and operational limits

Internal TLS uses a private CA with a separate key/certificate for each node.
Only node 1 retains the CA private key. Nodes receive their own key and trust
bundle. etcd/Patroni REST require client certificates. PostgreSQL and Redis use
authenticated TLS. Node certificates last 365 days; renewal is an operator task.
The installer refuses certificates with fewer than seven days remaining.

Supply an existing frontend certificate/key for clients that already trust your
organization CA. Otherwise clients must explicitly trust the generated cluster
CA; it is not publicly trusted. External services require their PEM trust bundle.

The installer starts firewalld/chronyd and adds peer-scoped selected service
ports (4000, 5432, 6379, 26379, 2379, 2380, 8008), client CIDRs on 443, and
peer-scoped VRRP. Existing broad firewall rules are not removed; audit them.
SELinux remains enabled. Selecting any managed proxy enables the RHEL
haproxy_connect_any boolean; this appears in the apply summary. Redis/PostgreSQL
paths receive distribution service/data labels. Validate those labels on RHEL.

System services: litellm-etcd, litellm-postgres, litellm-redis, litellm-sentinel,
litellm-haproxy, and optionally keepalived. LiteLLM itself uses its existing
rootless user service or native system service. Worker failures have redacted
details in /var/lib/litellm-cluster/last-error.txt; inspect service journals as root.

Synchronous PostgreSQL mode deliberately stops writes without a synchronous
standby or DCS quorum. Redis replication is asynchronous, so failover can lose
recent writes even with min-replicas-to-write=1. Backups/restores, monitoring,
certificate renewal and infrastructure upgrade procedures are separate tasks.

Automated configuration/archive tests are not RHEL/failover certification.
Before accepting production traffic, test one-node loss, PostgreSQL primary
promotion, Redis promotion, VIP movement, quorum loss, and backup restoration.

References: [Patroni configuration](https://patroni.readthedocs.io/en/latest/yaml_configuration.html),
[replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html),
[Redis Sentinel](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/),
[etcd release](https://github.com/etcd-io/etcd/releases/tag/v3.6.7).
