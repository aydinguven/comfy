# Setup v4 — installer 2026-10-23.2

This rebuild retains LiteLLM v1.106.2 and the previously verified application
payloads. It incorporates the bootstrap problems observed on RHEL 9.8.

- Select PostgreSQL 16 and Redis 7 RPM streams instead of skipping installation
  because an older executable exists. Switching is allowed only with an empty
  managed data directory. Existing data is refused; no major-version data
  migration or automatic cleanup is performed.
- Allow normal SELinux transitions for managed PostgreSQL/Redis system services
  by removing their incompatible NoNewPrivileges restriction. SELinux and the
  unit filesystem sandbox remain active. Restore distribution labels as before.
- Generate explicit CA constraints/key usage and validate TLS chains strictly.
  Include the backup-first CA extension repair and offer it on old-CA resume.
- Restart managed services when staged units/configuration/certificates change,
  so retries use current TLS material. Preserve rewritten Redis/Sentinel config.
- Configure Redis memory overcommit on managed Redis hosts.
- Include detailed gateway dependency probe failures in the redacted worker
  error, and point incomplete-install status to the correct diagnostics and
  rootless service. Explain how to retrieve the initial UI admin credential.
- Check actual HAProxy HTTPS readiness, including hostname and trust validation;
  an HTTP 503 or unhealthy backend cannot result in a successful final check.
- Add a third deployment choice: three LiteLLM gateways with managed PostgreSQL
  and Redis on node 1 only, or existing external services. Database firewall/HBA
  access is scoped to gateway IPs. This placement has no datastore failover.
- Include reset and CA-repair helpers, documentation and refreshed checksums in
  the full bundle and a small setup update archive.

Use a new extraction directory for this release. Keep the same bundle, saved
plan, secrets and CA when resuming an attempted deployment. A working older
deployment is not automatically upgraded or expanded by rerunning bootstrap;
changing topology or replacing its bound bundle needs an explicit migration.

Validation covers Python/unit tests, real OpenSSL certificate repair/strict
validation, generated Ansible syntax, bundle checksums and unchanged application
payloads. Automated checks do not replace actual RHEL deployment or failover tests.

Recorded checks for this release: 59 regression tests; 64 Ansible syntax
combinations across single-node, replicated HA and node-1 datastore placement;
actual Ansible service-state template evaluation; a local HTTPS test that waits
through HTTP 503 and rejects a wrong certificate hostname; RHEL system-Python
3.9 syntax compatibility; shell syntax for both helpers. Full archive checksums
and application payload preservation are checked during release packaging.
