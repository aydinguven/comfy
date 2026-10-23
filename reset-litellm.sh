#!/usr/bin/env bash
# Reset this host's LiteLLM bootstrap state by archiving it, never deleting it.
set -euo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage: sudo bash reset-litellm.sh [--dry-run]

Runs on THIS host only. Stops/disables PostgreSQL and LiteLLM's system services,
then moves the listed data/configuration into /var/lib/litellm-reset.XXXXXXXX.
ALL PostgreSQL databases in /var/lib/pgsql/data are taken offline.
Packages, SSH keys, firewall rules and cached Podman images are retained.
Review the root-only backup before removing it. This is not a cluster teardown
or a migration tool; it does not contact other hosts or external databases.

--dry-run   Show the proposed reset without stopping services or changing files.
--help      Show this help.
USAGE
}

dry_run=false
case "${1:-}" in
    --dry-run) dry_run=true ;;
    --help|-h) usage; exit 0 ;;
    '') ;;
    *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then usage >&2; exit 2; fi

services=(litellm litellm-haproxy litellm-sentinel litellm-redis
          litellm-postgres litellm-etcd postgresql)
paths=(/var/lib/pgsql/data /var/lib/litellm-redis /var/lib/litellm-etcd
       /var/lib/litellm-cluster /etc/litellm-cluster
       /etc/haproxy/litellm /etc/haproxy/litellm-cluster.cfg
       /srv/litellm /opt/litellm /opt/litellm-patroni)

reset_host=$(hostname -s)
printf 'Host: %s\n' "$reset_host"
usage
printf '\nSystem services to stop/disable:\n'
printf '  %s.service\n' "${services[@]}"
printf '\nExisting paths to archive:\n'
for path in "${paths[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then printf '  %s\n' "$path"; fi
done
if "$dry_run"; then
    printf '\nDry run complete. Nothing was changed.\n'
    exit 0
fi

if (( EUID != 0 )); then echo 'Run with sudo.' >&2; exit 1; fi
for command in systemctl pgrep ss mountpoint mktemp mkdir mv flock; do
    command -v "$command" >/dev/null || { echo "Required command missing: $command" >&2; exit 1; }
done
# Moving a mounted directory fails and can leave a partially archived reset.
for path in "${paths[@]}"; do
    if mountpoint -q "$path"; then
        echo "STOP: $path is a mount point. Plan a storage-specific backup/reset first." >&2
        exit 1
    fi
done
printf '\nType this hostname to confirm taking its databases offline: '
read -r confirmation
if [[ "${confirmation,,}" != "${reset_host,,}" ]]; then echo 'Cancelled.'; exit 1; fi

exec 9>/var/lib/litellm-reset-lock
flock -n 9 || { echo 'Another reset is already running.' >&2; exit 1; }
for service in "${services[@]}"; do
    if systemctl cat "$service.service" >/dev/null 2>&1; then
        systemctl stop "$service.service"
        systemctl disable "$service.service" >/dev/null 2>&1 || true
    fi
done

postgres_status=0
pgrep -x postgres >/dev/null || postgres_status=$?
if (( postgres_status == 0 )); then
    echo 'STOP: PostgreSQL is still running. No data was moved:' >&2
    pgrep -a -x postgres >&2 || true
    exit 1
fi
if (( postgres_status != 1 )); then
    echo 'STOP: checking PostgreSQL processes failed. No data was moved.' >&2
    exit 1
fi
listeners=$(ss -H -ltn \
    '( sport = :5432 or sport = :6379 or sport = :2379 or sport = :2380 or sport = :26379 or sport = :8008 or sport = :6432 or sport = :4000 or sport = :443 )')
if [[ -n "$listeners" ]]; then
    printf 'STOP: installation ports still have listeners. No data was moved:\n%s\n' "$listeners" >&2
    echo 'Inspect them with sudo ss -ltnp before proceeding (including rootless or unrelated services).' >&2
    exit 1
fi

reset_backup=$(mktemp -d /var/lib/litellm-reset.XXXXXXXX)
trap 'echo "Reset interrupted or failed; inspect backup and original paths: $reset_backup" >&2' ERR
printf 'Reset on %s\n' "$reset_host" >"$reset_backup/reset.log"
for path in "${paths[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
        mkdir -p "$reset_backup$(dirname "$path")"
        mv -- "$path" "$reset_backup$path"
        printf '%s\n' "$path" >>"$reset_backup/reset.log"
    fi
done
trap - ERR
printf '\nReset complete. Backup: %s\n' "$reset_backup"
echo 'Return to the extracted bundle and run: sudo python3.12 install.py setup'
