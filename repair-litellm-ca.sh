#!/usr/bin/env bash
# Repair the controller's CA extensions without rotating its key or node certs.
set -euo pipefail
umask 077

usage() {
    echo 'Usage: sudo bash repair-litellm-ca.sh [--dry-run]'
    echo 'Run on the installer controller. Back up and repair its CA, then resume the SAME plan.'
    echo 'This does not modify databases, secrets, node certificates or service configuration.'
}
dry_run=false
case "${1:-}" in
    --dry-run) dry_run=true ;;
    --help|-h) usage; exit 0 ;;
    '') ;;
    *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then usage >&2; exit 2; fi
if (( EUID != 0 )); then echo 'Run with sudo.' >&2; exit 1; fi

state=/var/lib/litellm-cluster
ca="$state/work/ca"
for file in "$ca/ca.crt" "$ca/ca.key"; do
    [[ -f "$file" && ! -L "$file" ]] || { echo "Missing/unsafe CA file: $file" >&2; exit 1; }
done
[[ "$(openssl x509 -in "$ca/ca.crt" -pubkey -noout)" == "$(openssl pkey -in "$ca/ca.key" -pubout)" ]] || {
    echo 'CA certificate and private key do not match. Nothing replaced.' >&2; exit 1;
}
certs=()
for cert in "$state"/work/*/node.crt "$state/node.crt" \
    /etc/litellm-cluster/postgres/node.crt /etc/litellm-cluster/redis/node.crt; do
    if [[ -f "$cert" ]]; then certs+=("$cert"); fi
done
(( ${#certs[@]} )) || { echo 'No existing node certificates found. Nothing replaced.' >&2; exit 1; }
printf 'Controller CA: %s\nExisting node certificates: %s\n' "$ca/ca.crt" "${#certs[@]}"
if "$dry_run"; then
    echo 'Would preserve CA key, subject and serial; back up its certificate; add explicit CA extensions;'
    echo 'validate every discovered node certificate for TLS server/client use; then replace only the controller CA.'
    echo 'Dry run complete. Nothing changed.'
    exit 0
fi

exec 9>"$ca/.repair.lock"
flock -n 9 || { echo 'Another CA repair is running.' >&2; exit 1; }
valid_ca() {
    for purpose in sslserver sslclient; do
        openssl verify -x509_strict -purpose "$purpose" -CAfile "$1" "${certs[@]}" || return 1
    done
}
if valid_ca "$ca/ca.crt" >/dev/null 2>&1; then
    echo 'Existing CA and node certificates already pass strict TLS validation. Nothing replaced.'
    exit 0
fi

repair_dir=$(mktemp -d "$ca/repair.XXXXXXXX")
trap 'echo "CA repair failed. Inspect backup: $repair_dir/ca.before.crt" >&2' ERR
cp -p "$ca/ca.crt" "$repair_dir/ca.before.crt"
ca_serial=$(openssl x509 -in "$ca/ca.crt" -noout -serial)
ca_serial=${ca_serial#serial=}
openssl x509 -x509toreq -in "$ca/ca.crt" -signkey "$ca/ca.key" -out "$repair_dir/ca.csr"
openssl req -x509 -in "$repair_dir/ca.csr" -key "$ca/ca.key" -sha256 -days 3650 \
    -set_serial "0x$ca_serial" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -addext 'authorityKeyIdentifier=keyid:always' \
    -out "$repair_dir/ca.fixed.crt"
for option in -pubkey -subject -serial; do
    [[ "$(openssl x509 -in "$ca/ca.crt" "$option" -noout)" == \
       "$(openssl x509 -in "$repair_dir/ca.fixed.crt" "$option" -noout)" ]] || {
        echo "CA identity changed ($option); original retained. Backup: $repair_dir" >&2; exit 1;
    }
done
valid_ca "$repair_dir/ca.fixed.crt"
mv -- "$repair_dir/ca.fixed.crt" "$ca/ca.crt"
trap - ERR
echo "CA repaired. Backup: $repair_dir/ca.before.crt"
echo 'From the extracted installer directory, run: sudo python3.12 install.py setup'
echo 'Choose Resume saved plan with the SAME bundle and secrets to restage the CA on all planned nodes.'
echo 'This helper is not a CA/key rotation or a certificate renewal procedure.'
