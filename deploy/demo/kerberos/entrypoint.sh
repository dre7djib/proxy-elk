#!/usr/bin/env bash
# Bootstraps the demo KDC on first boot (idempotent: /var/lib/krb5kdc is
# a named volume, so a restart skips straight to step 4 and just starts
# krb5kdc). See the plan (kerberos_spnego_sso): two SPNs land in the
# proxy's keytab because the client requests a ticket for the hostname
# in the URL it called — the browser uses proxy.demo.local, the
# krb5-user container (same docker network) uses proxy.
set -euo pipefail

: "${REALM:=EXAMPLE.ORG}"
: "${ALICE_PASSWORD:?ALICE_PASSWORD is required}"
: "${KEYTAB_PATH:=/keytab/krb5.keytab}"

mkdir -p /etc/krb5kdc
cat >/etc/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    ${REALM} = {
        database_name = /var/lib/krb5kdc/principal
        key_stash_file = /var/lib/krb5kdc/.k5.${REALM}
        acl_file = /var/lib/krb5kdc/kadm5.acl
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
EOF

if [ ! -f /var/lib/krb5kdc/principal ]; then
    echo "First boot: creating realm ${REALM}..."
    master_password="$(head -c 32 /dev/urandom | base64)"
    kdb5_util create -s -r "${REALM}" -P "${master_password}"
else
    echo "Realm ${REALM} already provisioned, reusing it."
fi

# Separate from the realm check above for the same reason as the keytab
# below: an earlier boot (missing kadmin.local, pre-fix) created the
# realm but died before alice existed.
if ! kadmin.local -r "${REALM}" -q "getprinc alice" 2>&1 | grep -q "^Principal:"; then
    echo "Creating principal alice@${REALM}..."
    kadmin.local -r "${REALM}" -q "addprinc -pw ${ALICE_PASSWORD} alice"
else
    echo "Principal alice@${REALM} already exists, reusing it."
fi

# Separate from the realm check above: a prior boot can have created the
# realm but died before the keytab existed (e.g. missing kadmin.local —
# this cost us a debugging round), so re-check the keytab itself rather
# than bundling it under the same guard.
if [ ! -s "${KEYTAB_PATH}" ]; then
    echo "Creating service principals and keytab..."
    mkdir -p "$(dirname "${KEYTAB_PATH}")"
    kadmin.local -r "${REALM}" -q "addprinc -randkey HTTP/proxy.demo.local" 2>&1 | grep -v "already exists" || true
    kadmin.local -r "${REALM}" -q "addprinc -randkey HTTP/proxy" 2>&1 | grep -v "already exists" || true
    kadmin.local -r "${REALM}" -q "ktadd -k ${KEYTAB_PATH} HTTP/proxy.demo.local"
    kadmin.local -r "${REALM}" -q "ktadd -k ${KEYTAB_PATH} HTTP/proxy"
    chmod 644 "${KEYTAB_PATH}"
    if [ ! -s "${KEYTAB_PATH}" ]; then
        echo "FATAL: keytab was not created at ${KEYTAB_PATH}" >&2
        exit 1
    fi
else
    echo "Keytab already present at ${KEYTAB_PATH}, reusing it."
fi

echo "Starting krb5kdc..."
exec krb5kdc -n
