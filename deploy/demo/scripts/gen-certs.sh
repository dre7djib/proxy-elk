#!/bin/sh
# CA + certificat serveur de démo pour LDAPS (F5, J1-13). Jetable, jamais
# pour la prod. Idempotent : ne régénère rien si ca.crt existe déjà (permet
# un `docker compose up` répété sans invalider les volumes LDAP/ES qui
# datent du run précédent).
set -eu

CERT_DIR="$(dirname "$0")/../certs"
cd "$CERT_DIR"

if [ -f ca.crt ] && [ -f server.crt ] && [ -f server.key ]; then
  echo "Certs déjà présents, rien à faire."
  exit 0
fi

command -v openssl >/dev/null 2>&1 || { apk add --no-cache openssl >/dev/null; }

echo "Génération CA démo..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=proxy-elk-demo-ca" -out ca.crt 2>/dev/null

echo "Génération certificat serveur openldap (SAN=DNS:openldap)..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/CN=openldap" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile /dev/stdin -out server.crt 2>/dev/null <<EOF
subjectAltName=DNS:openldap
EOF
rm -f server.csr ca.srl

chmod 644 ca.crt server.crt
chmod 600 ca.key server.key
echo "OK : certs/ca.crt, certs/server.crt, certs/server.key"
