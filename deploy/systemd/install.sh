#!/bin/sh
# Install or update proxy-elk from an unpacked release archive. Run as root
# from the archive directory. Needs neither Docker nor Go.
# First run: user, dirs, binary, unit, example config. Secrets are left to you.
# Later runs: binary + unit replaced, service restarted; /etc/proxy untouched.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
cd "$(dirname "$0")"

id proxy >/dev/null 2>&1 || useradd --system --home /var/lib/proxy --shell /usr/sbin/nologin proxy
install -d -o root -g proxy -m 0750 /etc/proxy /etc/proxy/secrets
install -d -o proxy -g proxy -m 0750 /var/lib/proxy
install -m 0755 proxy /usr/local/bin/proxy
install -m 0644 proxy-elk.service /etc/systemd/system/proxy-elk.service
if [ ! -e /etc/proxy/proxy.yaml ]; then
  install -o root -g proxy -m 0640 proxy.yaml /etc/proxy/proxy.yaml
  new=1
fi
systemctl daemon-reload

echo "installed $(/usr/local/bin/proxy -version)"
if [ "${new:-}" = 1 ]; then
  echo "next: edit /etc/proxy/proxy.yaml, create /etc/proxy/secrets/* (root:proxy 0640),"
  echo "      then: systemctl enable --now proxy-elk"
else
  systemctl restart proxy-elk
  echo "config and secrets kept; proxy-elk restarted"
fi
