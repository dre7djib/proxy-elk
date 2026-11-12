# MIT krb5-kdc for the demo (plan: kerberos_spnego_sso): a tiny KDC for
# realm EXAMPLE.ORG, not a third-party image — only krb5-kdc/kadmin from
# Debian. entrypoint.sh creates the realm, the alice principal, and the
# proxy's keytab (two SPNs, see entrypoint.sh) on first boot.
FROM debian:bookworm-slim

# kadmin.local ships in krb5-admin-server, not krb5-kdc (confirmed by
# running the built image: krb5-kdc alone has kdb5_util/krb5kdc but no
# kadmin.local). The remote admin daemon (kadmind) itself is never
# started — this demo has no need for it, only the local tool.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       krb5-kdc krb5-admin-server krb5-config \
    && rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 88/udp 88/tcp 749/tcp
ENTRYPOINT ["/entrypoint.sh"]
