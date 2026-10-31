# krb5-user + curl client container for the demo's SPNEGO smoke test
# (verify.sh): macOS's own GSS doesn't reliably follow KRB5_CONFIG, so
# the end-to-end `kinit` + `curl --negotiate` check runs from here
# instead, on the `demo` network, where the proxy resolves as `proxy`
# (hence the second SPN in entrypoint.sh).
FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       krb5-user curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
ENTRYPOINT ["sleep", "infinity"]
