# Short-lived token keys

**Throwaway** 2048-bit RSA key pair, generated for this spike (like the
plaintext passwords in the LDIF,) — never a production key. Regenerated in
a few seconds:

```sh
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

- [`private.pem`](private.pem): private key. Mounted **only** on the proxy (`JWT_PRIVATE_KEY_PATH`, [`../docker-compose.yml`](../docker-compose.yml)). Only the proxy signs a token: neither the Kibana plugin nor the engine ever has access to it.
- [`public.pem`](public.pem): public key. Mounted **only** on the dummy engine (`JWT_PUBLIC_KEY_PATH`), which verifies the signature without ever being able to issue one.
- [`wrong-private.pem`](wrong-private.pem): **not** used by the stack. Serves only as a negative test vector (invalid signature) in [`../scripts/verify-sp06.sh`](../scripts/verify-sp06.sh): a token signed with this key but carrying the right claims must be rejected by the engine.

No rotation in this spike (a single key pair): that is later work.
