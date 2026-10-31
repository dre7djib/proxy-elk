# Proxy ELK

Authentication and authorization proxy in front of self-hosted Elasticsearch, with an AI assistant integrated into Kibana through a minimal plugin. Open source (Apache-2.0).

> **Status: J1 done.** SP-01 to SP-08 (spike) and J1-01 to J1-15 are done (see `spike/` and the spike plan): authentication, ACL, audit, secrets, and the Elasticsearch relay (`run_as`) are in the product binary — a proxy usable on its own in front of Elasticsearch, not yet a published release. J2 (AI assistant) is next.

## Why

Some of Elasticsearch's security features (LDAP and Active Directory, SSO, audit) are reserved for paid tiers. This project brings them in front of Elasticsearch as an external proxy, without touching Elastic's code or its license check.

## Principles

- **Deny by default**: any unrecognized route or action is denied.
- **User's rights**: the AI never has more rights than the logged-in person.
- **Read-only** for everything the AI generates.
- **Transparency**: the generated query is always visible and replayable.
- **Self-hosted Kibana only**; Elastic Cloud is out of scope.

## Roadmap

| Milestone | Content | Deliverable |
| --- | --- | --- |
| J1 | Authentication (OIDC, LDAP/AD), ACL, audit, secrets | A proxy usable on its own in front of Elasticsearch |
| J2 | AI assistant, Kibana plugin, teams and spaces | The "Ask" page in Kibana |
| J3 | MCP server, log analysis | MCP access and AI analysis of a specific log |

Target versions: Elasticsearch and Kibana 8.19. A 9.x version will be added afterwards.

## Running the proxy image

The proxy ships as a Docker image (no demo compose, no Kibana image). Config stays 100% file-based: mount your YAML read-only and pass secrets (`${env:...}` refs in the YAML) as environment variables.

```bash
docker build -t proxy-elk .
docker run --rm -p 8080:8080 \
  -e SESSION_SECRET=... -e ES_API_KEY=... \
  -e ES_RUN_AS_PASSWORD=... -e ES_SHADOW_PASSWORD=... \
  -v "$PWD/configs/my-proxy.yaml:/etc/proxy/proxy.yaml:ro" \
  proxy-elk
curl -sf localhost:8080/health   # liveness, no auth
curl -sf localhost:8080/metrics | head  # Prometheus, no auth
```

The image runs as non-root (uid 65532) and never embeds `configs/proxy.example.yaml` as a runtime config — mounting a real config is mandatory.

## Contributing

The project does not yet accept external contributions. The rules (DCO or CLA) will be defined before the first public release.

Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/). Enable the enforcing hook once per clone:

```
git config core.hooksPath .githooks
```

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## License

[Apache-2.0](LICENSE).
