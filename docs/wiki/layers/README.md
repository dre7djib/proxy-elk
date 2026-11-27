# Layer-by-layer diagrams

Interactive pages generated with [Archify](https://github.com/tt-a1i/archify) and published by GitHub Pages together with the rest of `docs/wiki/`.

| Page | Layer | Type |
| --- | --- | --- |
| `index.html` | Overview, links to every layer | architecture |
| `01-kibana-ask.html` | Kibana & the Ask app | workflow |
| `02-authentication.html` | Authentication (LDAP login into Kibana) | sequence |
| `03-authorization.html` | Authorization pipeline | workflow |
| `04-elasticsearch.html` | Elasticsearch and its credentials | architecture |
| `05-ai-agent-mcp.html` | AI assistant (`/_proxy/ask`) | sequence |
| `06-end-to-end.html` | End-to-end scenario | sequence |

The sources are the JSON files in `src/`. Each one pins the commit it describes (`meta.repository.revision`) and cites the files it relies on, so Archify checks every reference.

## Updating a page

1. Install Archify (see its `llms.txt`) and edit the JSON in `src/`.
2. Set `meta.repository.revision` to the commit the page now describes.
3. Regenerate from the repository root, for example:

```bash
node <archify>/bin/archify.mjs finalize sequence \
  docs/wiki/layers/src/02-authentication.sequence.json \
  docs/wiki/layers/02-authentication.html \
  --repo-root . --quality showcase --json
```

Use `architecture`, `workflow` or `sequence` to match the file suffix. Receipts (`*.delivery.json`) and the `.archify/` folder are git-ignored.
