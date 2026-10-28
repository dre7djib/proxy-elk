# Security Policy

## Supported Versions

The project has no published version yet. From the first release onward, only the latest minor version will receive security fixes. This table will be updated with each release.

| Version | Supported |
| --- | --- |
| No published version yet | - |

## Reporting a Vulnerability

**Do not open a public issue for a security flaw.**

Two ways to reach us:

1. **Private GitHub report**: the repository's "Security" tab, then "Report a vulnerability".
2. **Email**: ADDRESS-TO-FILL-IN, with subject "[SECURITY]" followed by a short title.

Please include:

- the affected version or commit;
- a description of the flaw and its impact;
- steps to reproduce it (ideally a minimal request or scenario);
- your name or handle if you'd like to be credited in the fix.

## What You Can Expect

- An acknowledgment within 7 days.
- An initial assessment, then regular updates on progress.
- A coordinated disclosure: we'll notify you before disclosure and credit you if you wish.

This is a project maintained on its authors' free time: these timelines are a good-faith commitment, not a service contract.

## Scope

The following are considered security flaws, for example:

- bypassing authentication or authorization (ACL, aliases, wildcards, system indices);
- accessing Elasticsearch without going through the proxy;
- injection (LDAP, ES|QL query, prompt) that allows reading or writing unauthorized data;
- leaking secrets, passwords, or tokens in logs or audit records;
- identity spoofing via tokens (JWT, personal tokens, identity headers).

Vulnerabilities in Elasticsearch, Kibana, or a model provider should be reported directly to their vendors.
