# `spike_smtp_mail` — email on Basic **without** Connectors

Throwaway example of how to send mail from Kibana on a **Basic** license
**without** registering an Actions connector (and without touching Elastic’s
license check).

The official `.email` connector and any third-party `actions.registerType`
with `minimumLicenseRequired: 'basic'` are blocked by Kibana
(`ensure_sufficient_license.ts`: only `.index` and `.server-log` may be
Basic). Circumventing that gate is an ELv2 violation and out of scope for
this project.

## Recommended path (this plugin)

**Custom Alerting rule type** (`alerting.registerType`) with
`minimumLicenseRequired: 'basic'`. The rule `executor` sends SMTP mail
**directly** (Node SMTP helper here). It never calls
`actions.registerType` and never uses the paid `.email` connector.

What you get in the UI:

- **Stack Management → Rules → Create rule** → type **“SMTP mail (Basic)”**
  (form: To / Subject / Body / optional index threshold — no API required)
- No entry under **Connectors** (by design)

The public plugin registers the rule type with `triggersActionsUi` and
`requiresAppContext: false`, which is what makes it appear in the global
Rules create flyout. Use the `elastic` user, or grant the feature
**Spike SMTP mail (Basic)** on the role.

SMTP credentials live in `kibana.yml` (plugin config), not in rule params.

```yaml
spikeSmtpMail:
  smtp:
    host: smtp.example.com
    port: 587
    secure: false          # true = TLS from the first byte (465)
    user: alerts@example.com
    password: "…"          # prefer env / secrets injection in real deploys
    from: alerts@example.com
```

Rule params (per rule): `to`, `subject`, `body`, optional ES query threshold.

### Create a rule (UI — preferred)

1. Open **Stack Management → Rules**.
2. **Create rule**.
3. Pick **SMTP mail (Basic)**.
4. Fill To / Subject / Body (and optional index threshold).
5. Set the schedule. Leave **Actions** empty (mail already goes out via SMTP).
   You may still attach Index / Server log connectors if you want an ES paper trail.
6. Save.

### Create a rule (API — optional)

Same result as the UI, for automation / smoke tests:

```bash
curl -s -u elastic:"$ELASTIC_PASSWORD" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:5601/api/alerting/rule" -d '{
  "name": "Spike SMTP demo",
  "consumer": "spikeSmtpMail",
  "rule_type_id": "spikeSmtpMail.thresholdEmail",
  "schedule": { "interval": "1m" },
  "params": {
    "to": "ops@example.com",
    "subject": "[spike] threshold",
    "body": "Condition met.",
    "index": "logs-*",
    "minDocCount": 1,
    "query": "level:error"
  },
  "actions": []
}'
```

## Other legitimate options (not coded here)

| Option | When to use |
| --- | --- |
| **A. This plugin** — rule type + SMTP in executor | You want alerts in Kibana Rules UI on Basic |
| **B. Plugin route + SMTP** | App-triggered mail (button / API), not Alerting |
| **C. Index connector + external mailer** | Stay on stock Kibana: rule → Index action → ElastAlert2 / cron / small service reads the index and sends SMTP |

Option C needs no custom Kibana plugin build.

## Build / install

Same flow as [`spike_ask`](../spike_ask/): copy into `kibana/plugins/spike_smtp_mail`
at tag `v8.19.23`, `pnpm build`, install into the Kibana image. Declare
dependency on the `alerting` plugin (see `kibana.json`).

`nodemailer` is **not** required: `server/lib/smtp_send.ts` speaks a minimal
SMTP subset (EHLO, optional STARTTLS, AUTH LOGIN, DATA). Swap it for
nodemailer in a real product if you need attachments / MIME edge cases.

## What this deliberately does not do

- No `actions.registerType` / no Connectors UI entry
- No patch of `ensureSufficientLicense` or `/_license`
- No reuse of Elastic’s `.email` action type id
