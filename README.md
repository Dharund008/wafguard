# Cloudflare WAF Validation Framework

A reusable, config-driven tool that validates Cloudflare WAF rules after a cutover.
It discovers the rules deployed on a zone **and** at the account level, exercises
each classified rule with targeted HTTP payloads, correlates results against
Cloudflare's firewall event stream (Instant Logs primary, GraphQL
`firewallEventsAdaptive` fallback, matched on CF-Ray ID / rule id), and renders
a self-contained HTML dashboard — plus optional JSON for CI/CD.

It is **read-only**: it never modifies Cloudflare configuration. The only side
effects are the test HTTP requests to the target host and the generated report.

## Two ways to run

- **Python package** — `pip install -e ".[instant-logs]"` and use `waf-validator`.
- **Docker** — build the image and run it with your token passed as an env var.

## Quick start

```bash
pip install -e ".[instant-logs]"
export CF_API_TOKEN="your-token"
cp config.example.yaml zones/myzone.yaml   # edit the values
waf-validator --config zones/myzone.yaml --dry-run
waf-validator --config zones/myzone.yaml --phase managed
```

## What the token needs

Scoped API token with **read-only** permissions:

| Permission | Why |
|---|---|
| Zone → Firewall Services → Read | Zone WAF rule discovery |
| Account → Account Rulesets / Account WAF → Read | Account WAF / rate-limit / managed discovery |
| Zone → Analytics → Read | GraphQL `firewallEventsAdaptive` correlation |
| Zone → Logs → Read | Instant Logs WebSocket (Business+ plans) |
| Account → Account Filter Lists → Read | IP-list membership auto-detection |

`account_id` is optional in config — resolved automatically from the zone.

## Architecture

Six-stage pipeline: bootstrap → discovery (account + zone) → classification →
execution → reconciliation → report. Test logic lives in pluggable **adapters**
under `engine/testers/`.

Classification is generic (any `$list_name`, host/method/score families). MANUAL
is a last resort with a copy-paste playbook — only when automation is physically
impossible (e.g. Cloudflare Verified Bot spoofing).

## Evidence

1. **Instant Logs** (preferred): real-time WebSocket, zero analytics lag.
2. **GraphQL** fallback with Ray-ID-targeted polling.
3. **Hybrid**: Instant Logs + GraphQL fill for any missing Ray IDs.

Reports show `evidence_source` and whether each rule was **security-event verified**
(rule id / Ray match in the event stream).

## Phases

```bash
waf-validator --config zones/myzone.yaml --phase custom
waf-validator --config zones/myzone.yaml --phase managed
waf-validator --config zones/myzone.yaml --phase ratelimit
waf-validator --config zones/myzone.yaml            # all
```

## Output

A self-contained `.html` file with summary cards, coverage (account vs zone),
rule-by-rule results with evidence, manual playbooks, and recommendations.
JSON is available for CI (`--format json|both`). Non-zero exit on any `FAIL`.
