# Cloudflare WAF Validation Framework

A reusable, config-driven tool that validates Cloudflare WAF rules after a cutover.
It discovers the rules deployed on a zone, exercises each one with targeted HTTP
payloads, correlates the results against Cloudflare's firewall event stream (via the
GraphQL `firewallEventsAdaptive` dataset, matched on CF-Ray ID), and renders a
self-contained HTML dashboard — plus optional JSON for CI/CD.

It is **read-only**: it never modifies Cloudflare configuration. The only side
effects are the test HTTP requests to the target host and the generated report.

## Two ways to run

- **Python package** — `pip install` and use the `waf-validator` command.
- **Docker** — build the image and run it with your token passed as an env var.

Both are covered step by step in [`RUNBOOK.md`](RUNBOOK.md).

## Quick start (package)

```bash
pip install -e .
export CF_API_TOKEN="your-token"
cp config.example.yaml zones/aptechdevlab.yaml   # edit the values
waf-validator --config zones/aptechdevlab.yaml
```

## Quick start (Docker)

```bash
docker build -t waf-validator .
docker run --rm \
  -e CF_API_TOKEN="your-token" \
  -v "$PWD/zones:/app/zones" \
  -v "$PWD/reports:/app/reports" \
  waf-validator --config zones/aptechdevlab.yaml
```

## What the token needs

A scoped API token with **read-only** permissions:

- Zone → Firewall Services → **Read** (rule discovery)
- Zone → Analytics → **Read** (event correlation via GraphQL)
- Account → Account Filter Lists → **Read** (only if you validate IP-list rules)

## Architecture

Six-stage pipeline: bootstrap → discovery → classification → execution →
reconciliation → report. Test logic lives in pluggable **adapters** under
`engine/testers/`. Adding a new rule type is two edits: a new adapter module and
one line in the classifier's pattern registry. See the design document for detail.

## Output

A single self-contained `.html` file (no external dependencies) with summary
cards, a coverage breakdown, a rule-by-rule results table with expandable
evidence, a manual-verification checklist, and auto-generated recommendations.
