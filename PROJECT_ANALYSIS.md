# Project Analysis Concept — Cloudflare WAF Validation Framework (wafguard)

**Repo:** `github.com/Dharund008/wafguard`  
**Analyzed revision:** `137a003` (`main`)  
**Package:** `cf-waf-validator` v1.0.0  
**Audience:** product / engineering stakeholders deciding how to evolve this tool

---

## 1. Product concept

### Problem
After a Cloudflare WAF cutover (or a material ruleset change), teams need **evidence** that deployed custom, rate-limit, and managed rules actually fire — not only that they appear in the dashboard. Manual Security Events review does not scale and is hard to attach to change tickets.

### Who it is for
Platform, security, and infrastructure engineers validating zone rules post-migration or post-policy change. The current config and adapters show an AP / Presidio operational origin (`$ap_*` lists, `services-*` hosts, `AP-WAF-Validator` user-agent).

### Value proposition
| Pillar | What it delivers |
|--------|------------------|
| **Read-only** | Never mutates Cloudflare config; side effects are HTTP probes + report files |
| **Discovery-driven** | Pulls live entrypoint rulesets instead of a static rule checklist |
| **Evidence-backed** | Correlates probe `CF-Ray` IDs to firewall events (Instant Logs → GraphQL fallback) |
| **Honest limits** | Rules that cannot be spoofed (geo / verified bot / missing egress IP) degrade to `MANUAL` instead of false `PASS` |
| **CI-friendly** | Optional JSON output; process exit `1` on any `FAIL` |

### Positioning
This is a **cutover sign-off / evidence kit**, not a continuous WAF assurance platform. Sample reports on `pronto.aptechlab.com` show a typical mix (~2 PASS / 1 FAIL / 10 MANUAL): automation covers what can be simulated; operators still verify the rest.

---

## 2. Architecture

### Six-stage pipeline (`waf_validator.py`)

```
bootstrap → discovery → classification → execution → reconciliation → report
```

| Stage | Primary modules | Responsibility |
|-------|-----------------|----------------|
| **Bootstrap** | `engine/config.py`, `engine/cf_client.py` | YAML or ad-hoc CLI → `Config`; token from `CF_API_TOKEN` / `--api-token`; soft token verify |
| **Discovery** | `engine/discovery.py` → `DiscoveryService` | Fetch entrypoints: `http_request_firewall_custom`, `http_ratelimit`, `http_request_firewall_managed` |
| **Classification** | `classify()`, `_PATTERN_REGISTRY` | Expression / action → `rule_type`, `adapter_class`, `extracted_params`; `compute_coverage()` |
| **Execution** | `engine/test_engine.py` + `engine/testers/*` | Sequential HTTP; Instant Logs WebSocket opened *before* probes when available |
| **Reconciliation** | `engine/correlator.py`, `engine/instant_logs.py` | Match Ray IDs to events; adapter `interpret` + action aliases |
| **Report** | `engine/reporter.py` | Self-contained HTML dashboard + optional JSON |

`--dry-run` stops after discovery/classification. `--phase` scopes `custom` / `ratelimit` / `managed`.

### Data flow

```
Config (YAML / CLI)
    → CloudflareClient (REST rulesets + GraphQL / Instant Logs)
    → list[DiscoveredRule]
    → TestEngine → list[TestResult]   (CF-Ray IDs on outcomes)
    → Correlator → list[Evidence]
    → reporter → reports/waf_validation_{zone}_{hostname}_{date}_{time}.{html|json}
```

### Key abstractions

| Abstraction | Role |
|-------------|------|
| `DiscoveredRule` | Normalized inventory + classification metadata |
| `BaseTestAdapter` | Strategy seam: `can_execute` / `build_payloads` / `expected_action` / optional `interpret` |
| `TestPayload` → `RequestOutcome` → `TestResult` → `Evidence` | Execution → evidence chain |
| `Verdict` | `PASS \| FAIL \| MANUAL \| ERROR` |
| `FirewallEvent` | Shared shape for Instant Logs and GraphQL |

---

## 3. Design patterns

### Adapter / plugin model
- **Strategy pattern:** `TestEngine` talks only to `BaseTestAdapter` (`engine/testers/base.py`).
- **Auto-discovery:** `testers/__init__._discover()` loads sibling modules via `pkgutil` and registers concrete subclasses in `REGISTRY` by class name.
- **Classifier binding:** `_PATTERN_REGISTRY` in `discovery.py` maps expression regexes to adapter class names. Adding a rule type still needs: (1) new adapter module, (2) one registry line — matching the README claim.

### Config model
Zone-centric YAML (`config.example.yaml`):
- `zone` / `api.token_env` / multi-`targets` with `test_paths`
- `test_ips` for list-based rules (runner must egress from that IP)
- `options` (poll delays, rate-limit buffer, optional SOCKS proxy for geo)
- `output` (html / json / both)

Secrets stay in env vars; `zones/*.yaml` is gitignored. Multi-target exists, but most adapters use `primary_target()`; content-type / API-traffic specially look for `services-*` hosts.

### Correlation strategy

**Primary — Instant Logs** (`engine/instant_logs.py`)
1. Create edge Logpush job → WSS URL  
2. Background reader collects while probes fire  
3. Expand match triples → `FirewallEvent` list  
4. Pass as `preloaded_events` → skip GraphQL wait  

**Fallback — GraphQL** `firewallEventsAdaptive`
- ±5 minute window, delay + retries  
- Poll until *expected* Ray IDs appear (hardened after false FAIL bugs)  
- Action aliases normalize GraphQL snake_case and Instant Logs camelCase  

**Verdict precedence** (per rule): preflight → adapter `interpret` → Ray action match → skip-without-event PASS → else FAIL.

Recent history (PR #1 / #2) focused on rendering / correlation correctness — production learning baked into the correlator.

---

## 4. Rule-type coverage

| `rule_type` | Adapter | Validation approach |
|-------------|---------|---------------------|
| `waf_score` | `WAFScoreAdapter` | SQLi / XSS / traversal probes by threshold |
| `bot_score` | `BotScoreAdapter` | Header-stripped GET; often `MANUAL` (ML / JA3 not spoofable) |
| `ip_*` / `rate_bypass` | `IPListAdapter` | Requires `test_ips.*` + matching egress |
| `geo_block` | `GeoBlockAdapter` | `MANUAL` unless `options.socks_proxy` |
| `content_type` | `ContentTypeAdapter` | Wrong CT on `services-*` + JSON negative control |
| `host_method_block` | `HostMethodAdapter` | Blocked methods expect 403; GET control |
| `verified_bot` | `VerifiedBotAdapter` | Always `MANUAL` |
| `api_traffic` | `APITrafficAdapter` | GET to `services-*`; expect skip |
| `rate_limit` / `rate_limit_404` | `RateLimitAdapter` | `threshold + buffer` repeats; trip on 429/403/503 |
| `managed_*` | `ManagedRulesetAdapter` | OWASP-category inert probes; expect block |
| `unknown` | — | `MANUAL`: no matching adapter |

**Org coupling note:** IP patterns hardcode `$ap_blacklist`, `$ap_whitelist`, `$ap_bypasslist`, `$ap_ratecontrol_bypass`. That is fine for an internal AP tool; it blocks drop-in reuse by other customers without code changes.

---

## 5. Strengths

1. Clear, linear pipeline with one orchestration entrypoint.
2. Extensible adapter seam with auto-registration.
3. Honest `MANUAL` path — avoids fake confidence for bot / geo / IP constraints.
4. Dual correlation (Instant Logs first, GraphQL hardened with Ray-targeted polling and action aliases).
5. Read-only Cloudflare posture; token scoped to Read permissions (with Instant Logs needing extra Logpush/edge scopes).
6. Operator-friendly HTML (summary cards, coverage, expandable evidence, checklist, recommendations) + JSON for CI.
7. Practical UX: `--dry-run`, phase filters, Docker volume layout for `zones/` + `reports/`.

---

## 6. Gaps, risks, and technical debt

### Documentation
- `README.md` links to **`RUNBOOK.md` — file is missing**.
- README references a **design document that is not in the repo**.
- Instant Logs permissions (Logpush / edge jobs) are not listed under “What the token needs”.
- Report footer still describes GraphQL correlation even when Instant Logs was used.

### Tests & CI
- **No `tests/` directory**, no pytest suite, no GitHub Actions / CI workflows.
- High regression risk for correlator / reporter paths that already caused false incidents.

### Classifier & adapters
- Hardcoded `$ap_*` list names and `services-*` host assumptions.
- `rate_limit_404` shares `RateLimitAdapter` but does not force 404-generating paths.
- Coverage can overstate “auto-testable”: discovery marks `testable=True` if an adapter exists; real gate is later `can_execute`.
- `websockets` is an optional extra (`instant-logs`); Docker / `requirements.txt` omit it → GraphQL path is more common than the README implies.

### Security & ops
- Probes are inert by design but still send attack-shaped strings to live origins (SOC noise risk).
- Rate-limit tests intentionally trip mitigation (brief availability blip).
- `verify_ssl` can be disabled via config.
- **License mismatch:** root `LICENSE` is MIT; `pyproject.toml` declares `Proprietary`.

### Productization limits
- Sequential, single-zone, single-process.
- No multi-zone orchestration, scheduling, historical store, or drift detection.
- `zones/` ships empty (only `.gitkeep`); example config embeds a real-looking zone ID.

---

## 7. Concept evolution directions

Ranked from “nearest to current shape” to “new product surface”:

1. **Cutover Sign-off Kit** — restore RUNBOOK + design doc; ticket-ready evidence pack (HTML + JSON + dry-run plan).
2. **Customer-generic classifier** — config-driven list / host patterns instead of `$ap_*` hardcoding.
3. **Fleet / CI validator** — multi-zone matrix on ruleset change (GitOps hook).
4. **Egress orchestrator** — documented whitelist runners, SOCKS geo exits, optional Worker-as-probe.
5. **Passive validation mode** — query historical Security Events by `rule_id` without firing probes (bot / geo / verified-bot).
6. **Drift detection** — snapshot discovery across runs (“what changed since last cutover”).
7. **SaaS-lite** — store reports, trend FAIL rates, Slack / Jira on regressions.
8. **Broader CF surface** — Workers, API Shield, account-level / non-entrypoint rulesets.

---

## 8. Recommended next steps (prioritized)

| Priority | Action | Why |
|----------|--------|-----|
| P0 | Add `RUNBOOK.md` (and a short design doc, or remove the README pointer) | Broken docs link; blocks onboarding |
| P0 | Introduce unit tests for `classify`, action aliases, Ray matching, `expand_events`, coverage math | Protects hard-won correlator fixes |
| P1 | Generalize IP-list patterns via config | Unlocks reuse beyond AP |
| P1 | Align packaging: optional Instant Logs in Docker docs or defaults; fix MIT vs Proprietary; document Logpush scopes | Credibility / install friction |
| P2 | Adapter holes: dedicated 404 path for `rate_limit_404`; content-type `interpret`; report footer shows correlation source | Fewer false/noisy results |
| P2 | Coverage semantics via `can_execute(rule, config)` after config load | Honest auto vs manual counts |
| P3 | CI skeleton (lint + unit tests); sanitized example zone YAML | Continuous quality |

---

## 9. Architecture snapshot

```
┌─────────────┐   ┌──────────────┐   ┌─────────────────┐
│  Config YAML │──▶│ Discovery +  │──▶│ TestEngine +    │
│  / CLI args  │   │ Classifier   │   │ Adapters        │
└─────────────┘   └──────┬───────┘   └────────┬────────┘
                         │                    │ CF-Ray
                         ▼                    ▼
                  Cloudflare REST      Instant Logs WS
                  (rulesets)           └─or─ GraphQL events
                                              │
                                              ▼
                                       Correlator → Evidence
                                              │
                                              ▼
                                       HTML / JSON report
```

---

## 10. Bottom line

**wafguard is a solid v1 evidence-producing WAF cutover validator.** The pipeline, adapter seam, and dual correlation path are coherent and already battle-hardened against false FAIL/PASS report bugs.

The shortest path from “internal AP tool” to “reusable product concept” is:

1. Close the docs / tests / license gaps.  
2. Externalize org-specific classifier assumptions.  
3. Keep the product thesis: **honest, evidence-backed sign-off** — not a pretend-full automation of bot/geo/IP reality.

No application code was changed for this analysis; this document is the concept deliverable.
