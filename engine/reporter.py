"""Report renderer.

Pure function: (evidence, coverage, run metadata) in, a self-contained HTML
string out. All CSS/JS is inlined so the report opens offline and can be
attached to sign-off documentation. A JSON serializer is also provided for
CI/CD consumption.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from jinja2 import Template

from .correlator import Evidence
from .discovery import CoverageStats, DiscoveredRule
from .testers import Verdict

_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF Validation Report — {{ zone }} / {{ hostname }}</title>
<style>
  :root {
    --bg: #0f1117; --card: #181b23; --card2: #1f232d; --border: #2a2f3a;
    --text: #e6e8ec; --muted: #9aa2b1; --accent: #6ea8fe;
    --pass: #3fb950; --fail: #f85149; --manual: #d29922; --skip: #58a6ff;
    --pass-bg: #12261a; --fail-bg: #2a1315; --manual-bg: #2a230f;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5; }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 32px 0 14px; }
  .meta { color: var(--muted); font-size: 13px; }
  .meta code { color: var(--text); background: var(--card2); padding: 1px 6px; border-radius: 4px; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 24px 0; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }
  .card .n { font-size: 30px; font-weight: 700; }
  .card .l { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .card.pass .n { color: var(--pass); } .card.fail .n { color: var(--fail); }
  .card.manual .n { color: var(--manual); } .card.cov .n { color: var(--accent); }
  .bar { height: 8px; border-radius: 5px; background: var(--card2); overflow: hidden; margin-top: 12px; display: flex; }
  .bar span { display: block; height: 100%; }
  .cov-tree { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 20px; font-size: 14px; }
  .cov-tree div { padding: 3px 0; color: var(--muted); }
  .cov-tree b { color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr.rowhead { cursor: pointer; }
  tr.rowhead:hover td { background: var(--card2); }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .badge.PASS { color: var(--pass); background: var(--pass-bg); }
  .badge.FAIL { color: var(--fail); background: var(--fail-bg); }
  .badge.MANUAL { color: var(--manual); background: var(--manual-bg); }
  .badge.ERROR { color: var(--fail); background: var(--fail-bg); }
  .detail { display: none; }
  .detail.open { display: table-row; }
  .detail td { background: var(--card2); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre-wrap; color: var(--muted); }
  .chk { list-style: none; padding: 0; }
  .chk li { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; }
  .chk .rn { font-weight: 600; color: var(--text); }
  .chk .st { color: var(--muted); font-size: 13px; margin-top: 3px; }
  .rec { background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; font-size: 14px; }
  .rec.warn { border-left-color: var(--manual); }
  .rec.err { border-left-color: var(--fail); }
  .muted { color: var(--muted); }
  .tag { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
  .header-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .header-row .titles { flex: 1; min-width: 220px; }
  .btn-pdf {
    flex-shrink: 0; cursor: pointer; border: 1px solid var(--border); background: var(--card2);
    color: var(--text); border-radius: 8px; padding: 8px 14px; font-size: 13px; font-weight: 600;
  }
  .btn-pdf:hover { border-color: var(--accent); color: var(--accent); }
  @media print {
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    body { background: var(--bg); }
    .wrap { max-width: none; margin: 0; padding: 12px; }
    .no-print { display: none !important; }
    tr.rowhead { cursor: default; }
    tr.rowhead:hover td { background: transparent; }
    .detail, .detail.open { display: table-row !important; }
    .card, .cov-tree, .chk li, .rec, tr.rowhead, tr.detail {
      break-inside: avoid; page-break-inside: avoid;
    }
    h2 { break-after: avoid; page-break-after: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="header-row">
      <div class="titles">
        <h1>Cloudflare WAF Validation Report</h1>
        <div class="meta">
          Zone <code>{{ zone }}</code> &nbsp;·&nbsp; Target <code>{{ hostname }}</code>
          &nbsp;·&nbsp; {{ generated }} &nbsp;·&nbsp; {{ framework }}
          &nbsp;·&nbsp; API {{ api_status }}
          &nbsp;·&nbsp; Evidence <code>{{ evidence_source or 'n/a' }}</code>
        </div>
        {% if evidence_note %}<div class="meta" style="margin-top:6px">{{ evidence_note }}</div>{% endif %}
      </div>
      <button type="button" class="btn-pdf no-print" onclick="exportPdf()" title="Expand all details and open the print dialog (Save as PDF)">Export PDF</button>
    </div>
  </header>

  <section class="cards">
    <div class="card pass"><div class="n">{{ counts.PASS }}</div><div class="l">Passed</div></div>
    <div class="card fail"><div class="n">{{ counts.FAIL }}</div><div class="l">Failed</div></div>
    <div class="card manual"><div class="n">{{ counts.MANUAL }}</div><div class="l">Manual</div></div>
    {% if counts.ERROR %}<div class="card fail"><div class="n">{{ counts.ERROR }}</div><div class="l">Errors</div></div>{% endif %}
    <div class="card cov"><div class="n">{{ coverage_pct }}%</div><div class="l">Auto coverage (this run)</div></div>
  </section>

  <div class="bar">
    <span style="width: {{ pct.PASS }}%; background: var(--pass);"></span>
    <span style="width: {{ pct.FAIL }}%; background: var(--fail);"></span>
    <span style="width: {{ pct.MANUAL }}%; background: var(--manual);"></span>
    <span style="width: {{ pct.ERROR }}%; background: var(--fail); opacity: 0.5;"></span>
  </div>

  <h2>Coverage breakdown (this run)</h2>
  <div class="cov-tree">
    <div>Rules in scope: <b>{{ cov.total }}</b> (account <b>{{ cov.account }}</b> · zone <b>{{ cov.zone }}</b>)</div>
    <div>├── Enabled: <b>{{ cov.enabled }}</b></div>
    <div>│&nbsp;&nbsp;&nbsp;├── Auto-testable: <b>{{ cov.auto_testable }}</b></div>
    <div>│&nbsp;&nbsp;&nbsp;└── Manual / partial: <b>{{ cov.enabled - cov.auto_testable }}</b></div>
    <div>├── Disabled (excluded): <b>{{ cov.disabled }}</b></div>
    <div>└── Unclassified: <b>{{ cov.unknown }}</b></div>
  </div>

  <h2>Rule-by-rule results</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Rule</th><th>Scope</th><th>Phase</th><th>Type</th><th>Expected</th><th>SecEvt</th><th>Verdict</th></tr>
    </thead>
    <tbody>
      {% for e in evidence %}
      <tr class="rowhead" onclick="toggle('d{{ loop.index }}')">
        <td>{{ loop.index }}</td>
        <td>{{ e.rule_description }}</td>
        <td class="tag">{{ e.scope or 'zone' }}</td>
        <td class="tag">{{ e.phase }}</td>
        <td class="tag">{{ e.rule_type }}</td>
        <td class="tag">{{ e.expected_action or '—' }}</td>
        <td class="tag">{% if e.security_event_verified %}yes{% else %}—{% endif %}</td>
        <td><span class="badge {{ e.verdict.value }}">{{ e.verdict.value }}</span></td>
      </tr>
      <tr class="detail" id="d{{ loop.index }}">
        <td colspan="8">{{ e.detail_block }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  {% if manual_items %}
  <h2>Manual verification playbooks</h2>
  <ul class="chk">
    {% for m in manual_items %}
    <li>
      <div class="rn">☐ {{ m.rule_description }} <span class="tag">{{ m.scope }}</span></div>
      <div class="st">{{ m.details }}</div>
    </li>
    {% endfor %}
  </ul>
  {% endif %}

  {% if disabled_rules %}
  <h2>Disabled rules (excluded from scope)</h2>
  <ul class="chk">
    {% for d in disabled_rules %}
    <li>
      <div class="rn">{{ d.description }}</div>
      <div class="st">Type: <span class="tag">{{ d.rule_type }}</span> — currently disabled. Confirm this is intentional.</div>
    </li>
    {% endfor %}
  </ul>
  {% endif %}

  <h2>Recommendations</h2>
  {% for r in recommendations %}
  <div class="rec {{ r.level }}">{{ r.text }}</div>
  {% endfor %}

  <footer>
    Generated by the Cloudflare WAF Validation Framework · {{ framework }} ·
    Correlation via Instant Logs (primary) / GraphQL firewallEventsAdaptive (fallback) · Read-only.
  </footer>
</div>
<script>
  function toggle(id) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('open');
  }
  function expandAllDetails() {
    document.querySelectorAll('tr.detail').forEach(function (el) {
      el.classList.add('open');
    });
  }
  function collapseAllDetails() {
    document.querySelectorAll('tr.detail').forEach(function (el) {
      el.classList.remove('open');
    });
  }
  function exportPdf() {
    expandAllDetails();
    window.addEventListener('afterprint', function onAfter() {
      window.removeEventListener('afterprint', onAfter);
      collapseAllDetails();
    });
    // Allow layout to settle with details open before the print dialog.
    setTimeout(function () { window.print(); }, 50);
  }
</script>
</body>
</html>""")


FRAMEWORK_VERSION = "WAF Validation Framework v1.1.0"


def _detail_block(e: Evidence, outcomes: list | None = None) -> str:
    lines = [
        f"Verdict:        {e.verdict.value}",
        f"Details:        {e.details}",
        f"Scope:          {e.scope or 'zone'}",
        f"Adapter:        {e.adapter_name}",
        f"Evidence:       {e.evidence_source or '—'}",
        f"SecEvt verified:{'yes' if e.security_event_verified else 'no'}",
        f"Match method:   {e.match_method or '—'}",
        f"Expected action:{e.expected_action or '—'}",
        f"Observed action:{e.action_taken or '—'}",
        f"Payloads:       {e.payload_summary}",
        f"CF-Ray IDs:     {', '.join(e.cf_ray_ids) if e.cf_ray_ids else '—'}",
        f"Matched events: {', '.join(e.matched_event_ids) if e.matched_event_ids else '—'}",
    ]
    if outcomes and len(outcomes) > 1:
        lines.append("")
        lines.append("Per-payload breakdown:")
        for i, o in enumerate(outcomes, 1):
            ray = o.cf_ray_id or "—"
            status = o.status_code or "err"
            desc = o.payload.description[:60]
            lines.append(f"  [{i}] {status:>4}  {ray:<20}  {desc}")
    return "\n".join(lines)


def _build_recommendations(evidence: list[Evidence], cov: CoverageStats,
                           disabled: list[DiscoveredRule]) -> list[dict]:
    recs: list[dict] = []
    fails = [e for e in evidence if e.verdict == Verdict.FAIL]
    for e in fails:
        recs.append({
            "level": "err",
            "text": f"FAILED — “{e.rule_description}”: {e.details} "
                    f"Investigate the rule expression and confirm it targets the tested path.",
        })
    for d in disabled:
        recs.append({
            "level": "warn",
            "text": f"Rule “{d.description}” is disabled. If this is not intentional for the "
                    f"current cutover, enable it and re-run validation.",
        })
    if cov.unknown:
        recs.append({
            "level": "warn",
            "text": f"{cov.unknown} rule(s) could not be classified automatically. "
                    f"Consider adding an adapter + expression pattern to cover them.",
        })
    if not recs:
        recs.append({
            "level": "",
            "text": "All executed validations passed and no anomalies detected. "
                    "Complete the manual checklist for full coverage sign-off.",
        })
    return recs


def render_html(
    *,
    zone: str,
    hostname: str,
    evidence: list[Evidence],
    coverage: CoverageStats,
    disabled_rules: list[DiscoveredRule],
    api_status: str = "connected",
    evidence_source: str = "",
    evidence_note: str = "",
) -> str:
    counts = {v.value: 0 for v in Verdict}
    for e in evidence:
        counts[e.verdict.value] = counts.get(e.verdict.value, 0) + 1

    executed = max(1, len(evidence))
    pct = {
        "PASS": round(counts.get("PASS", 0) / executed * 100),
        "FAIL": round(counts.get("FAIL", 0) / executed * 100),
        "MANUAL": round(counts.get("MANUAL", 0) / executed * 100),
        "ERROR": round(counts.get("ERROR", 0) / executed * 100),
    }
    # Coverage % = auto-tested / auto-testable, where auto_testable is counted
    # after can_execute preflight (not merely "adapter class exists").
    auto_tested = counts.get("PASS", 0) + counts.get("FAIL", 0)
    auto_testable = max(1, coverage.auto_testable) if coverage.auto_testable else max(1, auto_tested)
    coverage_pct = round(auto_tested / auto_testable * 100)

    # Build a map from rule_id to outcomes for per-payload detail blocks.
    outcome_map: dict[str, list] = {}
    if hasattr(evidence, '__iter__'):
        for e in evidence:
            outcome_map[e.rule_id] = getattr(e, '_outcomes', None)

    for e in evidence:
        e.detail_block = _detail_block(e, outcome_map.get(e.rule_id))  # type: ignore[attr-defined]

    manual_items = [e for e in evidence if e.verdict == Verdict.MANUAL]
    recommendations = _build_recommendations(evidence, coverage, disabled_rules)

    return _TEMPLATE.render(
        zone=zone,
        hostname=hostname,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        framework=FRAMEWORK_VERSION,
        api_status=api_status,
        evidence_source=evidence_source,
        evidence_note=evidence_note,
        counts=counts,
        pct=pct,
        coverage_pct=coverage_pct,
        cov=coverage,
        evidence=evidence,
        manual_items=manual_items,
        disabled_rules=disabled_rules,
        recommendations=recommendations,
    )


def render_json(
    *,
    zone: str,
    hostname: str,
    evidence: list[Evidence],
    coverage: CoverageStats,
    disabled_rules: list[DiscoveredRule],
    evidence_source: str = "",
    evidence_note: str = "",
) -> str:
    def ev_to_dict(e: Evidence) -> dict:
        d = asdict(e)
        d["verdict"] = e.verdict.value
        d.pop("_outcomes", None)
        return d

    payload = {
        "framework": FRAMEWORK_VERSION,
        "zone": zone,
        "hostname": hostname,
        "generated": datetime.now(timezone.utc).isoformat(),
        "evidence_source": evidence_source,
        "evidence_note": evidence_note,
        "coverage": coverage.as_dict(),
        "results": [ev_to_dict(e) for e in evidence],
        "disabled_rules": [
            {
                "description": d.description,
                "rule_type": d.rule_type,
                "scope": getattr(d, "scope", "zone"),
            }
            for d in disabled_rules
        ],
    }
    return json.dumps(payload, indent=2)
