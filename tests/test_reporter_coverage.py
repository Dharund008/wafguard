"""Offline reporter coverage contracts — HTML/JSON this-run labels and %."""

from __future__ import annotations

import json

from engine.correlator import Evidence
from engine.discovery import compute_coverage
from engine.reporter import render_html, render_json
from engine.testers.base import Verdict
from helpers import make_rule


def _evidence(verdict: Verdict, *, rule_id: str = "r1", desc: str = "Rule") -> Evidence:
    return Evidence(
        rule_id=rule_id,
        rule_description=desc,
        phase="custom",
        rule_type="waf_score",
        adapter_name="waf_score",
        expected_action="block",
        verdict=verdict,
        details="ok",
        scope="account",
    )


def test_html_shows_this_run_labels_and_pct():
    rules = [
        make_rule(rule_id="a", testable=True, enabled=True),
        make_rule(rule_id="b", testable=True, enabled=True),
        make_rule(rule_id="c", testable=False, enabled=True),
    ]
    cov = compute_coverage(rules)
    evidence = [
        _evidence(Verdict.PASS, rule_id="a"),
        _evidence(Verdict.FAIL, rule_id="b", desc="Fail rule"),
        _evidence(Verdict.MANUAL, rule_id="c", desc="Manual rule"),
    ]
    html = render_html(
        zone="example.com",
        hostname="www.example.com",
        evidence=evidence,
        coverage=cov,
        disabled_rules=[],
        evidence_source="instant_logs",
        evidence_note="test",
    )
    assert "Auto coverage (this run)" in html
    assert "Coverage breakdown (this run)" in html
    assert "Rules in scope:" in html
    # (PASS+FAIL)/auto_testable = 2/2 = 100%
    assert ">100%</div>" in html or ">100%</div><div class=\"l\">Auto coverage" in html
    assert cov.auto_testable == 2


def test_json_exposes_coverage_stats():
    rules = [
        make_rule(rule_id="a", testable=True, phase="managed", scope="account"),
        make_rule(rule_id="b", testable=False, phase="managed", scope="zone"),
    ]
    cov = compute_coverage(rules)
    evidence = [
        _evidence(Verdict.PASS, rule_id="a"),
        _evidence(Verdict.MANUAL, rule_id="b"),
    ]
    raw = render_json(
        zone="example.com",
        hostname="www.example.com",
        evidence=evidence,
        coverage=cov,
        disabled_rules=[],
        evidence_source="graphql",
    )
    payload = json.loads(raw)
    assert payload["coverage"]["total"] == 2
    assert payload["coverage"]["auto_testable"] == 1
    assert payload["coverage"]["manual"] == 1
    assert payload["evidence_source"] == "graphql"
    assert len(payload["results"]) == 2


def test_phase_scoped_stats_in_report():
    """Reporter must consume already phase-scoped CoverageStats."""
    all_rules = [
        make_rule(rule_id="c1", phase="custom", testable=True),
        make_rule(rule_id="m1", phase="managed", testable=True),
        make_rule(rule_id="m2", phase="managed", testable=True),
    ]
    scoped = [r for r in all_rules if r.phase == "managed"]
    cov = compute_coverage(scoped)
    evidence = [
        _evidence(Verdict.PASS, rule_id="m1"),
        _evidence(Verdict.PASS, rule_id="m2"),
    ]
    html = render_html(
        zone="z", hostname="h", evidence=evidence,
        coverage=cov, disabled_rules=[],
    )
    assert "<b>2</b>" in html  # rules in scope
    assert "Auto-testable: <b>2</b>" in html
