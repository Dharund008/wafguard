"""Offline CoverageStats contracts — can_execute + phase scope."""

from __future__ import annotations

from engine.discovery import compute_coverage
from helpers import make_config, make_rule
import engine.test_engine as te_mod
import engine.testers as testers_mod


def _coverage_pct(auto_testable: int, pass_n: int, fail_n: int) -> int:
    """Mirror reporter.py auto-coverage formula."""
    auto_tested = pass_n + fail_n
    denom = max(1, auto_testable) if auto_testable else max(1, auto_tested)
    return round(auto_tested / denom * 100)


def test_compute_coverage_empty():
    c = compute_coverage([])
    assert c.total == 0
    assert c.auto_testable == 0
    assert c.enabled == 0


def test_compute_coverage_mixed():
    rules = [
        make_rule(rule_id="1", enabled=True, testable=True, scope="account", phase="custom"),
        make_rule(rule_id="2", enabled=True, testable=True, scope="zone", phase="custom"),
        make_rule(rule_id="3", enabled=True, testable=False, scope="zone", phase="custom"),
        make_rule(rule_id="4", enabled=False, testable=True, scope="zone", phase="custom"),
        make_rule(
            rule_id="5", enabled=True, testable=False,
            rule_type="unknown", scope="zone", phase="custom",
        ),
        make_rule(rule_id="6", enabled=True, testable=True, scope="account", phase="managed"),
    ]
    c = compute_coverage(rules)
    assert c.total == 6
    assert c.enabled == 5
    assert c.disabled == 1
    assert c.auto_testable == 3
    assert c.manual == 2
    assert c.unknown == 1
    assert c.account == 2
    assert c.zone == 4
    assert c.enabled - c.auto_testable == c.manual


def test_phase_scoped_coverage_not_whole_zone():
    all_rules = [
        make_rule(rule_id="c1", phase="custom", testable=True),
        make_rule(rule_id="c2", phase="custom", testable=False),
        make_rule(rule_id="m1", phase="managed", testable=True),
        make_rule(rule_id="rl1", phase="ratelimit", testable=True),
    ]
    scoped = [r for r in all_rules if r.phase == "managed"]
    c_all = compute_coverage(all_rules)
    c_scoped = compute_coverage(scoped)
    assert c_all.auto_testable == 3
    assert c_scoped.total == 1
    assert c_scoped.auto_testable == 1
    # Old misleading % used whole-zone denominator with phase evidence.
    assert round(1 / max(1, c_all.auto_testable) * 100) == 33
    assert round(1 / max(1, c_scoped.auto_testable) * 100) == 100


def test_disabled_never_auto_testable():
    c = compute_coverage([make_rule(enabled=False, testable=True)])
    assert c.auto_testable == 0
    assert c.manual == 0
    assert c.disabled == 1


def test_reporter_pct_formula():
    assert _coverage_pct(3, 2, 1) == 100
    assert _coverage_pct(4, 1, 1) == 50
    assert _coverage_pct(0, 0, 0) == 0
    assert _coverage_pct(2, 0, 2) == 100
    assert _coverage_pct(3, 1, 1) == 67
    assert _coverage_pct(5, 2, 0) == 40


def test_apply_preflight_sets_testable_from_can_execute(monkeypatch):
    class _Yes:
        name = "yes"
        def can_execute(self, rule, config):
            return True, ""
        def manual_playbook(self, rule, config):
            return ""
        def expected_action(self, rule):
            return "block"

    class _No:
        name = "no"
        def can_execute(self, rule, config):
            return False, "blocked by fixture"
        def manual_playbook(self, rule, config):
            return "playbook"
        def expected_action(self, rule):
            return "block"

    def fake_get(name):
        if name == "YesAdapter":
            return _Yes()
        if name == "NoAdapter":
            return _No()
        return None

    monkeypatch.setattr(testers_mod, "get_adapter", fake_get)
    monkeypatch.setattr(te_mod, "get_adapter", fake_get)

    cfg = make_config()
    engine = te_mod.TestEngine(cfg)
    rules = [
        make_rule(rule_id="y", adapter_class="YesAdapter", testable=True),
        make_rule(rule_id="n", adapter_class="NoAdapter", testable=True),
        make_rule(rule_id="u", adapter_class=None, testable=False, rule_type="unknown"),
        make_rule(rule_id="d", adapter_class="YesAdapter", enabled=False, testable=True),
    ]
    engine.apply_preflight(rules)
    c = compute_coverage(rules)
    assert rules[0].testable is True
    assert rules[1].testable is False
    assert rules[2].testable is False
    assert c.auto_testable == 1
    assert c.manual == 2
    assert c.disabled == 1


def test_as_dict_keys():
    d = compute_coverage([make_rule(testable=True)]).as_dict()
    assert set(d.keys()) == {
        "total", "enabled", "disabled", "auto_testable",
        "manual", "unknown", "account", "zone",
    }
