"""Offline classify() contracts — expression → adapter binding."""

from __future__ import annotations

import pytest

from engine.discovery import classify
from helpers import load_rule_fixture


@pytest.mark.parametrize(
    "fixture,expected_type,expected_adapter",
    [
        ("waf_score.json", "waf_score", "WAFScoreAdapter"),
        ("ip_blocklist.json", "ip_blocklist", "IPListAdapter"),
        ("geo_block.json", "geo_block", "GeoBlockAdapter"),
        ("rate_limit.json", "rate_limit", "RateLimitAdapter"),
        ("rate_limit_404.json", "rate_limit_404", "RateLimitAdapter"),
        ("managed_owasp.json", "managed_owasp", "ManagedRulesetAdapter"),
        ("unknown.json", "unknown", None),
    ],
)
def test_classify_fixture_families(fixture, expected_type, expected_adapter):
    rule = load_rule_fixture(fixture)
    rtype, adapter, params = classify(rule)
    assert rtype == expected_type
    assert adapter == expected_adapter
    assert isinstance(params, dict)


def test_classify_waf_score_extracts_threshold():
    rtype, adapter, params = classify(load_rule_fixture("waf_score.json"))
    assert rtype == "waf_score"
    assert adapter == "WAFScoreAdapter"
    assert params.get("score_threshold") == 5


def test_classify_geo_extracts_countries():
    _, _, params = classify(load_rule_fixture("geo_block.json"))
    assert set(params.get("countries") or []) == {"CN", "RU", "T1"}


def test_classify_ip_list_name():
    rtype, _, params = classify(load_rule_fixture("ip_blocklist.json"))
    assert rtype == "ip_blocklist"
    assert params.get("list_name") == "ap_blacklist"


def test_classify_rate_limit_404_via_counting_expression():
    rtype, adapter, params = classify(load_rule_fixture("rate_limit_404.json"))
    assert rtype == "rate_limit_404"
    assert adapter == "RateLimitAdapter"
    assert params.get("requests_per_period") == 50


def test_classify_log_observe_true():
    rtype, adapter, _ = classify({
        "id": "log-1",
        "description": "Log all",
        "expression": "true",
        "action": "log",
        "enabled": True,
    })
    assert rtype == "log_observe"
    assert adapter == "LogObserveAdapter"


def test_classify_whitelist_skip_action():
    rtype, adapter, params = classify({
        "id": "wl-1",
        "description": "AP WhiteList",
        "expression": "(ip.src in $ap_whitelist)",
        "action": "skip",
        "enabled": True,
        "action_parameters": {"products": []},
    })
    assert rtype == "ip_whitelist"
    assert adapter == "IPListAdapter"
    assert params.get("list_name") == "ap_whitelist"


def test_classify_managed_cf_waf():
    rtype, adapter, params = classify({
        "id": "m-cf",
        "description": "CF Managed",
        "expression": "true",
        "action": "execute",
        "action_parameters": {"id": "efb7b8c949ac4650a09736fc376e9aee"},
    })
    assert rtype == "managed_cf_waf"
    assert adapter == "ManagedRulesetAdapter"
    assert params.get("managed_id") == "efb7b8c949ac4650a09736fc376e9aee"
