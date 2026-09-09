"""Offline adapter preflight / payload contracts — no host probes."""

from __future__ import annotations

from engine.config import Target
from engine.testers.bot_score import BotScoreAdapter
from engine.testers.content_type import ContentTypeAdapter
from engine.testers.geo_block import GeoBlockAdapter
from engine.testers.rate_limit import RateLimitAdapter
from engine.testers.verified_bot import APITrafficAdapter, VerifiedBotAdapter
from helpers import make_config, make_rule


def test_verified_bot_never_auto_executable():
    adapter = VerifiedBotAdapter()
    rule = make_rule(
        description="Good Bots",
        expression="cf.bot_management.verified_bot",
        action="skip",
        adapter_class="VerifiedBotAdapter",
    )
    ok, reason = adapter.can_execute(rule, make_config())
    assert ok is False
    assert "cannot be simulated" in reason.lower() or "Verified bot" in reason


def test_rate_limit_404_builds_missing_path():
    adapter = RateLimitAdapter()
    rule = make_rule(
        rule_type="rate_limit_404",
        action="managed_challenge",
        adapter_class="RateLimitAdapter",
        extracted_params={
            "requests_per_period": 50,
            "period": 10,
            "method": "GET",
            "counting_expression": "http.response.code eq 404",
        },
    )
    cfg = make_config()
    ok, _ = adapter.can_execute(rule, cfg)
    assert ok is True
    payloads = adapter.build_payloads(rule, cfg)
    assert len(payloads) == 1
    assert "/waf-validator-404-probe-50" in payloads[0].url
    assert payloads[0].repeat == 50 + int(cfg.options.get("rate_limit_buffer", 5))


def test_geo_block_requires_socks_or_matching_country(monkeypatch):
    adapter = GeoBlockAdapter()
    rule = make_rule(
        rule_type="geo_block",
        adapter_class="GeoBlockAdapter",
        extracted_params={"countries": ["CN", "T1"]},
    )
    # No socks and no matching detected country → MANUAL.
    monkeypatch.setattr(adapter, "_detect_country", lambda: "US")
    ok, reason = adapter.can_execute(rule, make_config(options={"socks_proxy": None}))
    assert ok is False
    assert "GEO" in reason or "country" in reason.lower() or "socks" in reason.lower()

    ok2, _ = adapter.can_execute(
        rule, make_config(options={"socks_proxy": "socks5h://127.0.0.1:9050"}),
    )
    assert ok2 is True


def test_content_type_needs_matching_target():
    adapter = ContentTypeAdapter()
    rule = make_rule(
        rule_type="content_type",
        adapter_class="ContentTypeAdapter",
        expression='(http.host contains "services")',
        extracted_params={
            "hosts": ["services"],
            "host_contains": ["services"],
            "host_equals": [],
            "host_wildcards": [],
        },
    )
    cfg_no = make_config(targets=[Target(hostname="www.example.com")])
    ok, _ = adapter.can_execute(rule, cfg_no)
    assert ok is False

    cfg_yes = make_config(
        targets=[Target(hostname="services-us-east-1.example.com")],
    )
    ok2, _ = adapter.can_execute(rule, cfg_yes)
    assert ok2 is True


def test_api_traffic_needs_matching_target():
    adapter = APITrafficAdapter()
    rule = make_rule(
        rule_type="host_scoped",
        adapter_class="APITrafficAdapter",
        action="skip",
        extracted_params={
            "hosts": ["api"],
            "host_contains": ["api"],
            "host_equals": [],
            "host_wildcards": [],
        },
    )
    assert adapter.can_execute(rule, make_config())[0] is False
    cfg = make_config(targets=[Target(hostname="api.example.com")])
    assert adapter.can_execute(rule, cfg)[0] is True


def test_bot_score_can_execute_without_network():
    """Bot score adapter is executable; interpret may still MANUAL later."""
    adapter = BotScoreAdapter()
    rule = make_rule(
        rule_type="bot_score",
        adapter_class="BotScoreAdapter",
        extracted_params={"score_threshold": 5},
    )
    ok, _ = adapter.can_execute(rule, make_config())
    assert ok is True
