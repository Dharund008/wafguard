"""Offline correlator contracts — Ray/rule match and preflight short-circuit."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from engine.correlator import Correlator
from engine.testers.base import Verdict
from helpers import (
    FakeCloudflareClient,
    load_event_fixture,
    make_config,
    make_firewall_event,
    make_outcome,
    make_result,
    make_rule,
)


def _by_ray(events):
    d = defaultdict(list)
    for ev in events:
        if ev.ray_id:
            d[ev.ray_id].append(ev)
    return d


def test_preflight_short_circuit_stays_manual():
    cfg = make_config(options={"hybrid_graphql_fill": False})
    corr = Correlator(FakeCloudflareClient(), cfg)
    rule = make_rule(rule_id="vb-1", description="Good Bots", adapter_class="VerifiedBotAdapter")
    result = make_result(
        rule,
        adapter_name="verified_bot",
        preflight_verdict=Verdict.MANUAL,
        preflight_reason="cannot spoof",
    )
    ev = corr._reconcile_one(result, {}, [])
    assert ev.verdict == Verdict.MANUAL
    assert ev.match_method == "preflight"
    assert "cannot spoof" in ev.details


def test_rule_id_on_ray_pass():
    cfg = make_config(options={"hybrid_graphql_fill": False})
    corr = Correlator(FakeCloudflareClient(), cfg)
    rule = make_rule(
        rule_id="rule-1",
        description="Block POST",
        action="block",
        adapter_class=None,
        rule_type="host_method_block",
    )
    result = make_result(rule, outcomes=[make_outcome(ray="aabbccddeeff0011", status=403)])
    raw = load_event_fixture("ray_match_block.json")
    events = [make_firewall_event(**row) for row in raw]
    ev = corr._reconcile_one(result, _by_ray(events), events)
    assert ev.verdict == Verdict.PASS
    assert ev.security_event_verified is True
    assert ev.match_method == "rule_id"


def test_missing_events_fail_for_block():
    cfg = make_config(options={"hybrid_graphql_fill": False})
    corr = Correlator(FakeCloudflareClient(), cfg)
    rule = make_rule(rule_id="rule-missing", action="block", adapter_class=None)
    result = make_result(rule, outcomes=[make_outcome(ray="deadbeef00000001", status=200)])
    ev = corr._reconcile_one(result, {}, [])
    assert ev.verdict == Verdict.FAIL
    assert "No firewall/security event matched" in ev.details


def test_reconcile_with_preloaded_events_no_graphql():
    cfg = make_config(options={"hybrid_graphql_fill": False})
    client = FakeCloudflareClient()
    corr = Correlator(client, cfg)
    rule = make_rule(rule_id="rule-1", action="block", adapter_class=None)
    result = make_result(rule, outcomes=[make_outcome(ray="aabbccddeeff0011")])
    events = [make_firewall_event(ray_id="aabbccddeeff0011", rule_id="rule-1", action="block")]
    now = datetime.now(timezone.utc)
    evidence = corr.reconcile([result], now, now, preloaded_events=events)
    assert len(evidence) == 1
    assert evidence[0].verdict == Verdict.PASS
    assert corr.evidence_source == "instant_logs"


def test_allowlist_shadowing_downgrades_unverified_pass():
    cfg = make_config(options={"hybrid_graphql_fill": False})
    corr = Correlator(FakeCloudflareClient(), cfg)

    allow = make_rule(
        rule_id="allow-1",
        description="AP WhiteList",
        phase="custom",
        action="skip",
        rule_type="ip_whitelist",
        adapter_class="IPListAdapter",
        extracted_params={
            "list_name": "ap_whitelist",
            "membership": "member",
        },
    )
    other = make_rule(
        rule_id="other-1",
        description="Content Type",
        phase="custom",
        action="block",
        rule_type="content_type",
        adapter_class=None,
    )
    allow_result = make_result(
        allow,
        adapter_name="ip_list",
        expected_action="skip",
        outcomes=[make_outcome(ray="rayallow00000001", status=200)],
    )
    # Force membership params visible to shadowing helper.
    allow_result.rule.extracted_params["membership"] = "member"

    other_result = make_result(
        other,
        outcomes=[make_outcome(ray="rayother00000001", status=200)],
    )
    # Unverified PASS on other (no own rule_id event).
    events = [
        make_firewall_event(
            ray_id="rayallow00000001", rule_id="allow-1", action="skip",
        ),
    ]
    now = datetime.now(timezone.utc)
    evidence = corr.reconcile(
        [allow_result, other_result], now, now, preloaded_events=events,
    )
    by_id = {e.rule_id: e for e in evidence}
    # other had no matching events → FAIL, then shadowing → MANUAL
    assert by_id["other-1"].verdict == Verdict.MANUAL
    assert by_id["other-1"].match_method == "shadowed"
