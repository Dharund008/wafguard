"""Shared helpers for offline WafGuard unit tests (no network)."""

from __future__ import annotations

import json
from pathlib import Path

from engine.cf_client import FirewallEvent
from engine.config import Config, Target, _DEFAULT_OPTIONS
from engine.discovery import DiscoveredRule
from engine.testers.base import RequestOutcome, TestPayload, TestResult, Verdict

FIXTURES = Path(__file__).parent / "fixtures"


def load_rule_fixture(name: str) -> dict:
    path = FIXTURES / "rules" / name
    return json.loads(path.read_text(encoding="utf-8"))


def load_event_fixture(name: str) -> list[dict]:
    path = FIXTURES / "events" / name
    return json.loads(path.read_text(encoding="utf-8"))


def make_config(**kwargs) -> Config:
    opts = dict(_DEFAULT_OPTIONS)
    opts.update(kwargs.pop("options", {}) or {})
    targets = kwargs.pop("targets", None) or [
        Target(hostname="www.example.com", protocol="https"),
    ]
    return Config(
        zone_name=kwargs.pop("zone_name", "example.com"),
        zone_id=kwargs.pop("zone_id", "zone-test"),
        account_id=kwargs.pop("account_id", "acct-test"),
        api_token=kwargs.pop("api_token", "token-test"),
        targets=targets,
        test_ips=kwargs.pop("test_ips", {}),
        options=opts,
        **{k: v for k, v in kwargs.items() if k in {
            "output_format", "output_dir", "filename_template",
        }},
    )


def make_rule(**kwargs) -> DiscoveredRule:
    defaults = dict(
        rule_id="rule-1",
        phase="custom",
        description="test rule",
        expression="true",
        action="block",
        enabled=True,
        rule_type="ip_list",
        testable=False,
        scope="zone",
        adapter_class=None,
        extracted_params={},
    )
    defaults.update(kwargs)
    return DiscoveredRule(**defaults)


def make_firewall_event(**kwargs) -> FirewallEvent:
    defaults = dict(
        ray_id="aabbccddeeff0011",
        action="block",
        source="firewallCustom",
        rule_id="rule-1",
        description="test event",
        datetime="2026-01-01T00:00:00Z",
        raw={},
    )
    defaults.update(kwargs)
    return FirewallEvent(**defaults)


def make_outcome(*, ray: str = "aabbccddeeff0011", status: int = 403) -> RequestOutcome:
    payload = TestPayload(
        method="GET",
        url="https://www.example.com/",
        description="probe",
        metadata={"rays": [ray], "per_request_status": [status]},
    )
    return RequestOutcome(
        payload=payload,
        status_code=status,
        cf_ray_id=ray,
    )


def make_result(
    rule: DiscoveredRule,
    *,
    adapter_name: str = "test",
    expected_action: str | None = None,
    outcomes: list[RequestOutcome] | None = None,
    preflight_verdict: Verdict | None = None,
    preflight_reason: str = "",
) -> TestResult:
    return TestResult(
        rule=rule,
        adapter_name=adapter_name,
        expected_action=expected_action or (rule.action or "block"),
        outcomes=outcomes or [],
        preflight_verdict=preflight_verdict,
        preflight_reason=preflight_reason,
    )


class FakeCloudflareClient:
    """Minimal stub — never touches the network."""

    def __init__(self):
        self.events: list[FirewallEvent] = []

    def fetch_firewall_events(self, *args, **kwargs):
        return list(self.events)
