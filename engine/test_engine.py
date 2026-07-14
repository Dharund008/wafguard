"""Test execution engine.

Iterates classified rules, resolves each to its adapter, runs the pre-flight
check with config in hand, and — if executable — sends the adapter's payloads
live over HTTP, capturing status codes and CF-Ray IDs. Rules that cannot be
executed are recorded with a MANUAL verdict and the adapter's reason.

Execution is deliberately sequential and gently paced: WAF validation is not a
load test, and hammering the origin would distort results.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import requests

from .config import Config
from .discovery import DiscoveredRule
from .testers import Verdict, get_adapter
from .testers.base import RequestOutcome, TestResult

log = logging.getLogger("waf_validator.engine")

# Headers that make a request look like a normal browser. Stripped when an
# adapter requests a bare request (bot tests).
_DEFAULT_BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class TestEngine:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.window_start: datetime | None = None
        self.window_end: datetime | None = None

    # ------------------------------------------------------------------ #
    def run(self, rules: list[DiscoveredRule]) -> list[TestResult]:
        results: list[TestResult] = []
        self.window_start = datetime.now(timezone.utc)

        for rule in rules:
            if not rule.enabled:
                # Disabled rules are out of test scope; the reporter lists them
                # separately. We skip execution but keep a record.
                continue
            results.append(self._run_one(rule))

        self.window_end = datetime.now(timezone.utc)
        return results

    # ------------------------------------------------------------------ #
    def _run_one(self, rule: DiscoveredRule) -> TestResult:
        adapter = get_adapter(rule.adapter_class) if rule.adapter_class else None

        if adapter is None:
            return TestResult(
                rule=rule,
                adapter_name="(none)",
                expected_action=rule.action or "unknown",
                preflight_verdict=Verdict.MANUAL,
                preflight_reason=(
                    rule.manual_reason
                    or "No adapter is available for this rule type."
                ),
            )

        executable, reason = adapter.can_execute(rule, self.config)
        expected = adapter.expected_action(rule)

        if not executable:
            return TestResult(
                rule=rule,
                adapter_name=adapter.name,
                expected_action=expected,
                preflight_verdict=Verdict.MANUAL,
                preflight_reason=reason,
            )

        result = TestResult(
            rule=rule,
            adapter_name=adapter.name,
            expected_action=expected,
        )

        payloads = adapter.build_payloads(rule, self.config)
        for payload in payloads:
            outcome = self._send(payload)
            result.outcomes.append(outcome)

        return result

    # ------------------------------------------------------------------ #
    def _send(self, payload) -> RequestOutcome:
        opts = self.config.options
        headers = {"User-Agent": opts.get("user_agent", "AP-WAF-Validator/1.0")}
        if not payload.strip_default_headers:
            headers.update(_DEFAULT_BROWSER_HEADERS)
        headers.update(payload.headers or {})

        proxies = None
        socks = opts.get("socks_proxy")
        if socks and payload.metadata.get("socks_proxy"):
            proxies = {"http": socks, "https": socks}

        verify = opts.get("verify_ssl", True)
        timeout = opts.get("request_timeout", 10)
        inter_delay = float(opts.get("inter_request_delay", 0.0))

        per_request_status: list[int] = []
        first_ray: str | None = None
        last_status: int | None = None
        last_headers: dict = {}
        error: str | None = None
        sent_at = datetime.now(timezone.utc)
        start = time.monotonic()

        for i in range(max(1, payload.repeat)):
            try:
                resp = self.session.request(
                    payload.method,
                    payload.url,
                    headers=headers,
                    data=payload.body,
                    timeout=timeout,
                    verify=verify,
                    proxies=proxies,
                    allow_redirects=False,
                )
                last_status = resp.status_code
                last_headers = dict(resp.headers)
                per_request_status.append(resp.status_code)
                ray = resp.headers.get("cf-ray", "").split("-")[0] or None
                if ray and first_ray is None:
                    first_ray = ray
                if ray:
                    payload.metadata.setdefault("rays", [])
                    if ray not in payload.metadata["rays"]:
                        payload.metadata["rays"].append(ray)
            except requests.RequestException as exc:
                error = str(exc)
                per_request_status.append(-1)
                log.warning("Request error for %s: %s", payload.url, exc)
            if inter_delay and i < payload.repeat - 1:
                time.sleep(inter_delay)

        duration_ms = (time.monotonic() - start) * 1000.0
        payload.metadata["per_request_status"] = per_request_status

        return RequestOutcome(
            payload=payload,
            status_code=last_status,
            cf_ray_id=first_ray,
            response_headers=last_headers,
            sent_at=sent_at,
            duration_ms=duration_ms,
            error=error,
        )
