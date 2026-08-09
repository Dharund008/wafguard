"""RateLimitAdapter — validates rate limiting rules.

Sends ``requests_per_period + buffer`` requests within the configured period
and observes when enforcement begins. Overrides ``interpret`` to assert on the
observed HTTP status transition (2xx/4xx -> 429/403/503) rather than relying
solely on event correlation, because rate-limit enforcement is most reliably
observed client-side at the moment the threshold trips.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url

# Status codes Cloudflare returns when a rate-limit mitigation engages.
_MITIGATION_CODES = {429, 403, 503}


class RateLimitAdapter(BaseTestAdapter):
    name = "rate_limit"
    description = "Validates rate limiting rules by tripping the threshold"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        params = rule.extracted_params or {}
        if not params.get("requests_per_period"):
            return False, self.manual_playbook(rule, config)
        # Skip extremely high thresholds unless explicitly allowed — still
        # auto-testable, but warn via notes; do not force MANUAL.
        threshold = int(params.get("requests_per_period") or 0)
        max_auto = int(config.options.get("rate_limit_max_auto", 600))
        if threshold > max_auto:
            return False, (
                f"Threshold {threshold} exceeds rate_limit_max_auto={max_auto}. "
                f"Raise options.rate_limit_max_auto to auto-test, or follow:\n"
                + self.manual_playbook(rule, config)
            )
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "managed_challenge").lower()

    def build_payloads(self, rule, config) -> list[TestPayload]:
        params = rule.extracted_params or {}
        threshold = int(params.get("requests_per_period", 10))
        buffer = int(config.options.get("rate_limit_buffer", 5))
        total = threshold + buffer

        method = params.get("method", "GET")
        # 404 counting rules need a missing path.
        target = config.primary_target()
        if rule.rule_type == "rate_limit_404":
            url = f"{target.protocol}://{target.hostname}/waf-validator-404-probe-{threshold}"
        else:
            url = target_url(target)

        headers = {}
        if method in {"POST", "PUT", "PATCH"}:
            headers["Content-Type"] = "application/json"
            body = "{}"
        else:
            body = None

        # A single payload with repeat=total; the engine sends it in a tight
        # loop and records the status of every individual request.
        return [
            TestPayload(
                method=method,
                url=url,
                headers=headers,
                body=body,
                description=(
                    f"{total} {method} requests to trip rate limit "
                    f"(threshold={threshold}, buffer={buffer})"
                ),
                repeat=total,
                metadata={
                    "threshold": threshold,
                    "total": total,
                    "rule_id": rule.rule_id,
                },
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        """Assert enforcement engaged; also accept rule-id evidence for log actions."""
        if not result.outcomes:
            return Verdict.ERROR, "No requests were sent."

        outcome = result.outcomes[0]
        statuses = outcome.payload.metadata.get("per_request_status", [])
        threshold = outcome.payload.metadata.get("threshold", 0)
        rule_id = result.rule.rule_id
        expected = (result.expected_action or "").lower()

        # Event proof by rule id (works for action=log as well as mitigations).
        rays = set()
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.add(o.cf_ray_id.split("-")[0])
            for r in o.payload.metadata.get("rays", []):
                rays.add(str(r).split("-")[0])
        rule_hits = []
        for ray in rays:
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id:
                    rule_hits.append(ev)

        if not statuses:
            if rule_hits:
                return Verdict.PASS, (
                    f"Rate-limit rule {rule_id} matched in event stream "
                    f"({len(rule_hits)} event(s))."
                )
            return Verdict.ERROR, "No per-request status data captured."

        trip_index = next(
            (i for i, s in enumerate(statuses) if s in _MITIGATION_CODES),
            None,
        )
        if trip_index is not None:
            return Verdict.PASS, (
                f"Mitigation engaged at request #{trip_index + 1} "
                f"(threshold={threshold}). Observed status {statuses[trip_index]}."
            )

        if expected == "log" and rule_hits:
            return Verdict.PASS, (
                f"Rate-limit rule {rule_id} logged {len(rule_hits)} event(s) "
                f"during the probe burst (action=log; no HTTP mitigation expected)."
            )

        if expected == "log":
            # Log-only rules may not change status codes — defer to correlator.
            return None, ""

        return Verdict.FAIL, (
            f"Sent {len(statuses)} requests; no mitigation status "
            f"({sorted(_MITIGATION_CODES)}) and no event for rule {rule_id}."
        )

    def manual_playbook(self, rule, config) -> str:
        params = rule.extracted_params or {}
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Threshold: {params.get('requests_per_period')} / "
            f"{params.get('period')}s, action {self.expected_action(rule)}\n"
            f"Burst more than the threshold requests at the matching host/method, "
            f"then confirm rule {rule.rule_id} in Security Events / Instant Logs."
        )
