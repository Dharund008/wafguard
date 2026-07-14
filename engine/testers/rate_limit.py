"""RateLimitAdapter — validates rate limiting rules.

Sends ``requests_per_period + buffer`` requests within the configured period
and observes when enforcement begins. Overrides ``interpret`` to assert on the
observed HTTP status transition (2xx/4xx -> 429/403/503) rather than relying
solely on event correlation, because rate-limit enforcement is most reliably
observed client-side at the moment the threshold trips.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict

# Status codes Cloudflare returns when a rate-limit mitigation engages.
_MITIGATION_CODES = {429, 403, 503}


class RateLimitAdapter(BaseTestAdapter):
    name = "rate_limit"
    description = "Validates rate limiting rules by tripping the threshold"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        params = rule.extracted_params or {}
        if not params.get("requests_per_period"):
            return False, (
                "Could not extract requests_per_period from the rule; "
                "verify the rate-limit configuration manually."
            )
        return True, ""

    def expected_action(self, rule) -> str:
        # Rate-limit rules carry their own action (managed_challenge / block).
        return rule.action or "managed_challenge"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        params = rule.extracted_params or {}
        threshold = int(params.get("requests_per_period", 10))
        buffer = int(config.options.get("rate_limit_buffer", 5))
        total = threshold + buffer

        method = params.get("method", "GET")
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"

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
                metadata={"threshold": threshold, "total": total},
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict, str]:
        """Assert enforcement engaged at or shortly after the threshold."""
        if not result.outcomes:
            return Verdict.ERROR, "No requests were sent."

        outcome = result.outcomes[0]
        # The engine records per-request statuses in metadata for repeat>1.
        statuses = outcome.metadata.get("per_request_status", []) if hasattr(outcome, "metadata") else []
        # RequestOutcome has no metadata field by default; the engine stashes
        # the per-request list on the payload metadata instead.
        statuses = outcome.payload.metadata.get("per_request_status", [])
        threshold = outcome.payload.metadata.get("threshold", 0)

        if not statuses:
            return Verdict.ERROR, "No per-request status data captured."

        trip_index = next(
            (i for i, s in enumerate(statuses) if s in _MITIGATION_CODES),
            None,
        )
        if trip_index is None:
            return Verdict.FAIL, (
                f"Sent {len(statuses)} requests; no mitigation status "
                f"({sorted(_MITIGATION_CODES)}) observed. Rate limit may not be firing."
            )

        trip_request = trip_index + 1  # 1-indexed for humans
        return Verdict.PASS, (
            f"Mitigation engaged at request #{trip_request} "
            f"(threshold={threshold}). Observed status {statuses[trip_index]}."
        )
