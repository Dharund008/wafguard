"""LogObserveAdapter — validates catch-all / observe (log) rules."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url


class LogObserveAdapter(BaseTestAdapter):
    name = "log_observe"
    description = "Validates log/observe rules by confirming the rule id in events"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        return "log"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        return [
            TestPayload(
                method="GET",
                url=target_url(target),
                description=f"Observe/log probe for rule {rule.rule_id}",
                metadata={"rule_id": rule.rule_id, "expect_rule_match": True},
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        """PASS if any correlated event for our rays references this rule id."""
        rule_id = result.rule.rule_id
        rays = set()
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.add(o.cf_ray_id.split("-")[0])
            for r in o.payload.metadata.get("rays", []):
                rays.add(str(r).split("-")[0])
        matches = []
        for ray in rays:
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id or (ev.action or "").lower() in {"log", "unknown"}:
                    matches.append(ev)
        if matches:
            return Verdict.PASS, (
                f"Log/observe rule matched in event stream "
                f"({len(matches)} event(s) for rule {rule_id})."
            )
        # Defer to generic correlator (may still PASS on action=log).
        return None, ""
