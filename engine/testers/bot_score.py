"""BotScoreAdapter — validates bot-management score rules."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url


class BotScoreAdapter(BaseTestAdapter):
    name = "bot_score"
    description = "Validates bot-management score rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "block").lower()

    def _threshold(self, rule) -> int:
        return int(rule.extracted_params.get("score_threshold", 5))

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        url = target_url(target)
        threshold = self._threshold(rule)
        return [
            TestPayload(
                method="GET",
                url=url,
                strip_default_headers=True,
                description=(
                    f"Bot-like request (stripped headers); "
                    f"targets bot score <= {threshold}"
                ),
                metadata={
                    "score_threshold": threshold,
                    "rule_id": rule.rule_id,
                },
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        rule_id = result.rule.rule_id
        rays = []
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.append(o.cf_ray_id.split("-")[0])
        matched = []
        for ray in rays:
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id:
                    matched.append(ev)
        if matched:
            return Verdict.PASS, (
                f"Bot-score rule {rule_id} matched in event stream "
                f"({len(matched)} event(s))."
            )

        if not result.outcomes:
            return Verdict.ERROR, "No requests were sent."

        status = result.outcomes[0].status_code
        if status and status < 400:
            # Probe sent and allowed — bot score did not trip. Not a config FAIL;
            # automation cannot force a low bot score. Provide playbook.
            return Verdict.MANUAL, self.manual_playbook(result.rule, None)
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        threshold = self._threshold(rule)
        expected = self.expected_action(rule)
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Condition: cf.bot_management.score ≤ {threshold}, action {expected}\n"
            f"Bot scoring uses TLS fingerprint, IP reputation, ASN, and behavior — "
            f"HTTP header stripping alone often cannot force score ≤ {threshold}.\n"
            f"1. In Security Events, find traffic with bot score ≤ {threshold}.\n"
            f"2. Confirm rule id {rule.rule_id} applied action '{expected}'."
        )
