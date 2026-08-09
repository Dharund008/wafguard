"""VerifiedBotAdapter and APITrafficAdapter."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload
from .helpers import select_matching_target, target_url


class VerifiedBotAdapter(BaseTestAdapter):
    name = "verified_bot"
    description = "Validates verified-bot skip rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        # Physically cannot spoof Cloudflare verified-bot classification.
        return False, self.manual_playbook(rule, config)

    def expected_action(self, rule) -> str:
        return (rule.action or "skip").lower()

    def build_payloads(self, rule, config) -> list[TestPayload]:
        return []

    def manual_playbook(self, rule, config) -> str:
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Verified bot status is assigned by Cloudflare to known crawlers "
            f"(Googlebot, Bingbot, etc.) and cannot be simulated client-side.\n"
            f"1. In Security Events, filter Source ≈ firewallCustom and "
            f"rule id {rule.rule_id} (or description contains 'Good Bots' / verified).\n"
            f"2. Confirm action '{self.expected_action(rule)}' on real crawler traffic.\n"
            f"3. Expression for reference: {rule.expression}"
        )


class APITrafficAdapter(BaseTestAdapter):
    name = "api_traffic"
    description = "Validates host-scoped skip/allow rules (e.g. API traffic)"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        if select_matching_target(rule, config) is None:
            return False, self.manual_playbook(rule, config)
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "skip").lower()

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = select_matching_target(rule, config)
        if target is None:
            return []
        url = target_url(target)
        return [
            TestPayload(
                method="GET",
                url=url,
                description=f"Host-scoped probe to {target.hostname}; expect {self.expected_action(rule)}",
                metadata={"rule_id": rule.rule_id},
            )
        ]

    def manual_playbook(self, rule, config) -> str:
        hosts = (rule.extracted_params or {}).get("hosts") or []
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Add a target hostname matching {hosts or rule.expression}, then re-run.\n"
            f"Or manually: curl -sI https://<matching-host>/ and confirm rule "
            f"{rule.rule_id} action '{self.expected_action(rule)}' in Security Events / Instant Logs."
        )
