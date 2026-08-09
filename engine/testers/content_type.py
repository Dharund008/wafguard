"""ContentTypeAdapter — validates content-type enforcement on matching hosts."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload
from .helpers import select_matching_target, target_url

_METHODS = ["POST", "PUT", "PATCH"]


class ContentTypeAdapter(BaseTestAdapter):
    name = "content_type"
    description = "Validates JSON content-type enforcement on matching hostnames"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        target = select_matching_target(rule, config)
        if target is None:
            return False, self.manual_playbook(rule, config)
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "block").lower()

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = select_matching_target(rule, config)
        if target is None:
            return []
        url = target_url(target)
        payloads = []
        for method in _METHODS:
            payloads.append(
                TestPayload(
                    method=method,
                    url=url,
                    headers={"Content-Type": "text/plain"},
                    body="not json",
                    description=f"{method} with text/plain to {target.hostname}",
                    metadata={"control": False, "method": method, "rule_id": rule.rule_id},
                )
            )
        payloads.append(
            TestPayload(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body="{}",
                description=f"POST application/json to {target.hostname} (control)",
                metadata={"control": True, "method": "POST", "rule_id": rule.rule_id},
            )
        )
        return payloads

    def manual_playbook(self, rule, config) -> str:
        hosts = (rule.extracted_params or {}).get("hosts") or []
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Needs a target hostname matching: {hosts or rule.expression}\n"
            f"1. Add a matching hostname under targets: in the zone config.\n"
            f"2. Re-run, or manually:\n"
            f"   curl -X POST https://<matching-host>/ -H 'Content-Type: text/plain' -d 'x'\n"
            f"3. Confirm rule {rule.rule_id} action '{self.expected_action(rule)}' in Security Events."
        )
