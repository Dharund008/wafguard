"""HostMethodAdapter — validates host + HTTP method rules."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import select_matching_target, target_url


class HostMethodAdapter(BaseTestAdapter):
    name = "host_method_block"
    description = "Validates host + HTTP method block rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        if select_matching_target(rule, config) is None:
            return False, self.manual_playbook(rule, config)
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "block").lower()

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = select_matching_target(rule, config)
        if not target:
            return []
        methods = rule.extracted_params.get("methods") or ["POST"]
        url = target_url(target)
        payloads = []
        for method in methods:
            body = "{}" if method in {"POST", "PUT", "PATCH"} else None
            headers = {"Content-Type": "application/json"} if body else {}
            payloads.append(TestPayload(
                method=method,
                url=url,
                headers=headers,
                body=body,
                description=f"{method} to {target.hostname} (expect {self.expected_action(rule)})",
                metadata={"rule_id": rule.rule_id},
            ))
        if "GET" not in methods:
            payloads.append(TestPayload(
                method="GET",
                url=url,
                description=f"GET to {target.hostname} (negative control)",
                metadata={"negative_control": True, "rule_id": rule.rule_id},
            ))
        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        if not result.outcomes:
            return None, ""
        blocked = [o for o in result.outcomes if not o.payload.metadata.get("negative_control")]
        passed = [o for o in result.outcomes if o.payload.metadata.get("negative_control")]
        blocked_statuses = [o.status_code for o in blocked if o.status_code]
        passed_statuses = [o.status_code for o in passed if o.status_code]
        expected = result.expected_action

        # Prefer event correlation when available; only assert on hard blocks via status.
        if expected in {"block", "managed_challenge", "challenge"} and blocked_statuses:
            if all(s in (403, 429, 503) for s in blocked_statuses):
                if passed_statuses and all(s < 400 for s in passed_statuses):
                    return Verdict.PASS, (
                        f"Blocked method(s) returned {blocked_statuses}; "
                        f"negative control returned {passed_statuses}."
                    )
                return Verdict.PASS, f"Blocked method(s) returned {blocked_statuses}."
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        hosts = (rule.extracted_params or {}).get("hosts") or [
            (rule.extracted_params or {}).get("host", "")
        ]
        methods = (rule.extracted_params or {}).get("methods") or []
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Add a target matching host(s) {hosts} then re-run, or:\n"
            f"  curl -X {methods[0] if methods else 'POST'} https://<matching-host>/\n"
            f"Confirm rule {rule.rule_id} action '{self.expected_action(rule)}' in Security Events."
        )
