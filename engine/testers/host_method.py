"""HostMethodAdapter — validates host + HTTP method block rules.

Handles rules like: block POST to hosts containing "pronto-training".
Sends the blocked method as a positive test (expect block) and GET as a
negative control (expect pass).
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict


class HostMethodAdapter(BaseTestAdapter):
    name = "host_method_block"
    description = "Validates host + HTTP method block rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        host_substr = rule.extracted_params.get("host", "")
        for target in config.targets:
            if host_substr in target.hostname:
                return True, ""
        return False, (
            f"No configured target hostname contains \"{host_substr}\". "
            f"Add a target with \"{host_substr}\" in its hostname to test this rule."
        )

    def expected_action(self, rule) -> str:
        return rule.action or "block"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        host_substr = rule.extracted_params.get("host", "")
        methods = rule.extracted_params.get("methods", ["POST"])

        target = None
        for t in config.targets:
            if host_substr in t.hostname:
                target = t
                break

        if not target:
            return []

        path = target.test_paths.get("default", "/")
        base_url = f"{target.protocol}://{target.hostname}{path}"
        payloads = []

        for method in methods:
            payloads.append(TestPayload(
                method=method,
                url=base_url,
                description=f"{method} to {target.hostname} (expect block)",
            ))

        if "GET" not in methods:
            payloads.append(TestPayload(
                method="GET",
                url=base_url,
                description=f"GET to {target.hostname} (negative control, expect pass)",
                metadata={"negative_control": True},
            ))

        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict, str]:
        if not result.outcomes:
            return None, ""

        blocked = []
        passed = []
        for o in result.outcomes:
            if o.payload.metadata.get("negative_control"):
                passed.append(o)
            else:
                blocked.append(o)

        blocked_statuses = [o.status_code for o in blocked if o.status_code]
        passed_statuses = [o.status_code for o in passed if o.status_code]

        if blocked_statuses and all(s == 403 for s in blocked_statuses):
            methods = ", ".join(o.payload.method for o in blocked)
            if passed_statuses and all(s < 400 for s in passed_statuses):
                ctrl_methods = ", ".join(o.payload.method for o in passed)
                return Verdict.PASS, (
                    f"Blocked method(s) [{methods}] returned 403. "
                    f"Negative control [{ctrl_methods}] returned "
                    f"{passed_statuses[0]} (passed through). "
                    f"Rule is selectively enforcing on the correct methods."
                )
            return Verdict.PASS, (
                f"Blocked method(s) [{methods}] returned 403. "
                f"Rule is enforcing correctly."
            )
        return None, ""
