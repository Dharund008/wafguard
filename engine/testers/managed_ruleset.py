"""ManagedRulesetAdapter — validates managed rulesets (Cloudflare Managed WAF,
OWASP Core Ruleset).

Fires a payload set spanning OWASP categories. The correlator confirms that
managed rules fired by matching CF-Ray IDs to events whose source is the
managed ruleset. Payloads are inert probe strings — they exercise rule matching
without carrying a working exploit against the origin.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload

# (label, query-fragment) probe set across OWASP categories.
_PROBES = [
    ("sqli_union", "id=1 UNION SELECT NULL,NULL,NULL--"),
    ("sqli_bool", "id=1 AND 1=1"),
    ("xss_reflected", "q=<script>alert(document.cookie)</script>"),
    ("xss_event", "q=<img src=x onerror=alert(1)>"),
    ("lfi", "page=../../../../etc/passwd"),
    ("rfi", "page=http://169.254.169.254/latest/meta-data/"),
    ("cmdi", "host=127.0.0.1;cat /etc/passwd"),
    ("ssrf", "url=http://169.254.169.254/latest/meta-data/"),
]


class ManagedRulesetAdapter(BaseTestAdapter):
    name = "managed_ruleset"
    description = "Validates managed rulesets with OWASP-category probes"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        # Managed rulesets execute; individual managed rules decide the action.
        # We expect at least a block/challenge to be observable for the obvious
        # probes.
        return "block"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        base = f"{target.protocol}://{target.hostname}{path}"

        payloads = []
        for label, query in _PROBES:
            sep = "&" if "?" in base else "?"
            payloads.append(
                TestPayload(
                    method="GET",
                    url=f"{base}{sep}{query}",
                    description=f"Managed-ruleset probe: {label}",
                    metadata={"probe": label, "ruleset": rule.rule_type},
                )
            )
        return payloads
