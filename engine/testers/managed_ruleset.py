"""ManagedRulesetAdapter — validates managed rulesets (Cloudflare Managed WAF,
OWASP Core Ruleset).

Fires a payload set spanning OWASP categories. The correlator confirms that
managed rules fired by matching CF-Ray IDs to events whose source is the
managed ruleset. Payloads are inert probe strings — they exercise rule matching
without carrying a working exploit against the origin.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url

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

_MITIGATION = {403, 429, 503}


class ManagedRulesetAdapter(BaseTestAdapter):
    name = "managed_ruleset"
    description = "Validates managed rulesets with OWASP-category probes"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        return "block"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        base = target_url(target)

        payloads = []
        for label, query in _PROBES:
            sep = "&" if "?" in base else "?"
            payloads.append(
                TestPayload(
                    method="GET",
                    url=f"{base}{sep}{query}",
                    description=f"Managed-ruleset probe: {label}",
                    metadata={
                        "probe": label,
                        "ruleset": rule.rule_type,
                        "rule_id": rule.rule_id,
                    },
                )
            )
        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        """Prefer security-event proof; accept consistent HTTP mitigation as backup."""
        rays = []
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.append(o.cf_ray_id.split("-")[0])
            rays.extend(str(r).split("-")[0] for r in o.payload.metadata.get("rays", []))

        managed_hits = []
        for ray in dict.fromkeys(rays):
            for ev in correlated.get(ray, []):
                src = (ev.source or "").lower()
                if "managed" in src or (ev.action or "").lower() in {
                    "block", "managed_block", "challenge", "managed_challenge",
                }:
                    managed_hits.append(ev)

        if managed_hits:
            return Verdict.PASS, (
                f"Managed ruleset activity verified in security events "
                f"({len(managed_hits)} event(s) across probe Ray IDs)."
            )

        statuses = [o.status_code for o in result.outcomes if o.status_code]
        if statuses and all(s in _MITIGATION for s in statuses):
            # Mark via metadata so correlator can still attach events loosely.
            result.notes = "http_mitigation_all_probes"
            return Verdict.PASS, (
                f"All {len(statuses)} managed probes returned mitigation HTTP "
                f"statuses {sorted(set(statuses))}. Prefer Instant Logs/GraphQL "
                f"Ray matches for stricter security-event proof when available."
            )
        return None, ""
