"""WAFScoreAdapter — validates Cloudflare WAF attack-score rules."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url

_HIGH_CONFIDENCE = [
    ("sqli", "id=1' OR '1'='1"),
    ("sqli_union", "id=1 UNION SELECT username,password FROM users--"),
    ("xss", "q=<script>alert(1)</script>"),
    ("traversal", "file=../../../../etc/passwd"),
    ("xss_img_onerror", "q=<img src=x onerror=alert(1)>"),
]

_MEDIUM_CONFIDENCE = [
    ("sqli_encoded", "id=1%27%20OR%20%271%27%3D%271"),
    ("xss_attr", "q=%22onmouseover%3Dalert(1)"),
    ("traversal_encoded", "file=..%2f..%2f..%2fetc%2fpasswd"),
    ("xss_svg_onload", "q=<svg/onload=fetch('//localhost')>"),
    ("cmdi_semicolon", "cmd=;cat /etc/shadow"),
    ("cmdi_pipe", "input=|id"),
]

_LOW_CONFIDENCE = [
    ("sqli_orderby_suspicious", "sort=name&order=1,2,3--"),
    ("sqli_like_wildcard", "search=admin%' AND '%'='"),
    ("xss_partial_tag", "comment=<b>bold</b><script>"),
    ("traversal_single", "path=../config.yml"),
]


class WAFScoreAdapter(BaseTestAdapter):
    name = "waf_score"
    description = "Validates WAF attack-score rules with graduated payloads"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        return (rule.action or "block").lower()

    def _threshold(self, rule) -> int:
        return int(rule.extracted_params.get("score_threshold", 5))

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        base = target_url(target)
        threshold = self._threshold(rule)
        if threshold <= 5:
            cases = list(_HIGH_CONFIDENCE)
        elif threshold <= 20:
            cases = list(_MEDIUM_CONFIDENCE)
        else:
            cases = list(_LOW_CONFIDENCE)

        payloads = []
        for label, query in cases:
            sep = "&" if "?" in base else "?"
            payloads.append(
                TestPayload(
                    method="GET",
                    url=f"{base}{sep}{query}",
                    description=f"WAF attack-score probe: {label}",
                    metadata={
                        "probe": label,
                        "score_threshold": threshold,
                        "rule_id": rule.rule_id,
                    },
                )
            )
        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        """Prefer exact rule-id evidence; only MANUAL when shadowed without proof."""
        rule_id = result.rule.rule_id
        threshold = self._threshold(result.rule)
        rays = []
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.append(o.cf_ray_id.split("-")[0])
            rays.extend(str(r).split("-")[0] for r in o.payload.metadata.get("rays", []))

        matched_this = []
        matched_other = []
        for ray in dict.fromkeys(rays):
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id:
                    matched_this.append(ev)
                elif ev.action:
                    matched_other.append(ev)

        if matched_this:
            actions = sorted({(e.action or "") for e in matched_this})
            return Verdict.PASS, (
                f"Rule id {rule_id} fired on {len(matched_this)} event(s); "
                f"actions={actions}."
            )

        if threshold > 5 and matched_other:
            return Verdict.MANUAL, (
                f"Probes were handled by other WAF rules before this threshold "
                f"(score ≤ {threshold}) could be attributed to rule {rule_id}. "
                f"Other actions seen: "
                f"{sorted({(e.action or '') for e in matched_other})}.\n\n"
                + self.manual_playbook(result.rule, None)
            )
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        threshold = self._threshold(rule)
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Condition: cf.waf.score ≤ {threshold}, action {self.expected_action(rule)}\n"
            f"In Security Events / Instant Logs, filter requests with waf score in the "
            f"band that only this rule covers, and confirm rule id {rule.rule_id} fired."
        )
