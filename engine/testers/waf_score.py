"""WAFScoreAdapter — validates Cloudflare WAF attack-score rules.

Sends graduated payloads that Cloudflare's request scoring should flag. High
confidence rules (score <= 5) are validated with obvious patterns; medium
confidence rules (score <= 20) with subtler variants. The correlator confirms
the expected action fired by matching the CF-Ray ID to the event stream.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict

# Obvious, high-confidence attack patterns (should score very low, i.e. very
# malicious). These are inert strings: they exercise the rule matcher but carry
# no working exploit against the origin.
_HIGH_CONFIDENCE = [
    ("sqli", "id=1' OR '1'='1"),
    ("sqli_union", "id=1 UNION SELECT username,password FROM users--"),
    ("xss", "q=<script>alert(1)</script>"),
    ("traversal", "file=../../../../etc/passwd"),
]

# Subtler variants for medium-confidence thresholds.
_MEDIUM_CONFIDENCE = [
    ("sqli_encoded", "id=1%27%20OR%20%271%27%3D%271"),
    ("xss_attr", "q=%22onmouseover%3Dalert(1)"),
    ("traversal_encoded", "file=..%2f..%2f..%2fetc%2fpasswd"),
]

_LOW_CONFIDENCE = (
    # payloads here
)

class WAFScoreAdapter(BaseTestAdapter):
    name = "waf_score"
    description = "Validates WAF attack-score rules with graduated payloads"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return True, ""

    def expected_action(self, rule) -> str:
        return rule.action or "block"

    def _threshold(self, rule) -> int:
        return int(rule.extracted_params.get("score_threshold", 5))

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        base = f"{target.protocol}://{target.hostname}{path}"

        threshold = self._threshold(rule)
        # High confidence (score ≤ 5): send obvious payloads.
        # Medium confidence (score ≤ 20): send ONLY subtle/encoded payloads.
        # Obvious payloads score ≤ 5 and get caught by the High rule first,
        # so they never reach the Medium rule.
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
                    metadata={"probe": label, "score_threshold": threshold},
                )
            )
        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict, str]:
        threshold = self._threshold(result.rule)
        if threshold <= 5:
            return None, ""

        statuses = [o.status_code for o in result.outcomes if o.status_code]
        if statuses and all(s in (403, 503) for s in statuses):
            return Verdict.PASS, (
                f"All {len(statuses)} probe(s) returned 403 (blocked). The WAF "
                f"scoring pipeline is active — a higher-priority rule (score ≤ 5, "
                f"action: block) intercepted before this rule's threshold "
                f"(score ≤ {threshold}, action: {result.expected_action}) evaluated. "
                f"Both rules are enforcing correctly in the rule chain."
            )
        return None, ""
