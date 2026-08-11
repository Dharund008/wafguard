"""WAFScoreAdapter — validates Cloudflare WAF attack-score rules.

PASS requires this rule's ``rule_id`` on **this rule's own probe Rays**.
Cross-probe hits (e.g. Medium firing on a High payload) are noted but never
alone certify PASS — that caused false Medium PASS during cutover validation.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import target_url

# Map Instant Logs / GraphQL action strings to our vocabulary.
_ACTION_NORM = {
    "managed_challenge": "challenge",
    "managedChallenge": "challenge",
    "js_challenge": "challenge",
    "jsChallenge": "challenge",
    "jschallenge": "challenge",
    "challenge": "challenge",
    "block": "block",
    "managed_block": "block",
    "managedBlock": "block",
    "log": "log",
    "skip": "skip",
}


def _norm_action(action: str | None) -> str:
    if not action:
        return ""
    return _ACTION_NORM.get(action, action.lower())


_HIGH_CONFIDENCE = [
    ("sqli", "id=1' OR '1'='1"),
    ("sqli_union", "id=1 UNION SELECT username,password FROM users--"),
    ("xss", "q=<script>alert(1)</script>"),
    ("traversal", "file=../../../../etc/passwd"),
    ("xss_img_onerror", "q=<img src=x onerror=alert(1)>"),
]

# Subtler probes aimed at cf.waf.score in (5, 20] without routinely scoring ≤ 5
# (which the High rule intercepts). Avoid raw cmdi / deep traversal that High
# blocked in live aptechlab events.
_MEDIUM_CONFIDENCE = [
    ("sqli_comment_noise", "id=1/*noise*/OR/**/1=1"),
    ("sqli_like_partial", "q=admin%'--"),
    ("xss_entity_partial", "q=&lt;img%20src=x%20onerror=alert(1)&gt;"),
    ("xss_js_uri_soft", "redirect=javascript:void(0)"),
    ("path_dotdot_soft", "path=./../config"),
    ("param_suspicious_order", "sort=name&order=1,2--"),
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
        return _norm_action(rule.action or "block")

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
                        "own_probe": True,
                    },
                )
            )
        return payloads

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        """PASS only on own-probe Rays matching this rule_id + expected action."""
        rule_id = result.rule.rule_id
        threshold = self._threshold(result.rule)
        expected = self.expected_action(result.rule)

        rays = []
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.append(o.cf_ray_id.split("-")[0])
            rays.extend(str(r).split("-")[0] for r in o.payload.metadata.get("rays", []))
        own_rays = list(dict.fromkeys(rays))

        matched_this: list = []
        matched_other: list = []
        for ray in own_rays:
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id:
                    matched_this.append(ev)
                elif ev.action and _norm_action(ev.action) not in {"", "log"}:
                    # Ignore ubiquitous "Log all" when classifying shadowing.
                    matched_other.append(ev)

        if matched_this:
            actions = {_norm_action(e.action) for e in matched_this}
            actions.discard("")
            if expected in actions or (expected == "challenge" and "challenge" in actions):
                return Verdict.PASS, (
                    f"Rule id {rule_id} fired on {len(matched_this)} own-probe "
                    f"event(s); actions={sorted(actions)} (expected '{expected}')."
                )
            return Verdict.FAIL, (
                f"Rule id {rule_id} fired on own-probe Rays but action(s) "
                f"{sorted(actions)} do not match expected '{expected}'."
            )

        # Cross-probe sightings (e.g. Medium on a High payload) — informational only.
        cross = [
            ev
            for evs in correlated.values()
            for ev in evs
            if ev.rule_id == rule_id
            and (ev.ray_id or "") not in own_rays
        ]
        cross_note = ""
        if cross:
            cross_actions = sorted({_norm_action(e.action) for e in cross if e.action})
            cross_note = (
                f"\nNote: rule id {rule_id} also appeared on {len(cross)} "
                f"other-test Ray(s) in this run (actions={cross_actions}); "
                f"that is not independent proof for this threshold band."
            )

        if threshold > 5:
            other_actions = sorted({_norm_action(e.action) for e in matched_other if e.action})
            if matched_other:
                return Verdict.MANUAL, (
                    f"Own probes did not trigger rule {rule_id} (score ≤ {threshold}). "
                    f"Higher-priority / other WAF rules handled the traffic instead "
                    f"(actions seen on own Rays: {other_actions}). "
                    f"This threshold band could not be independently verified.\n\n"
                    + self.manual_playbook(result.rule, None)
                    + cross_note
                )
            # No rule_id match and no clear shadowing events (sampling / empty).
            return Verdict.MANUAL, (
                f"No security event for rule {rule_id} on this rule's own probe "
                f"Rays. Cannot confirm score ≤ {threshold} enforcement.\n\n"
                + self.manual_playbook(result.rule, None)
                + cross_note
            )

        # High threshold (≤ 5): defer to correlator if no own-probe rule match.
        if cross_note:
            result.notes = cross_note.strip()
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        threshold = self._threshold(rule)
        expected = self.expected_action(rule)
        band = f"1–{threshold}" if threshold <= 5 else f"{5 + 1}–{threshold}"
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Condition: cf.waf.score ≤ {threshold}, action {expected}\n"
            f"1. In Security Events / Instant Logs, find requests whose WAF attack "
            f"score falls in band ({band}) so a higher-priority score rule does "
            f"not intercept first.\n"
            f"2. Confirm rule id {rule.rule_id} applied action '{expected}'.\n"
            f"3. Do not treat this rule firing on a different test's payload "
            f"(e.g. High sqli_union) as proof of this threshold alone."
        )
