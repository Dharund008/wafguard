"""BotScoreAdapter — validates bot-management score rules.

Sends requests engineered to look automated (stripped browser headers, no
session state) to drive a low bot score. Marked partial: Cloudflare's bot
scoring is a server-side ML model, so identical inputs do not guarantee
identical scores across edge locations. The event stream is the authoritative
verdict source; this adapter documents exactly what it sent.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict


class BotScoreAdapter(BaseTestAdapter):
    name = "bot_score"
    description = "Validates bot-management score rules (partial automation)"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        # Always executable, but the caller should treat the result as
        # indicative — see notes attached in build_payloads.
        return True, ""

    def expected_action(self, rule) -> str:
        return rule.action or "block"

    def _threshold(self, rule) -> int:
        return int(rule.extracted_params.get("score_threshold", 5))

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"
        threshold = self._threshold(rule)

        # A bare, header-stripped request looks maximally bot-like.
        return [
            TestPayload(
                method="GET",
                url=url,
                strip_default_headers=True,
                description=(
                    f"Bot-like request (stripped headers, no cookies); "
                    f"targets bot score <= {threshold}"
                ),
                metadata={
                    "score_threshold": threshold,
                    "partial": True,
                    "note": (
                        "Bot scoring is non-deterministic server-side ML; "
                        "treat the event-stream result as authoritative."
                    ),
                },
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict, str]:
        if not result.outcomes:
            return Verdict.ERROR, "No requests were sent."
        status = result.outcomes[0].status_code
        threshold = self._threshold(result.rule)
        expected = result.expected_action or "block"

        if status and status < 400:
            return Verdict.MANUAL, (
                f"Request sent → Cloudflare evaluated → bot score did not meet threshold.\n"
                f"\n"
                f"  Probe sent:        GET / (stripped headers, no cookies)\n"
                f"  Response:          {status} (no enforcement action taken)\n"
                f"  Rule condition:    bot_management.score ≤ {threshold}\n"
                f"  Expected action:   {expected}\n"
                f"  What happened:     Cloudflare's ML evaluated the request but scored it\n"
                f"                     above {threshold}. The rule condition was not met,\n"
                f"                     so no action was taken and no Security Event was generated.\n"
                f"  Why:               Bot scoring relies on TLS fingerprint (JA3/JA4), IP\n"
                f"                     reputation, ASN classification, and behavioral signals —\n"
                f"                     not just HTTP headers. A legitimate client cannot\n"
                f"                     simulate a low enough score to trigger this rule.\n"
                f"  Rule status:       Configured correctly — cannot be validated from this client.\n"
                f"  Manual step:       Check Security Events for real bot traffic (score ≤ {threshold})\n"
                f"                     and confirm the '{expected}' action was applied."
            )
        return None, ""
