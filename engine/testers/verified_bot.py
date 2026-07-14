"""VerifiedBotAdapter and APITrafficAdapter.

VerifiedBotAdapter: "Good Bots" rules skip verified crawlers. Verified status
is an upstream classification that cannot be spoofed client-side, so this is
always MANUAL — the operator checks the event stream for real crawler traffic.

APITrafficAdapter: rules that skip the super-bot-fight-management phase for
services-* API hosts. Partially automatable: we can send a request to the API
host and confirm the skip appears in the event stream, but the "verified API
client" nuance may require manual confirmation.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload


class VerifiedBotAdapter(BaseTestAdapter):
    name = "verified_bot"
    description = "Validates verified-bot skip rules (manual)"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        return False, (
            "Verified bot status is assigned by Cloudflare to known crawler "
            "infrastructure (Googlebot, Bingbot, etc.) and cannot be simulated. "
            "Validate manually: query the event stream for verified-bot traffic "
            "and confirm the 'skip' action was applied."
        )

    def expected_action(self, rule) -> str:
        return rule.action or "skip"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        return []


class APITrafficAdapter(BaseTestAdapter):
    name = "api_traffic"
    description = "Validates API-traffic bot-skip rules (partial)"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        api_host = next(
            (t for t in config.targets if t.hostname.startswith("services-")),
            None,
        )
        if api_host is None:
            return False, (
                "No services-* hostname in targets. Add one to validate the "
                "API-traffic skip rule."
            )
        return True, ""

    def expected_action(self, rule) -> str:
        return rule.action or "skip"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = next(
            (t for t in config.targets if t.hostname.startswith("services-")),
            None,
        )
        if target is None:
            return []
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"
        return [
            TestPayload(
                method="GET",
                url=url,
                description="Request to services-* host; expect SBFM skip",
                metadata={"partial": True},
            )
        ]
