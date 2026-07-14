"""GeoBlockAdapter — validates country/geo block rules.

Geo enforcement requires the request to originate from the blocked geography,
which cannot be simulated from an arbitrary client. Marked MANUAL by default.
If a SOCKS proxy is configured in options, the adapter becomes executable and
routes the probe through it.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload


class GeoBlockAdapter(BaseTestAdapter):
    name = "geo_block"
    description = "Validates country/geo block rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        proxy = config.options.get("socks_proxy")
        if proxy:
            return True, ""
        countries = rule.extracted_params.get("countries", ["?"])
        return False, (
            f"Rule blocks country code(s) {countries}. Requires a request from "
            f"that geography (e.g. Tor exit for T1). Configure options.socks_proxy "
            f"to automate, or validate manually via Tor Browser / a regional proxy "
            f"and confirm the block in the event stream."
        )

    def expected_action(self, rule) -> str:
        return rule.action or "block"

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"
        proxy = config.options.get("socks_proxy")
        countries = rule.extracted_params.get("countries", [])
        return [
            TestPayload(
                method="GET",
                url=url,
                description=f"Geo-block probe for {countries} via proxy",
                metadata={"socks_proxy": proxy, "countries": countries},
            )
        ]
