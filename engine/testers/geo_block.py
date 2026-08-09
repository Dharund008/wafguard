"""GeoBlockAdapter — validates country/geo block rules."""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload
from .helpers import detect_egress_ip, target_url


class GeoBlockAdapter(BaseTestAdapter):
    name = "geo_block"
    description = "Validates country/geo block rules"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        if config.options.get("socks_proxy"):
            return True, ""
        # Auto-run when we can detect country via Cloudflare trace and it matches.
        countries = set((rule.extracted_params or {}).get("countries") or [])
        detected = self._detect_country()
        if detected and detected.upper() in {c.upper() for c in countries}:
            rule.extracted_params["detected_country"] = detected
            return True, ""
        return False, self.manual_playbook(rule, config)

    def expected_action(self, rule) -> str:
        return (rule.action or "block").lower()

    def _detect_country(self) -> str | None:
        import requests
        try:
            resp = requests.get("https://1.1.1.1/cdn-cgi/trace", timeout=5)
            for line in (resp.text or "").splitlines():
                if line.startswith("loc="):
                    return line.split("=", 1)[1].strip()
        except Exception:
            return None
        return None

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = config.primary_target()
        url = target_url(target)
        proxy = config.options.get("socks_proxy")
        countries = rule.extracted_params.get("countries", [])
        return [
            TestPayload(
                method="GET",
                url=url,
                description=f"Geo-block probe for {countries}",
                metadata={
                    "socks_proxy": proxy,
                    "countries": countries,
                    "rule_id": rule.rule_id,
                },
            )
        ]

    def manual_playbook(self, rule, config) -> str:
        countries = (rule.extracted_params or {}).get("countries", [])
        egress = detect_egress_ip()
        target = config.primary_target()
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Blocks country code(s): {countries}. Runner egress: {egress}.\n"
            f"Option A: set options.socks_proxy to an egress in {countries} and re-run.\n"
            f"Option B: from a host in {countries}:\n"
            f"  curl -sI https://{target.hostname}/\n"
            f"Confirm rule {rule.rule_id} action '{self.expected_action(rule)}' in Security Events.\n"
            f"Note: T1 is Tor; use a Tor SOCKS proxy (socks5h://127.0.0.1:9050)."
        )
