"""ContentTypeAdapter — validates content-type enforcement on API hostnames.

Sends POST/PUT/PATCH to services-* hostnames with the wrong content type
(text/plain instead of application/json); expects a block. Also sends a valid
JSON request as a negative control that should pass through.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload

_METHODS = ["POST", "PUT", "PATCH"]


class ContentTypeAdapter(BaseTestAdapter):
    name = "content_type"
    description = "Validates JSON content-type enforcement on API hostnames"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        # Needs a services-* hostname among the targets to be meaningful.
        api_host = self._api_target(config)
        if api_host is None:
            return False, (
                "No services-* API hostname found in targets. Add one to the "
                "config to validate content-type enforcement."
            )
        return True, ""

    def expected_action(self, rule) -> str:
        return rule.action or "block"

    def _api_target(self, config):
        for t in config.targets:
            if t.hostname.startswith("services-"):
                return t
        return None

    def build_payloads(self, rule, config) -> list[TestPayload]:
        target = self._api_target(config)
        if target is None:
            return []
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"

        payloads = []
        # Violating requests: wrong content type, should be blocked.
        for method in _METHODS:
            payloads.append(
                TestPayload(
                    method=method,
                    url=url,
                    headers={"Content-Type": "text/plain"},
                    body="not json",
                    description=f"{method} with text/plain (should block)",
                    metadata={"control": False, "method": method},
                )
            )
        # Negative control: valid JSON, should pass.
        payloads.append(
            TestPayload(
                method="POST",
                url=url,
                headers={"Content-Type": "application/json"},
                body="{}",
                description="POST with valid application/json (should pass)",
                metadata={"control": True, "method": "POST"},
            )
        )
        return payloads
