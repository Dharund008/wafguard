"""IPListAdapter — validates rules matching against named IP lists.

Covers $ap_whitelist (skip), $ap_blacklist (block), $ap_bypasslist (skip
managed+sbfm) and $ap_ratecontrol_bypass (skip ratelimit). Because the source
IP of the test runner usually is not in any of these lists, this adapter marks
the rule MANUAL unless the corresponding test IP is supplied in config. When a
test IP is available it is surfaced in the payload metadata so the operator can
run the request from that source.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload

# Map classified rule_type -> (config test_ip key, expected action, human label)
_LIST_MAP = {
    "ip_whitelist": ("whitelisted", "skip", "$ap_whitelist"),
    "ip_blocklist": ("blocked", "block", "$ap_blacklist"),
    "ip_bypass": ("bypass", "skip", "$ap_bypasslist"),
    "rate_bypass": ("rate_bypass", "skip", "$ap_ratecontrol_bypass"),
}


class IPListAdapter(BaseTestAdapter):
    name = "ip_list"
    description = "Validates IP allow/block/bypass list rules"

    def _mapping(self, rule):
        return _LIST_MAP.get(rule.rule_type, (None, "block", "unknown list"))

    def can_execute(self, rule, config) -> tuple[bool, str]:
        ip_key, _action, label = self._mapping(rule)
        if ip_key is None:
            return False, f"Unrecognized IP-list rule type: {rule.rule_type}"
        configured = config.test_ips.get(ip_key)
        if not configured:
            return False, (
                f"No test IP configured for {label}. Set test_ips.{ip_key} in "
                f"the config (an IP that is a member of {label}), or verify "
                f"this rule manually by sending a request from such an IP and "
                f"confirming the '{_action}' action in the event stream."
            )
        return True, ""

    def expected_action(self, rule) -> str:
        _ip_key, action, _label = self._mapping(rule)
        return action

    def build_payloads(self, rule, config) -> list[TestPayload]:
        ip_key, action, label = self._mapping(rule)
        configured = config.test_ips.get(ip_key)
        target = config.primary_target()
        path = target.test_paths.get("default", "/")
        url = f"{target.protocol}://{target.hostname}{path}"

        # NOTE: We cannot spoof the source IP from the client. If the operator
        # has arranged for the runner to egress from `configured`, this request
        # exercises the rule. Otherwise the pre-flight check already flagged it
        # MANUAL and this payload is not sent.
        return [
            TestPayload(
                method="GET",
                url=url,
                description=(
                    f"IP-list probe for {label}; expected action '{action}'. "
                    f"Must originate from {configured}."
                ),
                metadata={
                    "list": label,
                    "required_source_ip": configured,
                    "expected_action": action,
                },
            )
        ]
