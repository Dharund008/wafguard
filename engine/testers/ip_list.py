"""IPListAdapter — validates rules matching against named IP lists.

Works for any ``$list_name``. Prefers auto-execution when the runner's egress
IP is already a member of the list (queried via Account Lists API), or when
``test_ips`` maps the list name to an egress IP the runner is using.
"""

from __future__ import annotations

from .base import BaseTestAdapter, TestPayload, TestResult, Verdict
from .helpers import detect_egress_ip, resolve_test_ip_for_list, target_url


class IPListAdapter(BaseTestAdapter):
    name = "ip_list"
    description = "Validates IP allow/block/bypass list rules"

    def _list_name(self, rule) -> str:
        return (rule.extracted_params or {}).get("list_name") or ""

    def expected_action(self, rule) -> str:
        action = (rule.action or "").lower()
        if action in {"skip", "allow", "bypass"}:
            return "skip"
        if action == "log":
            return "log"
        return action or "block"

    def can_execute(self, rule, config) -> tuple[bool, str]:
        list_name = self._list_name(rule)
        if not list_name:
            return False, "Could not extract IP list name from the expression."

        configured = resolve_test_ip_for_list(config, list_name)
        egress = detect_egress_ip()

        client = getattr(config, "_cf_client", None)
        if client is not None and egress:
            member = client.list_contains_ip(list_name, egress)
            if member is True:
                rule.extracted_params["egress_ip"] = egress
                rule.extracted_params["membership"] = "member"
                rule.extracted_params["mode"] = "positive"
                return True, ""
            if member is False:
                rule.extracted_params["egress_ip"] = egress
                rule.extracted_params["membership"] = "non_member"
                if self.expected_action(rule) in {"block", "challenge", "log"}:
                    rule.extracted_params["mode"] = "negative_control"
                    return True, ""
                return False, self.manual_playbook(rule, config)

        if configured and egress and configured == egress:
            rule.extracted_params["egress_ip"] = egress
            rule.extracted_params["membership"] = "configured_match"
            rule.extracted_params["mode"] = "positive"
            return True, ""

        if configured:
            return False, (
                f"test_ips lists {configured} for ${list_name}, but this runner "
                f"egresses as {egress or 'unknown'}. Re-run from {configured}, "
                f"or add that IP to the runner's egress path.\n\n"
                + self.manual_playbook(rule, config)
            )

        return False, self.manual_playbook(rule, config)

    def build_payloads(self, rule, config) -> list[TestPayload]:
        list_name = self._list_name(rule)
        action = self.expected_action(rule)
        target = config.primary_target()
        url = target_url(target)
        mode = (rule.extracted_params or {}).get("mode", "positive")
        egress = (rule.extracted_params or {}).get("egress_ip") or detect_egress_ip()
        return [
            TestPayload(
                method="GET",
                url=url,
                description=(
                    f"IP-list probe for ${list_name} ({mode}); "
                    f"expected action '{action}' from {egress}."
                ),
                metadata={
                    "list": list_name,
                    "mode": mode,
                    "required_source_ip": egress,
                    "expected_action": action,
                    "rule_id": rule.rule_id,
                },
            )
        ]

    def interpret(self, result: TestResult, correlated) -> tuple[Verdict | None, str]:
        mode = (result.rule.extracted_params or {}).get("mode", "positive")
        rule_id = result.rule.rule_id
        list_name = self._list_name(result.rule)
        rays = []
        for o in result.outcomes:
            if o.cf_ray_id:
                rays.append(o.cf_ray_id.split("-")[0])
            rays.extend(str(r).split("-")[0] for r in o.payload.metadata.get("rays", []))

        hits = []
        for ray in dict.fromkeys(rays):
            for ev in correlated.get(ray, []):
                if ev.rule_id == rule_id:
                    hits.append(ev)

        if mode == "negative_control":
            if hits:
                return Verdict.FAIL, (
                    f"Negative control failed: runner is not in ${list_name} but "
                    f"rule {rule_id} still matched {len(hits)} event(s)."
                )
            return Verdict.PASS, (
                f"Negative control passed: egress is not in ${list_name} and "
                f"rule {rule_id} did not fire. Positive proof still requires a "
                f"member-IP egress (see playbook)."
            )

        if hits:
            return Verdict.PASS, (
                f"IP-list rule {rule_id} (${list_name}) matched "
                f"{len(hits)} security event(s)."
            )
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        list_name = self._list_name(rule)
        action = self.expected_action(rule)
        samples = []
        client = getattr(config, "_cf_client", None)
        if client is not None and list_name:
            try:
                samples = client.sample_list_ips(list_name, limit=3)
            except Exception:
                samples = []
        sample_txt = ", ".join(samples) if samples else "(unable to sample list)"
        target = config.primary_target()
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"List: ${list_name}  Expected action: {action}\n"
            f"Sample member IP(s): {sample_txt}\n"
            f"1. From a host whose egress IP is a member of ${list_name}, run:\n"
            f"   curl -sI https://{target.hostname}/\n"
            f"2. Note CF-Ray.\n"
            f"3. In Security Events / Instant Logs, confirm rule id {rule.rule_id} "
            f"with action '{action}'.\n"
            f"4. Optionally set test_ips.{list_name}: <member-ip> and re-run from that IP."
        )
