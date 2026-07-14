"""Event reconciliation service.

After execution, the correlator fetches firewall events for the test window via
GraphQL and matches each test's CF-Ray IDs to events. The Ray ID is the primary,
deterministic key. Where an adapter provides its own interpretation (e.g. the
rate-limit adapter asserting on observed status transitions), that takes
precedence over generic action-matching.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta

from .cf_client import CloudflareClient, FirewallEvent
from .config import Config
from .testers import Verdict, get_adapter
from .testers.base import TestResult

log = logging.getLogger("waf_validator.correlator")


@dataclass
class Evidence:
    rule_id: str
    rule_description: str
    phase: str
    rule_type: str
    adapter_name: str
    expected_action: str
    verdict: Verdict
    details: str
    payload_summary: str = ""
    cf_ray_ids: list[str] = field(default_factory=list)
    matched_event_ids: list[str] = field(default_factory=list)
    action_taken: str | None = None
    match_method: str = ""            # 'ray_id' | 'status' | 'fallback' | 'preflight'
    timestamps: list[str] = field(default_factory=list)


# Normalize CF action names to our vocabulary.
_ACTION_ALIASES = {
    "managed_challenge": "challenge",
    "jschallenge": "challenge",
    "challenge": "challenge",
    "block": "block",
    "skip": "skip",
    "allow": "skip",
    "log": "log",
}


def _norm_action(action: str | None) -> str:
    if not action:
        return ""
    return _ACTION_ALIASES.get(action, action)


def _strip_ray_suffix(ray: str) -> str:
    """Strip the datacenter suffix from a CF-Ray ID.

    HTTP header returns 'abc123-MAA', GraphQL returns 'abc123'."""
    parts = ray.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isalpha():
        return parts[0]
    return ray


class Correlator:
    def __init__(self, client: CloudflareClient, config: Config):
        self.client = client
        self.config = config

    # ------------------------------------------------------------------ #
    def reconcile(
        self, results: list[TestResult], window_start, window_end
    ) -> list[Evidence]:
        events = self._fetch_events(window_start, window_end)
        by_ray: dict[str, FirewallEvent] = {}
        for ev in events:
            if ev.ray_id:
                by_ray[ev.ray_id] = ev

        evidence: list[Evidence] = []
        for result in results:
            evidence.append(self._reconcile_one(result, by_ray, events))
        return evidence

    # ------------------------------------------------------------------ #
    def _fetch_events(self, window_start, window_end) -> list[FirewallEvent]:
        opts = self.config.options
        delay = int(opts.get("event_poll_delay", 5))
        retries = int(opts.get("event_poll_retries", 3))
        interval = int(opts.get("event_poll_interval", 5))

        since = (window_start - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = (window_end + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.debug("Event query window: %s → %s", since, until)

        if delay:
            log.info("Waiting %ss for events to propagate…", delay)
            time.sleep(delay)

        events: list[FirewallEvent] = []
        for attempt in range(1, retries + 1):
            try:
                events = self.client.get_firewall_events(since, until)
            except Exception as exc:
                log.warning("Event fetch attempt %s failed: %s", attempt, exc)
                events = []
            if events:
                break
            if attempt < retries:
                log.info("No events yet; retrying in %ss (%s/%s)", interval, attempt, retries)
                time.sleep(interval)
        log.info("Fetched %s firewall events for the window.", len(events))
        return events

    # ------------------------------------------------------------------ #
    def _reconcile_one(
        self,
        result: TestResult,
        by_ray: dict[str, FirewallEvent],
        all_events: list[FirewallEvent],
    ) -> Evidence:
        rule = result.rule
        base = Evidence(
            rule_id=rule.rule_id,
            rule_description=rule.description,
            phase=rule.phase,
            rule_type=rule.rule_type,
            adapter_name=result.adapter_name,
            expected_action=_norm_action(result.expected_action),
            verdict=Verdict.ERROR,
            details="",
            payload_summary="; ".join(
                o.payload.description for o in result.outcomes
            ) or "(no payloads sent)",
        )

        # Pre-flight short circuit (MANUAL / ERROR before any request).
        if result.preflight_verdict is not None:
            base.verdict = result.preflight_verdict
            base.details = result.preflight_reason
            base.match_method = "preflight"
            return base

        # Collect all Ray IDs seen across this rule's requests.
        # Strip datacenter suffix (e.g. "-MAA") to match GraphQL rayName format.
        rays: list[str] = []
        for o in result.outcomes:
            for r in o.payload.metadata.get("rays", []):
                rays.append(_strip_ray_suffix(r))
            if o.cf_ray_id:
                rays.append(_strip_ray_suffix(o.cf_ray_id))
        rays = list(dict.fromkeys(rays))  # dedupe, preserve order
        base.cf_ray_ids = rays

        # Adapter-specific interpretation (e.g. rate-limit status assertion).
        adapter = get_adapter(rule.adapter_class) if rule.adapter_class else None
        if adapter is not None:
            verdict, details = adapter.interpret(result, by_ray)
            if verdict is not None:
                base.verdict = verdict
                base.details = details
                base.match_method = "status"
                # Still attach any matched events for evidence.
                self._attach_events(base, rays, by_ray)
                return base

        # Generic Ray-ID correlation.
        matched = [by_ray[r] for r in rays if r in by_ray]
        if matched:
            actions = {_norm_action(ev.action) for ev in matched}
            base.matched_event_ids = [ev.ray_id for ev in matched if ev.ray_id]
            base.timestamps = [ev.datetime for ev in matched if ev.datetime]
            base.action_taken = ", ".join(sorted(a for a in actions if a))
            base.match_method = "ray_id"

            if base.expected_action in actions:
                base.verdict = Verdict.PASS
                base.details = (
                    f"Ray-ID matched event(s); observed action '{base.action_taken}' "
                    f"matches expected '{base.expected_action}'."
                )
            else:
                base.verdict = Verdict.FAIL
                base.details = (
                    f"Ray-ID matched event(s), but observed action "
                    f"'{base.action_taken}' does not match expected "
                    f"'{base.expected_action}'."
                )
            return base

        # No event matched. Distinguish "expected skip" (no event is often
        # correct for skip rules) from a genuine miss.
        if base.expected_action == "skip":
            base.verdict = Verdict.PASS
            base.details = (
                "Expected a skip and no block/challenge event was recorded for "
                "the test requests, consistent with the traffic being allowed "
                "through. Confirm via the event stream if strict proof is needed."
            )
            base.match_method = "fallback"
            return base

        # For content-type / managed / waf tests we expected a block; absence of
        # a matching event is a failure to demonstrate enforcement.
        base.verdict = Verdict.FAIL
        base.details = (
            "No firewall event matched the test Ray-ID(s) within the window. "
            "The rule may not have fired, or events had not propagated. "
            f"Ray IDs probed: {', '.join(rays) if rays else '(none captured)'}."
        )
        base.match_method = "ray_id"
        return base

    # ------------------------------------------------------------------ #
    def _attach_events(self, evidence: Evidence, rays, by_ray) -> None:
        matched = [by_ray[r] for r in rays if r in by_ray]
        if matched:
            evidence.matched_event_ids = [ev.ray_id for ev in matched if ev.ray_id]
            evidence.timestamps = [ev.datetime for ev in matched if ev.datetime]
            actions = {_norm_action(ev.action) for ev in matched}
            evidence.action_taken = ", ".join(sorted(a for a in actions if a))
