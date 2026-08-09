"""Event reconciliation service.

Prefers Instant Logs (real-time) when available, falls back to GraphQL
``firewallEventsAdaptive``, and can hybrid-fill missing Ray IDs from GraphQL
when Instant Logs was partial. Matches tests to events by CF-Ray ID and, when
possible, by rule id — proving the classified WAF rule actually fired.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
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
    match_method: str = ""            # 'ray_id' | 'rule_id' | 'status' | 'fallback' | 'preflight'
    timestamps: list[str] = field(default_factory=list)
    scope: str = "zone"
    evidence_source: str = ""         # instant_logs | graphql | hybrid | none
    security_event_verified: bool = False
    _outcomes: list = field(default_factory=list)


_ACTION_ALIASES = {
    "managed_challenge": "challenge",
    "managedChallenge": "challenge",
    "jschallenge": "challenge",
    "js_challenge": "challenge",
    "jsChallenge": "challenge",
    "challenge": "challenge",
    "block": "block",
    "managed_block": "block",
    "managedBlock": "block",
    "simulate_block": "block",
    "simulateBlock": "block",
    "force_connection_close": "block",
    "forceConnectionClose": "block",
    "connection_close": "block",
    "connectionClose": "block",
    "skip": "skip",
    "allow": "skip",
    "bypass": "skip",
    "log": "log",
    "rewrite": "rewrite",
}


def _norm_action(action: str | None) -> str:
    if not action:
        return ""
    return _ACTION_ALIASES.get(action, action.lower() if action else "")


def _strip_ray_suffix(ray: str) -> str:
    parts = ray.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isalpha():
        return parts[0]
    return ray


class Correlator:
    def __init__(self, client: CloudflareClient, config: Config):
        self.client = client
        self.config = config
        self.evidence_source: str = "none"
        self.evidence_note: str = ""

    def reconcile(
        self,
        results: list[TestResult],
        window_start,
        window_end,
        *,
        preloaded_events: list[FirewallEvent] | None = None,
    ) -> list[Evidence]:
        expected_rays = self._collect_expected_rays(results)
        events: list[FirewallEvent] = []
        source = "none"

        if preloaded_events is not None:
            events = list(preloaded_events)
            source = "instant_logs"
            log.info("Using %d Instant Logs events.", len(events))
            # Hybrid fill: if Instant Logs missed expected rays, query GraphQL.
            seen = {ev.ray_id for ev in events if ev.ray_id}
            missing = expected_rays - seen
            if missing and self.config.options.get("hybrid_graphql_fill", True):
                log.info(
                    "Instant Logs missing %d expected Ray ID(s); hybrid GraphQL fill…",
                    len(missing),
                )
                # Shorter wait: Instant Logs already drained; analytics only needs a brief lag.
                saved_delay = self.config.options.get("event_poll_delay")
                self.config.options["event_poll_delay"] = int(
                    self.config.options.get("hybrid_poll_delay", 15)
                )
                try:
                    gql = self._fetch_events_graphql(window_start, window_end, missing)
                finally:
                    if saved_delay is not None:
                        self.config.options["event_poll_delay"] = saved_delay
                if gql:
                    events = self._merge_events(events, gql)
                    source = "hybrid"
                    log.info("Hybrid merge complete: %d total events.", len(events))
        else:
            log.info("No Instant Logs events; falling back to GraphQL polling.")
            events = self._fetch_events_graphql(window_start, window_end, expected_rays)
            source = "graphql" if events is not None else "none"

        self.evidence_source = source
        self.evidence_note = {
            "instant_logs": "Real-time Instant Logs WebSocket.",
            "graphql": "GraphQL firewallEventsAdaptive (analytics; may be sampled/delayed).",
            "hybrid": "Instant Logs primary with GraphQL fill for missing Ray IDs.",
            "none": "No event source available.",
        }.get(source, source)

        by_ray: dict[str, list[FirewallEvent]] = defaultdict(list)
        for ev in events:
            if ev.ray_id:
                by_ray[ev.ray_id].append(ev)

        evidence: list[Evidence] = []
        for result in results:
            ev = self._reconcile_one(result, by_ray, events)
            ev.evidence_source = source
            evidence.append(ev)
        return evidence

    @staticmethod
    def _merge_events(
        primary: list[FirewallEvent], extra: list[FirewallEvent],
    ) -> list[FirewallEvent]:
        seen: set[str] = set()
        out: list[FirewallEvent] = []
        for ev in primary + extra:
            key = f"{ev.ray_id}:{ev.rule_id}:{ev.action}"
            if key in seen:
                continue
            seen.add(key)
            out.append(ev)
        return out

    @staticmethod
    def _rays_for_result(result: TestResult) -> list[str]:
        rays: list[str] = []
        if result.preflight_verdict is not None:
            return rays
        for o in result.outcomes:
            for r in o.payload.metadata.get("rays", []):
                rays.append(_strip_ray_suffix(r))
            if o.cf_ray_id:
                rays.append(_strip_ray_suffix(o.cf_ray_id))
        return rays

    def _collect_expected_rays(self, results: list[TestResult]) -> set[str]:
        rays: set[str] = set()
        for result in results:
            if _norm_action(result.expected_action) == "skip":
                continue
            rays.update(self._rays_for_result(result))
        return rays

    def _fetch_events_graphql(
        self, window_start, window_end, expected_rays: set[str] | None = None,
    ) -> list[FirewallEvent]:
        opts = self.config.options
        delay = int(opts.get("event_poll_delay", 30))
        retries = int(opts.get("event_poll_retries", 6))
        interval = int(opts.get("event_poll_interval", 10))

        since = (window_start - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = (window_end + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.debug("Event query window: %s → %s", since, until)

        expected_rays = expected_rays or set()

        if delay:
            log.info("Waiting %ss for events to propagate…", delay)
            time.sleep(delay)

        events: list[FirewallEvent] = []
        seen_rays: set[str] = set()
        # Prefer primary target host filter to avoid drowning rays on busy zones.
        host = None
        try:
            host = self.config.primary_target().hostname
        except Exception:
            host = None

        for attempt in range(1, retries + 1):
            try:
                fetched = self.client.get_firewall_events(since, until, host=host)
            except Exception as exc:
                log.warning("Event fetch attempt %s failed: %s", attempt, exc)
                fetched = None

            if fetched is not None:
                events = fetched
                seen_rays = {ev.ray_id for ev in events if ev.ray_id}

            if expected_rays:
                missing = expected_rays - seen_rays
                if not missing:
                    log.info(
                        "All %s expected Ray ID(s) matched after attempt %s/%s.",
                        len(expected_rays), attempt, retries,
                    )
                    break
                log.info(
                    "Attempt %s/%s: %s/%s expected Ray ID(s) matched so far, "
                    "%s still missing.",
                    attempt, retries,
                    len(expected_rays) - len(missing), len(expected_rays),
                    len(missing),
                )
            elif events:
                break

            if attempt < retries:
                log.info("Retrying in %ss (%s/%s)…", interval, attempt, retries)
                time.sleep(interval)

        if expected_rays:
            still_missing = expected_rays - seen_rays
            if still_missing:
                log.warning(
                    "Gave up after %s attempt(s); %s of %s expected Ray ID(s) "
                    "never appeared: %s",
                    retries, len(still_missing), len(expected_rays),
                    ", ".join(sorted(still_missing)[:10]),
                )

        log.info("Fetched %s firewall events for the window.", len(events))
        return events

    def _reconcile_one(
        self,
        result: TestResult,
        by_ray: dict[str, list[FirewallEvent]],
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
            scope=getattr(rule, "scope", "zone"),
            _outcomes=result.outcomes,
        )

        if result.preflight_verdict is not None:
            base.verdict = result.preflight_verdict
            base.details = result.preflight_reason
            base.match_method = "preflight"
            return base

        rays = list(dict.fromkeys(self._rays_for_result(result)))
        base.cf_ray_ids = rays

        adapter = get_adapter(rule.adapter_class) if rule.adapter_class else None
        if adapter is not None:
            verdict, details = adapter.interpret(result, by_ray)
            if verdict is not None:
                base.verdict = verdict
                base.details = details
                base.match_method = "status"
                # For managed rulesets, any firewallManaged event on our rays
                # counts as security-event verification (child rule ids differ
                # from the parent execute rule id).
                prefer = rule.rule_id
                if rule.phase == "managed" or rule.rule_type.startswith("managed_"):
                    prefer = None
                    for r in rays:
                        for ev in by_ray.get(r, []):
                            src = (ev.source or "").lower()
                            if "managed" in src or _norm_action(ev.action) in {
                                "block", "challenge",
                            }:
                                base.security_event_verified = True
                                base.match_method = "ray_id"
                                break
                self._attach_events(base, rays, by_ray, prefer_rule_id=prefer)
                if base.security_event_verified and base.match_method == "status":
                    base.match_method = "ray_id"
                if not base.action_taken:
                    statuses = [
                        o.status_code for o in result.outcomes if o.status_code
                    ]
                    if statuses:
                        base.action_taken = (
                            f"HTTP {', '.join(str(s) for s in statuses)} "
                            f"(status-based)"
                        )
                return base

        matched_events: list[FirewallEvent] = []
        for r in rays:
            matched_events.extend(by_ray.get(r, []))

        # Prefer events that cite this exact rule id.
        rule_matched = [ev for ev in matched_events if ev.rule_id == rule.rule_id]
        use_events = rule_matched or matched_events

        if use_events:
            actions = {_norm_action(ev.action) for ev in use_events}
            base.matched_event_ids = [
                ev.ray_id for ev in use_events if ev.ray_id
            ]
            base.timestamps = [
                ev.datetime for ev in use_events if ev.datetime
            ]
            base.action_taken = ", ".join(sorted(a for a in actions if a))
            base.match_method = "rule_id" if rule_matched else "ray_id"
            base.security_event_verified = True

            expected = base.expected_action
            if rule_matched:
                # Exact rule fired — PASS if action compatible, else FAIL.
                if not expected or expected in actions or expected == "log" and "log" in actions:
                    base.verdict = Verdict.PASS
                    base.details = (
                        f"Security event verified: rule id {rule.rule_id} fired "
                        f"on {len(rule_matched)} event(s); action(s) "
                        f"'{base.action_taken}'."
                    )
                else:
                    base.verdict = Verdict.FAIL
                    base.details = (
                        f"Rule id {rule.rule_id} fired but action "
                        f"'{base.action_taken}' != expected '{expected}'."
                    )
                return base

            if expected in actions:
                base.verdict = Verdict.PASS
                base.details = (
                    f"Ray-ID matched {len(use_events)} event(s); "
                    f"observed action '{base.action_taken}' "
                    f"matches expected '{expected}'. "
                    f"(Event rule ids differed from {rule.rule_id} — another "
                    f"rule may have acted first.)"
                )
            else:
                base.verdict = Verdict.FAIL
                base.details = (
                    f"Ray-ID matched {len(use_events)} event(s), "
                    f"but observed action '{base.action_taken}' does not match "
                    f"expected '{expected}'."
                )
            return base

        if base.expected_action == "skip":
            base.verdict = Verdict.PASS
            base.details = (
                "Expected a skip and no block/challenge event was recorded for "
                "the test requests, consistent with traffic being allowed through. "
                "Confirm via Security Events if strict proof is needed."
            )
            base.match_method = "fallback"
            return base

        if base.expected_action == "log":
            base.verdict = Verdict.FAIL
            base.details = (
                f"Expected log action for rule {rule.rule_id} but no matching "
                f"security event was found for Ray IDs: "
                f"{', '.join(rays) if rays else '(none)'}."
            )
            base.match_method = "ray_id"
            return base

        base.verdict = Verdict.FAIL
        base.details = (
            "No firewall/security event matched the test Ray-ID(s) within the "
            "window. The rule may not have fired, or events had not propagated. "
            f"Ray IDs probed: {', '.join(rays) if rays else '(none captured)'}."
        )
        base.match_method = "ray_id"
        return base

    def _attach_events(
        self, evidence: Evidence, rays: list[str],
        by_ray: dict[str, list[FirewallEvent]],
        prefer_rule_id: str | None = None,
    ) -> None:
        matched: list[FirewallEvent] = []
        for r in rays:
            matched.extend(by_ray.get(r, []))
        if prefer_rule_id:
            preferred = [ev for ev in matched if ev.rule_id == prefer_rule_id]
            if preferred:
                matched = preferred
                evidence.security_event_verified = True
        if matched:
            evidence.matched_event_ids = [
                ev.ray_id for ev in matched if ev.ray_id
            ]
            evidence.timestamps = [
                ev.datetime for ev in matched if ev.datetime
            ]
            actions = {_norm_action(ev.action) for ev in matched}
            evidence.action_taken = ", ".join(sorted(a for a in actions if a))
            if any(ev.rule_id == prefer_rule_id for ev in matched):
                evidence.security_event_verified = True
