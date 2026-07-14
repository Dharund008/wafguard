"""Cloudflare API gateway client.

Two upstream surfaces are used:

* REST (api.cloudflare.com/client/v4) for rule discovery — listing rulesets and
  their rules, and reading IP-list contents.
* GraphQL Analytics (api.cloudflare.com/client/v4/graphql) for event
  correlation via the ``firewallEventsAdaptive`` dataset. This is the same data
  source the dashboard Security Events page uses and supports filtering by
  ``rayName`` (the CF-Ray ID), which is our primary correlation key.

The client handles bearer auth, client-side rate limiting, retry-with-backoff
on transient errors, and a structured exception hierarchy.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

log = logging.getLogger("waf_validator.cf_client")

REST_BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"


# ---------------------------------------------------------------------- #
# Exceptions
# ---------------------------------------------------------------------- #
class CFError(Exception):
    """Base class for all Cloudflare client errors."""


class AuthenticationError(CFError):
    pass


class RateLimitError(CFError):
    pass


class APIError(CFError):
    pass


# ---------------------------------------------------------------------- #
# Lightweight data holders
# ---------------------------------------------------------------------- #
@dataclass
class RulesetRef:
    ruleset_id: str
    phase: str
    name: str
    kind: str


@dataclass
class FirewallEvent:
    ray_id: str | None
    action: str | None
    source: str | None          # e.g. 'firewallCustom', 'ratelimit', 'firewallManaged'
    rule_id: str | None
    description: str | None
    datetime: str | None
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------- #
# Client
# ---------------------------------------------------------------------- #
class CloudflareClient:
    def __init__(
        self,
        api_token: str,
        zone_id: str,
        account_id: str | None = None,
        *,
        max_rps: float = 4.0,
        max_retries: int = 3,
        timeout: int = 15,
    ):
        if not api_token:
            raise AuthenticationError("An API token is required.")
        self.zone_id = zone_id
        self.account_id = account_id
        self._min_interval = 1.0 / max_rps if max_rps > 0 else 0.0
        self._last_call = 0.0
        self._max_retries = max_retries
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------ #
    # Internal request plumbing
    # ------------------------------------------------------------------ #
    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()

    def _request(self, method: str, url: str, **kwargs) -> dict:
        attempt = 0
        while True:
            attempt += 1
            self._throttle()
            try:
                resp = self._session.request(
                    method, url, timeout=self._timeout, **kwargs
                )
            except requests.RequestException as exc:
                if attempt > self._max_retries:
                    raise APIError(f"Network error after {attempt} attempts: {exc}")
                backoff = 2 ** (attempt - 1)
                log.warning("Network error (%s); retrying in %ss", exc, backoff)
                time.sleep(backoff)
                continue

            if resp.status_code == 401 or resp.status_code == 403:
                raise AuthenticationError(
                    f"Auth failed ({resp.status_code}). Check the API token and its permissions."
                )
            if resp.status_code == 429:
                if attempt > self._max_retries:
                    raise RateLimitError("Rate limited by Cloudflare API after retries.")
                backoff = 2 ** (attempt - 1)
                log.warning("429 from CF API; backing off %ss", backoff)
                time.sleep(backoff)
                continue
            if resp.status_code >= 400:
                raise APIError(
                    f"{method} {url} -> {resp.status_code}: {resp.text[:400]}"
                )
            try:
                return resp.json()
            except ValueError:
                raise APIError(f"Non-JSON response from {url}: {resp.text[:200]}")

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    def verify_token(self) -> bool:
        data = self._request("GET", f"{REST_BASE}/user/tokens/verify")
        status = (data.get("result") or {}).get("status")
        return status == "active"

    # ------------------------------------------------------------------ #
    # Rule discovery (REST)
    # ------------------------------------------------------------------ #
    def get_zone_rulesets(self) -> list[RulesetRef]:
        data = self._request("GET", f"{REST_BASE}/zones/{self.zone_id}/rulesets")
        out = []
        for rs in data.get("result", []):
            out.append(
                RulesetRef(
                    ruleset_id=rs.get("id"),
                    phase=rs.get("phase", ""),
                    name=rs.get("name", ""),
                    kind=rs.get("kind", ""),
                )
            )
        return out

    def get_ruleset(self, ruleset_id: str) -> dict:
        data = self._request(
            "GET", f"{REST_BASE}/zones/{self.zone_id}/rulesets/{ruleset_id}"
        )
        return data.get("result", {})

    def get_entrypoint_ruleset(self, phase: str) -> dict:
        """Return the zone entrypoint ruleset for a phase (its rules array is
        what the dashboard shows for that phase)."""
        data = self._request(
            "GET",
            f"{REST_BASE}/zones/{self.zone_id}/rulesets/phases/{phase}/entrypoint",
        )
        return data.get("result", {})

    def get_ip_list_items(self, list_id: str) -> list[str]:
        if not self.account_id:
            raise APIError("account_id is required to read IP lists.")
        data = self._request(
            "GET",
            f"{REST_BASE}/accounts/{self.account_id}/rules/lists/{list_id}/items",
        )
        return [item.get("ip") for item in data.get("result", []) if item.get("ip")]

    # ------------------------------------------------------------------ #
    # Event correlation (GraphQL firewallEventsAdaptive)
    # ------------------------------------------------------------------ #
    _EVENTS_QUERY = """
    query WafEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            filter: {datetime_geq: $since, datetime_leq: $until}
            limit: $limit
            orderBy: [datetime_DESC]
          ) {
            action
            source
            ruleId
            rayName
            datetime
            clientIP
            clientRequestHTTPHost
            clientRequestPath
            description
          }
        }
      }
    }
    """

    def get_firewall_events(
        self, since_iso: str, until_iso: str, limit: int = 1000
    ) -> list[FirewallEvent]:
        """Fetch firewall events in a time window via GraphQL.

        Correlation by Ray ID is done client-side against ``rayName`` because
        the adaptive dataset does not always expose a rayName filter argument;
        pulling the window and matching locally is robust across API versions.
        """
        payload = {
            "query": self._EVENTS_QUERY,
            "variables": {
                "zoneTag": self.zone_id,
                "since": since_iso,
                "until": until_iso,
                "limit": limit,
            },
        }
        data = self._request("POST", GRAPHQL_URL, json=payload)
        log.debug("GraphQL response keys: %s", list(data.keys()) if isinstance(data, dict) else type(data))
        log.debug("GraphQL errors: %s", data.get("errors"))

        if data.get("errors"):
            raise APIError(f"GraphQL errors: {data['errors']}")

        events: list[FirewallEvent] = []
        try:
            zones = data["data"]["viewer"]["zones"]
        except (KeyError, TypeError):
            log.debug("GraphQL data structure unexpected: data=%s", str(data)[:500])
            return events

        log.debug("GraphQL returned %d zone(s), events in first: %d",
                   len(zones),
                   len(zones[0].get("firewallEventsAdaptive", []) or []) if zones else 0)

        for zone in zones:
            for ev in zone.get("firewallEventsAdaptive", []) or []:
                events.append(
                    FirewallEvent(
                        ray_id=(ev.get("rayName") or "").split("-")[0] or None,
                        action=ev.get("action"),
                        source=ev.get("source"),
                        rule_id=ev.get("ruleId"),
                        description=ev.get("description"),
                        datetime=ev.get("datetime"),
                        raw=ev,
                    )
                )
        return events
