"""Cloudflare API gateway client.

Two upstream surfaces are used:

* REST (api.cloudflare.com/client/v4) for rule discovery — listing zone and
  account rulesets/entrypoints, expanding executed custom rulesets, and
  reading IP-list contents.
* GraphQL Analytics (api.cloudflare.com/client/v4/graphql) for event
  correlation via the ``firewallEventsAdaptive`` dataset (fallback when
  Instant Logs is unavailable).

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

# Managed ruleset IDs shipped by Cloudflare (not custom account rulesets).
MANAGED_RULESET_IDS = {
    "efb7b8c949ac4650a09736fc376e9aee": "managed_cf_waf",   # Cloudflare Managed
    "4814384a9e5d4991b9815dcfc25d2f1f": "managed_owasp",     # OWASP Core
}


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


@dataclass
class ZoneInfo:
    zone_id: str
    name: str
    account_id: str | None
    plan_legacy_id: str | None = None
    plan_name: str | None = None


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
        self._lists_cache: list[dict] | None = None

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
            if resp.status_code == 404:
                return {"success": False, "result": None, "errors": [{"code": 404}]}
            if resp.status_code >= 400:
                raise APIError(
                    f"{method} {url} -> {resp.status_code}: {resp.text[:400]}"
                )
            try:
                return resp.json()
            except ValueError:
                raise APIError(f"Non-JSON response from {url}: {resp.text[:200]}")

    # ------------------------------------------------------------------ #
    # Auth / zone bootstrap
    # ------------------------------------------------------------------ #
    def verify_token(self) -> bool:
        data = self._request("GET", f"{REST_BASE}/user/tokens/verify")
        status = (data.get("result") or {}).get("status")
        return status == "active"

    def get_zone_info(self) -> ZoneInfo:
        data = self._request("GET", f"{REST_BASE}/zones/{self.zone_id}")
        result = data.get("result") or {}
        account = result.get("account") or {}
        plan = result.get("plan") or {}
        info = ZoneInfo(
            zone_id=result.get("id") or self.zone_id,
            name=result.get("name") or "",
            account_id=account.get("id"),
            plan_legacy_id=plan.get("legacy_id"),
            plan_name=plan.get("name"),
        )
        if info.account_id and not self.account_id:
            self.account_id = info.account_id
            log.info("Resolved account_id=%s from zone lookup.", self.account_id)
        return info

    def ensure_account_id(self) -> str | None:
        if self.account_id:
            return self.account_id
        try:
            return self.get_zone_info().account_id
        except CFError as exc:
            log.warning("Could not resolve account_id from zone: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Rule discovery (REST)
    # ------------------------------------------------------------------ #
    def get_zone_rulesets(self) -> list[RulesetRef]:
        data = self._request("GET", f"{REST_BASE}/zones/{self.zone_id}/rulesets")
        out = []
        for rs in data.get("result", []) or []:
            out.append(
                RulesetRef(
                    ruleset_id=rs.get("id"),
                    phase=rs.get("phase", ""),
                    name=rs.get("name", ""),
                    kind=rs.get("kind", ""),
                )
            )
        return out

    def get_ruleset(self, ruleset_id: str, *, scope: str = "zone") -> dict:
        if scope == "account":
            if not self.account_id:
                raise APIError("account_id is required to read account rulesets.")
            url = f"{REST_BASE}/accounts/{self.account_id}/rulesets/{ruleset_id}"
        else:
            url = f"{REST_BASE}/zones/{self.zone_id}/rulesets/{ruleset_id}"
        data = self._request("GET", url)
        return data.get("result") or {}

    def get_entrypoint_ruleset(self, phase: str, *, scope: str = "zone") -> dict:
        """Return the phase entrypoint ruleset at zone or account scope."""
        if scope == "account":
            if not self.account_id:
                raise APIError("account_id is required to read account entrypoints.")
            url = (
                f"{REST_BASE}/accounts/{self.account_id}/rulesets/phases/"
                f"{phase}/entrypoint"
            )
        else:
            url = (
                f"{REST_BASE}/zones/{self.zone_id}/rulesets/phases/"
                f"{phase}/entrypoint"
            )
        data = self._request("GET", url)
        if not data.get("success", True) and data.get("result") is None:
            return {}
        return data.get("result") or {}

    def get_account_lists(self) -> list[dict]:
        if not self.account_id:
            raise APIError("account_id is required to read IP lists.")
        if self._lists_cache is not None:
            return self._lists_cache
        data = self._request(
            "GET", f"{REST_BASE}/accounts/{self.account_id}/rules/lists"
        )
        self._lists_cache = data.get("result") or []
        return self._lists_cache

    def find_list_by_name(self, name: str) -> dict | None:
        name = name.lstrip("$")
        for lst in self.get_account_lists():
            if lst.get("name") == name:
                return lst
        return None

    def get_ip_list_items(self, list_id: str, *, per_page: int = 100,
                          max_pages: int = 5) -> list[str]:
        if not self.account_id:
            raise APIError("account_id is required to read IP lists.")
        items: list[str] = []
        page = 1
        while page <= max_pages:
            data = self._request(
                "GET",
                f"{REST_BASE}/accounts/{self.account_id}/rules/lists/{list_id}/items",
                params={"per_page": per_page, "page": page},
            )
            batch = data.get("result") or []
            for item in batch:
                if item.get("ip"):
                    items.append(item["ip"])
            if len(batch) < per_page:
                break
            page += 1
        return items

    def list_contains_ip(self, list_name: str, ip: str) -> bool | None:
        """Return True/False if searchable, or None if the list cannot be read."""
        import ipaddress

        try:
            lst = self.find_list_by_name(list_name)
            if not lst:
                return None
            data = self._request(
                "GET",
                f"{REST_BASE}/accounts/{self.account_id}/rules/lists/{lst['id']}/items",
                params={"search": ip},
            )
            needle = ipaddress.ip_address(ip)
            for item in data.get("result") or []:
                cidr = item.get("ip")
                if not cidr:
                    continue
                try:
                    if needle in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        except CFError as exc:
            log.debug("list_contains_ip(%s, %s) failed: %s", list_name, ip, exc)
            return None

    def sample_list_ips(self, list_name: str, limit: int = 3) -> list[str]:
        try:
            lst = self.find_list_by_name(list_name)
            if not lst:
                return []
            return self.get_ip_list_items(lst["id"], per_page=limit, max_pages=1)[:limit]
        except CFError:
            return []

    # ------------------------------------------------------------------ #
    # Event correlation (GraphQL firewallEventsAdaptive)
    # ------------------------------------------------------------------ #
    _EVENTS_QUERY = """
    query WafEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!, $host: String) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            filter: {
              datetime_geq: $since
              datetime_leq: $until
              clientRequestHTTPHost: $host
            }
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

    _EVENTS_QUERY_NO_HOST = """
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
        self, since_iso: str, until_iso: str, limit: int = 1000,
        max_pages: int = 5, host: str | None = None,
    ) -> list[FirewallEvent]:
        """Fetch firewall events in a time window via GraphQL.

        When ``host`` is set, filters to that hostname to avoid drowning test
        rays in busy multi-host zones.
        """
        all_events: list[FirewallEvent] = []
        current_until = until_iso
        seen_rays: set[str] = set()

        for page in range(1, max_pages + 1):
            if host:
                payload = {
                    "query": self._EVENTS_QUERY,
                    "variables": {
                        "zoneTag": self.zone_id,
                        "since": since_iso,
                        "until": current_until,
                        "limit": limit,
                        "host": host,
                    },
                }
            else:
                payload = {
                    "query": self._EVENTS_QUERY_NO_HOST,
                    "variables": {
                        "zoneTag": self.zone_id,
                        "since": since_iso,
                        "until": current_until,
                        "limit": limit,
                    },
                }
            data = self._request("POST", GRAPHQL_URL, json=payload)
            log.debug("GraphQL page %d response keys: %s", page,
                       list(data.keys()) if isinstance(data, dict) else type(data))
            log.debug("GraphQL errors: %s", data.get("errors"))

            if data.get("errors"):
                # Host filter unsupported on some schemas — retry without host once.
                if host and page == 1:
                    log.warning(
                        "GraphQL host filter failed (%s); retrying without host.",
                        data["errors"],
                    )
                    return self.get_firewall_events(
                        since_iso, until_iso, limit=limit, max_pages=max_pages, host=None,
                    )
                raise APIError(f"GraphQL errors: {data['errors']}")

            page_events: list[FirewallEvent] = []
            try:
                zones = data["data"]["viewer"]["zones"]
            except (KeyError, TypeError):
                log.debug("GraphQL data structure unexpected: data=%s", str(data)[:500])
                break

            raw_count = 0
            for zone in zones:
                for ev in zone.get("firewallEventsAdaptive", []) or []:
                    raw_count += 1
                    ray = (ev.get("rayName") or "").split("-")[0] or None
                    dedup_key = f"{ray}:{ev.get('ruleId')}:{ev.get('action')}"
                    if dedup_key in seen_rays:
                        continue
                    seen_rays.add(dedup_key)
                    page_events.append(
                        FirewallEvent(
                            ray_id=ray,
                            action=ev.get("action"),
                            source=ev.get("source"),
                            rule_id=ev.get("ruleId"),
                            description=ev.get("description"),
                            datetime=ev.get("datetime"),
                            raw=ev,
                        )
                    )

            log.debug("GraphQL page %d: %d raw, %d new (after dedup)",
                       page, raw_count, len(page_events))
            all_events.extend(page_events)

            if raw_count < limit:
                break

            oldest_dt = None
            for zone in zones:
                for ev in zone.get("firewallEventsAdaptive", []) or []:
                    dt = ev.get("datetime")
                    if dt and (oldest_dt is None or dt < oldest_dt):
                        oldest_dt = dt
            if oldest_dt and oldest_dt < current_until:
                current_until = oldest_dt
                log.info("Paginating events: page %d fetched %d, cursor → %s",
                         page, raw_count, current_until)
            else:
                break

        log.info("Fetched %d total firewall events across %d page(s).",
                 len(all_events), min(page, max_pages))
        return all_events
