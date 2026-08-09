"""Real-time event collection via Cloudflare Instant Logs (WebSocket).

Primary event source for the correlator. Opens a WebSocket session to
Cloudflare's Instant Logs endpoint *before* payloads are fired, collects
firewall events in real-time as they arrive at the edge, and hands them
to the correlator as FirewallEvent objects — zero propagation delay.

Falls back gracefully: if the session cannot be created (plan limitation,
permission error, network issue), the caller should fall back to GraphQL.

Flow:
  1. POST to /zones/{zone}/logpush/edge/jobs to get a WebSocket URL
  2. Connect to the WSS endpoint in a background thread
  3. Payloads are fired (by TestEngine) while the socket is open
  4. After execution, drain remaining messages with a short grace period
  5. Close the socket and return collected events

Required fields requested from the Instant Logs API:
  RayID, EdgeResponseStatus, EdgeStartTimestamp,
  FirewallMatchesActions, FirewallMatchesRuleIDs, FirewallMatchesSources,
  ClientIP, ClientRequestHost, ClientRequestMethod, ClientRequestURI
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field

from .cf_client import CloudflareClient, FirewallEvent, REST_BASE, APIError

log = logging.getLogger("waf_validator.instant_logs")

_INSTANT_LOGS_FIELDS = ",".join([
    "RayID",
    "ClientIP",
    "ClientRequestHost",
    "ClientRequestMethod",
    "ClientRequestURI",
    "EdgeStartTimestamp",
    "EdgeResponseStatus",
    "FirewallMatchesActions",
    "FirewallMatchesRuleIDs",
    "FirewallMatchesSources",
])


@dataclass
class InstantLogsSession:
    """Manages the lifecycle of an Instant Logs WebSocket session."""

    client: CloudflareClient
    zone_id: str
    _ws: object | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _events: list[FirewallEvent] = field(default_factory=list)
    _raw_messages: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _running: bool = False
    _ws_url: str | None = None
    _session_id: str | None = None

    # ------------------------------------------------------------------ #
    def start(self, host_filter: str | None = None) -> bool:
        """Create the Instant Logs job and open the WebSocket.

        Returns True if the session is active and collecting events.
        Returns False if Instant Logs is unavailable (caller should
        fall back to GraphQL).
        """
        try:
            self._ws_url = self._create_session(host_filter=host_filter)
        except Exception as exc:
            log.warning(
                "Instant Logs session creation failed (%s). "
                "Will fall back to GraphQL for event correlation.", exc,
            )
            return False

        if not self._ws_url:
            log.warning("No WebSocket URL returned. Falling back to GraphQL.")
            return False

        try:
            self._connect_ws()
        except Exception as exc:
            log.warning(
                "WebSocket connection failed (%s). Falling back to GraphQL.", exc,
            )
            return False

        log.info(
            "Instant Logs session active (session_id=%s). "
            "Events will be collected in real-time.", self._session_id,
        )
        return True

    # ------------------------------------------------------------------ #
    def stop(self, drain_seconds: float = 3.0) -> list[FirewallEvent]:
        """Stop collecting, drain remaining messages, return all events.

        Args:
            drain_seconds: How long to keep reading after signalling stop,
                to catch events from the last few payloads.
        """
        if not self._running:
            return list(self._events)

        # Give a grace period for trailing events to arrive.
        log.debug("Draining Instant Logs for %.1fs…", drain_seconds)
        time.sleep(drain_seconds)

        self._running = False

        # Close the WebSocket to unblock the reader thread.
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass

        if self._thread is not None:
            self._thread.join(timeout=5.0)

        with self._lock:
            events = list(self._events)

        log.info(
            "Instant Logs session closed. Collected %d events (%d raw messages).",
            len(events), len(self._raw_messages),
        )
        return events

    # ------------------------------------------------------------------ #
    @property
    def is_active(self) -> bool:
        return self._running

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------ #
    # Internal: session creation
    # ------------------------------------------------------------------ #
    def _create_session(self, host_filter: str | None = None) -> str | None:
        """POST to the logpush/edge/jobs endpoint to get a WSS URL.

        Optionally filter to a ClientRequestHost to reduce noise on busy zones.
        Instant Logs: Business/Enterprise only; one active session per zone.
        """
        url = f"{REST_BASE}/zones/{self.zone_id}/logpush/edge/jobs"
        filter_expr = ""
        if host_filter:
            # Build without an f-string so JSON braces are not misparsed.
            filter_expr = (
                '{"where":{"and":[{"key":"ClientRequestHost","operator":"eq",'
                '"value":"' + host_filter + '"}]}}'
            )
        payload = {
            "fields": _INSTANT_LOGS_FIELDS,
            "sample": 1,  # 1 = 100% of records
            "filter": filter_expr,
            "kind": "instant-logs",
        }
        # Use the client's internal _request for auth/retry/throttle.
        data = self.client._request("POST", url, json=payload)

        result = data.get("result", {})
        self._session_id = result.get("session_id")
        ws_url = result.get("destination_conf")

        if not ws_url:
            log.debug("Instant Logs response: %s", data)
            return None

        log.debug("Instant Logs WSS URL: %s", ws_url)
        return ws_url

    # ------------------------------------------------------------------ #
    # Internal: WebSocket connection
    # ------------------------------------------------------------------ #
    def _connect_ws(self) -> None:
        """Open the WebSocket and start the reader thread."""
        import websockets.sync.client as ws_sync

        self._ws = ws_sync.connect(
            self._ws_url,
            additional_headers={},
            open_timeout=10,
            close_timeout=5,
        )
        self._running = True
        self._thread = threading.Thread(
            target=self._reader_loop,
            name="instant-logs-reader",
            daemon=True,
        )
        self._thread.start()
        # Brief settle so the edge attaches before probes fire.
        time.sleep(1.5)

    # ------------------------------------------------------------------ #
    def _reader_loop(self) -> None:
        """Background thread: read messages from the WebSocket."""
        try:
            for message in self._ws:
                if not self._running:
                    break
                try:
                    raw = json.loads(message) if isinstance(message, str) else json.loads(message.decode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    log.debug("Non-JSON message on Instant Logs: %s", str(message)[:200])
                    continue

                with self._lock:
                    self._raw_messages.append(raw)

                ev = self._parse_event(raw)
                if ev is not None:
                    with self._lock:
                        self._events.append(ev)
                    log.debug(
                        "Instant Logs event: ray=%s action=%s rule=%s",
                        ev.ray_id, ev.action, ev.rule_id,
                    )
        except Exception as exc:
            if self._running:
                log.warning("Instant Logs reader ended: %s", exc)
            else:
                log.debug("Instant Logs reader ended: %s", exc)
        finally:
            self._running = False

    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_event(raw: dict) -> FirewallEvent | None:
        """Convert an Instant Logs JSON message to a FirewallEvent.

        A single log line can contain multiple matched rules in the
        FirewallMatchesActions / FirewallMatchesRuleIDs / FirewallMatchesSources
        arrays. We emit one FirewallEvent per (RayID, action, rule_id) triple
        so the correlator's multi-event-per-ray logic works correctly.
        """
        ray_id = (raw.get("RayID") or "").split("-")[0] or None
        if not ray_id:
            return None

        actions = raw.get("FirewallMatchesActions") or []
        rule_ids = raw.get("FirewallMatchesRuleIDs") or []
        sources = raw.get("FirewallMatchesSources") or []

        # If no firewall matches, still emit the event (useful for
        # negative-control correlation where we expect no action).
        if not actions:
            return FirewallEvent(
                ray_id=ray_id,
                action=None,
                source=None,
                rule_id=None,
                description=None,
                datetime=raw.get("EdgeStartTimestamp"),
                raw=raw,
            )

        # Return the first firewall match; additional matches for the
        # same ray are handled by _expand_multi_match_events() below.
        return FirewallEvent(
            ray_id=ray_id,
            action=actions[0] if actions else None,
            source=sources[0] if sources else None,
            rule_id=rule_ids[0] if rule_ids else None,
            description=None,
            datetime=raw.get("EdgeStartTimestamp"),
            raw=raw,
        )

    @staticmethod
    def expand_events(raw_messages: list[dict]) -> list[FirewallEvent]:
        """Post-process: expand multi-match log lines into individual events.

        Called after the session closes to ensure the correlator sees one
        FirewallEvent per (ray, action, rule) triple — matching the
        structure GraphQL returns (one row per event, not per request).
        """
        events: list[FirewallEvent] = []
        seen: set[str] = set()

        for raw in raw_messages:
            ray_id = (raw.get("RayID") or "").split("-")[0] or None
            if not ray_id:
                continue

            actions = raw.get("FirewallMatchesActions") or []
            rule_ids = raw.get("FirewallMatchesRuleIDs") or []
            sources = raw.get("FirewallMatchesSources") or []

            if not actions:
                # No firewall match — emit one event for negative-control rays.
                dedup = f"{ray_id}:none:none"
                if dedup not in seen:
                    seen.add(dedup)
                    events.append(FirewallEvent(
                        ray_id=ray_id, action=None, source=None,
                        rule_id=None, description=None,
                        datetime=raw.get("EdgeStartTimestamp"), raw=raw,
                    ))
                continue

            # Expand each match into its own event.
            for i, action in enumerate(actions):
                rid = rule_ids[i] if i < len(rule_ids) else None
                src = sources[i] if i < len(sources) else None
                dedup = f"{ray_id}:{action}:{rid}"
                if dedup in seen:
                    continue
                seen.add(dedup)
                events.append(FirewallEvent(
                    ray_id=ray_id,
                    action=action,
                    source=src,
                    rule_id=rid,
                    description=None,
                    datetime=raw.get("EdgeStartTimestamp"),
                    raw=raw,
                ))

        return events
