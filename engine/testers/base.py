"""Abstract base adapter and shared data models for the test engine.

Every test adapter implements the BaseTestAdapter contract. The test engine
interacts with adapters only through this interface — never through concrete
types. Adding a new rule type is a matter of dropping a new adapter module in
this package and registering one expression pattern in discovery.py.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Outcome of validating a single rule."""
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    ERROR = "ERROR"


@dataclass
class TestPayload:
    """A single HTTP request the engine will send on an adapter's behalf."""
    method: str                       # GET, POST, PUT, PATCH
    url: str                          # Fully qualified target URL
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    description: str = ""              # What this payload is designed to trigger
    repeat: int = 1                   # Repeat count (rate-limit adapter)
    strip_default_headers: bool = False  # For bot tests: send a bare request
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestOutcome:
    """The result of actually sending one TestPayload over the wire."""
    payload: TestPayload
    status_code: int | None
    cf_ray_id: str | None
    response_headers: dict[str, str] = field(default_factory=dict)
    sent_at: datetime | None = None
    duration_ms: float | None = None
    error: str | None = None


@dataclass
class TestResult:
    """Everything the engine captured while exercising one rule."""
    rule: Any                          # DiscoveredRule (avoids circular import)
    adapter_name: str
    expected_action: str               # block | challenge | skip | log
    outcomes: list[RequestOutcome] = field(default_factory=list)
    # Pre-flight verdict short-circuit: if the adapter cannot execute, the
    # engine sets this to MANUAL/ERROR before any requests are sent.
    preflight_verdict: Verdict | None = None
    preflight_reason: str = ""
    notes: str = ""


class BaseTestAdapter(ABC):
    """Contract implemented by every adapter."""

    name: str = "base"
    description: str = "Abstract base adapter"

    @abstractmethod
    def can_execute(self, rule, config) -> tuple[bool, str]:
        """Pre-flight check. Returns ``(executable, reason_if_not)``."""
        raise NotImplementedError

    @abstractmethod
    def build_payloads(self, rule, config) -> list[TestPayload]:
        """Generate the HTTP request(s) this adapter needs to send."""
        raise NotImplementedError

    @abstractmethod
    def expected_action(self, rule) -> str:
        """What Cloudflare should do: block | challenge | skip | log."""
        raise NotImplementedError

    def interpret(self, result: "TestResult", correlated) -> tuple[Verdict | None, str]:
        """Optional adapter-specific verdict refinement.

        Return ``(None, "")`` to defer to the correlator's generic action-match.
        """
        return None, ""

    def manual_playbook(self, rule, config) -> str:
        """Copy-paste steps when automation is genuinely impossible."""
        action = self.expected_action(rule)
        return (
            f"Rule: {rule.description} ({rule.rule_id})\n"
            f"Scope: {getattr(rule, 'scope', 'zone')} / phase {rule.phase}\n"
            f"Expression: {rule.expression}\n"
            f"Expected action: {action}\n"
            f"1. Send a request that satisfies the expression to a covered hostname.\n"
            f"2. Note the CF-Ray response header.\n"
            f"3. In Security Events or Instant Logs, confirm rule id {rule.rule_id} "
            f"fired with action '{action}'."
        )
