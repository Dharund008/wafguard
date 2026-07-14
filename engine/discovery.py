"""Rule discovery service + expression parser/classifier.

Discovery fetches the rule inventory across the three firewall phases and
normalizes each rule into a ``DiscoveredRule``. The classifier pattern-matches
each rule's Cloudflare expression to determine its semantic type, binds it to a
test adapter (by class name), and extracts parameters (thresholds, periods, IP
list names, managed ruleset IDs).

The pattern registry is priority-ordered: the first matching pattern wins, so
specific patterns precede generic ones.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

from .cf_client import CloudflareClient

log = logging.getLogger("waf_validator.discovery")

# Phase -> normalized category label
PHASE_LABELS = {
    "http_request_firewall_custom": "custom",
    "http_ratelimit": "ratelimit",
    "http_request_firewall_managed": "managed",
}

# Known managed ruleset IDs -> friendly type
MANAGED_RULESET_IDS = {
    "efb7b8c949ac4650a09736fc376e9aee": "managed_cf_waf",   # Cloudflare Managed
    "4814384a9e5d4991b9815dcfc25d2f1f": "managed_owasp",     # OWASP Core
}


@dataclass
class DiscoveredRule:
    rule_id: str
    phase: str                         # normalized: custom | ratelimit | managed
    description: str
    expression: str
    action: str
    enabled: bool
    rule_type: str = "unknown"
    testable: bool = False
    manual_reason: str | None = None
    adapter_class: str | None = None
    extracted_params: dict = field(default_factory=dict)


# ---------------------------------------------------------------------- #
# Expression classifier
# ---------------------------------------------------------------------- #
# Each entry: (compiled_regex, rule_type, adapter_class, param_extractor)
# param_extractor(match, rule_dict) -> dict
def _extract_score(match, _rule):
    return {"score_threshold": int(match.group("n"))}


def _extract_ratelimit(_match, rule):
    rl = rule.get("ratelimit", {}) or {}
    params = {
        "period": rl.get("period"),
        "requests_per_period": rl.get("requests_per_period"),
        "counting_expression": rl.get("counting_expression"),
    }
    # Detect method from the expression if present.
    expr = rule.get("expression", "")
    m = re.search(r'http\.request\.method\s+eq\s+"(\w+)"', expr)
    if m:
        params["method"] = m.group(1)
    return params


def _extract_country(match, _rule):
    raw = match.group("list")
    countries = re.findall(r'"([^"]+)"', raw)
    return {"countries": countries}


def _extract_list_name(match, _rule):
    return {"list_name": match.group("name")}


_PATTERN_REGISTRY: list[tuple[re.Pattern, str, str, Callable]] = [
    # WAF attack score
    (re.compile(r"cf\.waf\.score\s+le\s+(?P<n>\d+)"),
     "waf_score", "WAFScoreAdapter", _extract_score),
    # Bot management score
    (re.compile(r"cf\.bot_management\.score\s+le\s+(?P<n>\d+)"),
     "bot_score", "BotScoreAdapter", _extract_score),
    # IP lists (specific list names first)
    (re.compile(r"ip\.src\s+in\s+\$(?P<name>ap_blacklist)"),
     "ip_blocklist", "IPListAdapter", _extract_list_name),
    (re.compile(r"ip\.src\s+in\s+\$(?P<name>ap_whitelist)"),
     "ip_whitelist", "IPListAdapter", _extract_list_name),
    (re.compile(r"ip\.src\s+in\s+\$(?P<name>ap_bypasslist)"),
     "ip_bypass", "IPListAdapter", _extract_list_name),
    (re.compile(r"ip\.src\s+in\s+\$(?P<name>ap_ratecontrol_bypass)"),
     "rate_bypass", "IPListAdapter", _extract_list_name),
    # Geo block
    (re.compile(r"ip\.src\.country\s+in\s+\{(?P<list>[^}]*)\}"),
     "geo_block", "GeoBlockAdapter", _extract_country),
    # Content-type enforcement (JSON required on API hosts)
    (re.compile(r'content-type.*application/json', re.IGNORECASE | re.DOTALL),
     "content_type", "ContentTypeAdapter", lambda m, r: {}),
    # Host + method block (e.g. block POST to hosts containing "pronto-training")
    (re.compile(r'http\.host\s+contains\s+"(?P<host>[^"]+)"'),
     "host_method_block", "HostMethodAdapter",
     lambda m, r: {"host": m.group("host"),
                    "methods": re.findall(r'"(\w+)"', r.get("expression", ""))}),
    # Verified good bots
    (re.compile(r"cf\.verified_bot_category"),
     "verified_bot", "VerifiedBotAdapter", lambda m, r: {}),
    # API traffic skip bot rule
    (re.compile(r'http\.host\s+wildcard\s+r?"services-\*"'),
     "api_traffic", "APITrafficAdapter", lambda m, r: {}),
]


def classify(rule: dict) -> tuple[str, str | None, dict]:
    """Return (rule_type, adapter_class, params) for a raw CF rule dict.

    Managed rulesets are handled by their execute action_parameters ID before
    the expression registry, since their expression is usually just ``true``.
    """
    action = rule.get("action", "")
    ap = rule.get("action_parameters", {}) or {}

    # Managed ruleset execution
    if action == "execute":
        rid = ap.get("id")
        rtype = MANAGED_RULESET_IDS.get(rid, "managed_unknown")
        return rtype, "ManagedRulesetAdapter", {"managed_id": rid}

    expr = rule.get("expression", "") or ""

    # Rate limit rules carry a ratelimit block; classify by that, using the
    # counting_expression to distinguish 404-style rules.
    if "ratelimit" in rule and rule.get("ratelimit"):
        params = _extract_ratelimit(None, rule)
        counting = (params.get("counting_expression") or "")
        if "404" in counting or "response.code" in counting:
            return "rate_limit_404", "RateLimitAdapter", params
        return "rate_limit", "RateLimitAdapter", params

    for pattern, rtype, adapter, extractor in _PATTERN_REGISTRY:
        m = pattern.search(expr)
        if m:
            try:
                params = extractor(m, rule)
            except Exception as exc:  # defensive: never let extraction crash discovery
                log.warning("Param extraction failed for %s: %s", rtype, exc)
                params = {}
            return rtype, adapter, params

    return "unknown", None, {}


# ---------------------------------------------------------------------- #
# Discovery service
# ---------------------------------------------------------------------- #
class DiscoveryService:
    def __init__(self, client: CloudflareClient):
        self.client = client

    def discover(self) -> list[DiscoveredRule]:
        discovered: list[DiscoveredRule] = []
        for phase, label in PHASE_LABELS.items():
            try:
                entry = self.client.get_entrypoint_ruleset(phase)
            except Exception as exc:
                log.warning("Could not fetch entrypoint for phase %s: %s", phase, exc)
                continue

            for rule in entry.get("rules", []) or []:
                dr = self._normalize(rule, label)
                discovered.append(dr)
        return discovered

    def _normalize(self, rule: dict, phase_label: str) -> DiscoveredRule:
        rule_type, adapter_class, params = classify(rule)

        from .testers import get_adapter  # local import avoids cycle at import time

        testable = False
        manual_reason = None
        if adapter_class:
            adapter = get_adapter(adapter_class)
            # We can't run can_execute() without a config here; discovery only
            # records that an adapter exists. The engine performs the real
            # pre-flight check with config in hand. We mark unknown types as
            # not-testable up front.
            testable = adapter is not None
        else:
            manual_reason = "No adapter matches this rule expression."

        return DiscoveredRule(
            rule_id=rule.get("id") or rule.get("ref") or "",
            phase=phase_label,
            description=rule.get("description", "") or "(no description)",
            expression=rule.get("expression", "") or "",
            action=rule.get("action", ""),
            enabled=rule.get("enabled", False),
            rule_type=rule_type,
            testable=testable,
            manual_reason=manual_reason,
            adapter_class=adapter_class,
            extracted_params=params,
        )


# ---------------------------------------------------------------------- #
# Coverage stats
# ---------------------------------------------------------------------- #
@dataclass
class CoverageStats:
    total: int = 0
    enabled: int = 0
    disabled: int = 0
    auto_testable: int = 0
    manual: int = 0
    unknown: int = 0

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "enabled": self.enabled,
            "disabled": self.disabled,
            "auto_testable": self.auto_testable,
            "manual": self.manual,
            "unknown": self.unknown,
        }


def compute_coverage(rules: list[DiscoveredRule]) -> CoverageStats:
    stats = CoverageStats()
    stats.total = len(rules)
    for r in rules:
        if r.enabled:
            stats.enabled += 1
        else:
            stats.disabled += 1
        if r.rule_type == "unknown":
            stats.unknown += 1
        if r.enabled and r.testable:
            stats.auto_testable += 1
    return stats
