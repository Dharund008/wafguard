"""Rule discovery service + expression parser/classifier.

Discovery fetches the rule inventory across zone *and* account firewall
phases, expands account custom/rate-limit rulesets that are deployed via
``execute``, and normalizes each rule into a ``DiscoveredRule``.

Classification pattern-matches each rule's Cloudflare expression to determine
its semantic type, binds it to a test adapter, and extracts parameters. It is
intentionally generic (any ``$list_name``, any host/method expression) so the
framework works as a cutover standard across projects.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

from .cf_client import MANAGED_RULESET_IDS, CloudflareClient

log = logging.getLogger("waf_validator.discovery")

# Phase -> normalized category label
PHASE_LABELS = {
    "http_request_firewall_custom": "custom",
    "http_ratelimit": "ratelimit",
    "http_request_firewall_managed": "managed",
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
    scope: str = "zone"                # account | zone
    ruleset_id: str | None = None
    deploy_expression: str | None = None  # parent execute filter, if any
    action_parameters: dict = field(default_factory=dict)


# ---------------------------------------------------------------------- #
# Expression classifier
# ---------------------------------------------------------------------- #
def _extract_score(match, _rule):
    return {"score_threshold": int(match.group("n"))}


def _extract_ratelimit(_match, rule):
    rl = rule.get("ratelimit", {}) or {}
    params = {
        "period": rl.get("period"),
        "requests_per_period": rl.get("requests_per_period"),
        "counting_expression": rl.get("counting_expression"),
        "characteristics": rl.get("characteristics"),
        "mitigation_timeout": rl.get("mitigation_timeout"),
    }
    expr = rule.get("expression", "")
    m = re.search(r'http\.request\.method\s+eq\s+"(\w+)"', expr)
    if m:
        params["method"] = m.group(1)
    return params


def _extract_country(match, _rule):
    raw = match.group("list")
    countries = re.findall(r'"([^"]+)"', raw)
    return {"countries": countries}


def _extract_list(match, rule):
    name = match.group("name")
    negated = bool(match.groupdict().get("neg"))
    action = (rule.get("action") or "").lower()
    # Classify role from action + polarity — not from project-specific names.
    if action in {"block", "managed_challenge", "challenge", "js_challenge"}:
        role = "blocklist"
        rule_type = "ip_blocklist"
    elif action in {"skip", "allow", "bypass"}:
        role = "allowlist" if not negated else "blocklist"
        # skip + in $list => allow/bypass list
        skip_params = rule.get("action_parameters") or {}
        products = skip_params.get("products") or []
        phases = skip_params.get("phases") or []
        if "rateLimit" in str(products) or "http_ratelimit" in str(phases):
            rule_type = "rate_bypass"
            role = "rate_bypass"
        else:
            rule_type = "ip_bypass" if "bypass" in (rule.get("description") or "").lower() else "ip_whitelist"
    elif action == "log":
        role = "observe"
        rule_type = "ip_blocklist"  # still IP-list shaped; expect log
    else:
        role = "unknown"
        rule_type = "ip_list"
    return {
        "list_name": name,
        "negated": negated,
        "list_role": role,
        "_rule_type": rule_type,
    }


def _extract_host_method(match, rule):
    expr = rule.get("expression", "") or ""
    host = match.group("host") if "host" in match.groupdict() and match.group("host") else None
    hosts = []
    if host:
        hosts.append(host)
    hosts += re.findall(r'http\.host\s+contains\s+"([^"]+)"', expr)
    hosts += re.findall(r'http\.host\s+eq\s+"([^"]+)"', expr)
    hosts += re.findall(r'http\.host\s+wildcard\s+r?"([^"]+)"', expr)
    methods = re.findall(r'http\.request\.method\s+(?:eq|in)\s+', expr)
    method_vals = re.findall(r'"([A-Z]+)"', expr) if "http.request.method" in expr else []
    # Prefer only method tokens near method clause; fall back to quoted verbs.
    method_set = [m for m in method_vals if m in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    }]
    return {
        "hosts": list(dict.fromkeys(hosts)),
        "host": hosts[0] if hosts else "",
        "methods": method_set or ["POST"],
    }


def _host_family_params(match, rule):
    expr = rule.get("expression", "") or ""
    contains = re.findall(r'http\.host\s+contains\s+"([^"]+)"', expr)
    equals = re.findall(r'http\.host\s+eq\s+"([^"]+)"', expr)
    wildcards = re.findall(r'http\.host\s+wildcard\s+r?"([^"]+)"', expr)
    return {
        "hosts": list(dict.fromkeys(contains + equals + wildcards)),
        "host_contains": contains,
        "host_equals": equals,
        "host_wildcards": wildcards,
    }


_PATTERN_REGISTRY: list[tuple[re.Pattern, str, str, Callable]] = [
    # WAF attack score
    (re.compile(r"cf\.waf\.score\s+le\s+(?P<n>\d+)"),
     "waf_score", "WAFScoreAdapter", _extract_score),
    # Bot management score
    (re.compile(r"cf\.bot_management\.score\s+le\s+(?P<n>\d+)"),
     "bot_score", "BotScoreAdapter", _extract_score),
    # IP lists (any $name) — polarity optional via "not "
    (re.compile(r"(?P<neg>not\s+)?ip\.src\s+in\s+\$(?P<name>[A-Za-z0-9_]+)"),
     "ip_list", "IPListAdapter", _extract_list),
    # Geo block
    (re.compile(
        r"(?:ip\.src\.country|ip\.geoip\.country|ip\.country)\s+in\s+\{(?P<list>[^}]*)\}"
     ),
     "geo_block", "GeoBlockAdapter", _extract_country),
    # Content-type enforcement
    (re.compile(r'content-type|content_type|application/json', re.IGNORECASE),
     "content_type", "ContentTypeAdapter", _host_family_params),
    # Verified good bots
    (re.compile(r"cf\.verified_bot_category|cf\.bot_management\.verified_bot"),
     "verified_bot", "VerifiedBotAdapter", lambda m, r: {}),
    # Host + method block (host constraint with method constraint)
    (re.compile(
        r'http\.host\s+(?:contains|eq|wildcard)\s+r?"?(?P<host>[^"\s]+)"?'
        r'[\s\S]*http\.request\.method'
        r'|http\.request\.method[\s\S]*http\.host\s+(?:contains|eq|wildcard)'
     ),
     "host_method_block", "HostMethodAdapter", _extract_host_method),
    # Host-scoped skip / allow (API traffic style) — host match without score/list
    (re.compile(r"http\.host\s+(?:contains|eq|wildcard)"),
     "host_scoped", "APITrafficAdapter", _host_family_params),
]


def classify(rule: dict) -> tuple[str, str | None, dict]:
    """Return (rule_type, adapter_class, params) for a raw CF rule dict."""
    action = rule.get("action", "")
    ap = rule.get("action_parameters", {}) or {}

    # Managed ruleset execution (do not expand individual managed rules).
    if action == "execute":
        rid = ap.get("id")
        if rid in MANAGED_RULESET_IDS:
            rtype = MANAGED_RULESET_IDS[rid]
            return rtype, "ManagedRulesetAdapter", {"managed_id": rid}
        # Custom ruleset execute is expanded by DiscoveryService; if we still
        # see one here, mark it as a deployment wrapper.
        return "ruleset_deploy", None, {"managed_id": rid}

    expr = rule.get("expression", "") or ""

    # Rate limit rules carry a ratelimit block.
    if "ratelimit" in rule and rule.get("ratelimit"):
        params = _extract_ratelimit(None, rule)
        counting = (params.get("counting_expression") or "")
        if "404" in counting or "response.code" in counting:
            return "rate_limit_404", "RateLimitAdapter", params
        return "rate_limit", "RateLimitAdapter", params

    # Catch-all log of everything — still auto-testable via event evidence.
    if action == "log" and (
        expr.strip() in {"true", "(true)"}
        or re.search(r'http\.host\s+wildcard\s+r?"?\*?"?', expr)
    ):
        if "content-type" not in expr.lower() and "ip.src" not in expr:
            return "log_observe", "LogObserveAdapter", {}

    for pattern, rtype, adapter, extractor in _PATTERN_REGISTRY:
        m = pattern.search(expr)
        if m:
            try:
                params = extractor(m, rule)
            except Exception as exc:
                log.warning("Param extraction failed for %s: %s", rtype, exc)
                params = {}
            # IP-list extractor may override rule_type.
            if rtype == "ip_list" and params.get("_rule_type"):
                rtype = params.pop("_rule_type")
            return rtype, adapter, params

    return "unknown", None, {}


# ---------------------------------------------------------------------- #
# Host / deploy-filter helpers
# ---------------------------------------------------------------------- #
def hostname_matches_rule(hostname: str, params: dict, expression: str = "") -> bool:
    """Return True if ``hostname`` is in scope for host-based rule params."""
    host = hostname.lower()
    for needle in params.get("host_contains") or []:
        if needle.lower() in host:
            return True
    for needle in params.get("host_equals") or []:
        if host == needle.lower():
            return True
    for needle in params.get("hosts") or []:
        n = needle.lower().rstrip("*")
        if n and n in host:
            return True
        if needle == "*" or needle == "r\"*\"":
            return True
    for pat in params.get("host_wildcards") or []:
        # Convert simple CF wildcard (e.g. services-*) to regex.
        rx = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
        if re.match(rx, host, re.IGNORECASE):
            return True
    # Fallback: substring from extracted host field.
    single = (params.get("host") or "").lower()
    if single and single in host:
        return True
    # Expression-level contains checks when params empty.
    for needle in re.findall(r'http\.host\s+contains\s+"([^"]+)"', expression or ""):
        if needle.lower() in host:
            return True
    return False


def deploy_filter_applies(expression: str | None, zone_plan_legacy: str | None) -> bool:
    """Best-effort check that an account deploy filter applies to this zone."""
    if not expression or expression.strip() in {"true", "(true)"}:
        return True
    expr = expression.lower()
    if "cf.zone.plan" in expr and zone_plan_legacy:
        # e.g. (cf.zone.plan eq "ENT") — Cloudflare uses ENT for enterprise.
        plan = zone_plan_legacy.lower()
        aliases = {
            "enterprise": {"ent", "enterprise"},
            "business": {"biz", "business"},
            "pro": {"pro"},
            "free": {"free"},
        }
        wanted = set(re.findall(r'"([^"]+)"', expr))
        wanted_l = {w.lower() for w in wanted}
        for legacy, names in aliases.items():
            if plan == legacy and (wanted_l & names or wanted_l & {legacy}):
                return True
        # If filter mentions plan but we couldn't match, still include with caution.
        if wanted_l:
            log.debug(
                "Deploy filter %r vs plan %r — including rule (uncertain match).",
                expression, zone_plan_legacy,
            )
            return True
    return True


# ---------------------------------------------------------------------- #
# Discovery service
# ---------------------------------------------------------------------- #
class DiscoveryService:
    def __init__(self, client: CloudflareClient):
        self.client = client

    def discover(self) -> list[DiscoveredRule]:
        discovered: list[DiscoveredRule] = []
        zone_info = None
        try:
            zone_info = self.client.get_zone_info()
        except Exception as exc:
            log.warning("Zone info lookup failed: %s", exc)

        plan_legacy = zone_info.plan_legacy_id if zone_info else None
        account_id = self.client.ensure_account_id()

        for phase, label in PHASE_LABELS.items():
            # Zone entrypoint
            discovered.extend(
                self._discover_entrypoint(phase, label, scope="zone",
                                          plan_legacy=plan_legacy)
            )
            # Account entrypoint (+ expand custom executes)
            if account_id:
                discovered.extend(
                    self._discover_entrypoint(phase, label, scope="account",
                                              plan_legacy=plan_legacy)
                )
            else:
                log.warning(
                    "No account_id available; skipping account-level discovery "
                    "for phase %s.", phase,
                )

        log.info(
            "Discovery complete: %d rules (%d account, %d zone).",
            len(discovered),
            sum(1 for r in discovered if r.scope == "account"),
            sum(1 for r in discovered if r.scope == "zone"),
        )
        return discovered

    def _discover_entrypoint(
        self, phase: str, label: str, *, scope: str, plan_legacy: str | None,
    ) -> list[DiscoveredRule]:
        out: list[DiscoveredRule] = []
        try:
            entry = self.client.get_entrypoint_ruleset(phase, scope=scope)
        except Exception as exc:
            log.warning("Could not fetch %s entrypoint for phase %s: %s",
                        scope, phase, exc)
            return out

        if not entry:
            return out

        entry_id = entry.get("id")
        for rule in entry.get("rules", []) or []:
            action = rule.get("action")
            ap = rule.get("action_parameters") or {}
            target_id = ap.get("id")
            deploy_expr = rule.get("expression") or ""

            # Expand custom/rate-limit rulesets deployed via execute.
            # Do NOT expand managed rulesets (test as a single unit).
            if (
                action == "execute"
                and target_id
                and target_id not in MANAGED_RULESET_IDS
                and scope == "account"
            ):
                if not deploy_filter_applies(deploy_expr, plan_legacy):
                    log.info(
                        "Skipping account ruleset %s — deploy filter %r does not "
                        "apply to this zone.", target_id, deploy_expr,
                    )
                    continue
                out.extend(
                    self._expand_ruleset(
                        target_id, label, scope=scope,
                        deploy_expression=deploy_expr,
                    )
                )
                continue

            if action == "execute" and target_id in MANAGED_RULESET_IDS:
                if scope == "account" and not deploy_filter_applies(deploy_expr, plan_legacy):
                    continue

            dr = self._normalize(
                rule, label, scope=scope, ruleset_id=entry_id,
                deploy_expression=deploy_expr if scope == "account" else None,
            )
            out.append(dr)
        return out

    def _expand_ruleset(
        self, ruleset_id: str, phase_label: str, *, scope: str,
        deploy_expression: str | None,
    ) -> list[DiscoveredRule]:
        out: list[DiscoveredRule] = []
        try:
            rs = self.client.get_ruleset(ruleset_id, scope=scope)
        except Exception as exc:
            log.warning("Could not expand ruleset %s: %s", ruleset_id, exc)
            return out

        name = rs.get("name") or ruleset_id
        log.info("Expanded %s ruleset '%s' (%s) → %d rules.",
                 scope, name, ruleset_id, len(rs.get("rules") or []))
        for rule in rs.get("rules") or []:
            # Nested execute of a managed ruleset inside a custom ruleset.
            if rule.get("action") == "execute":
                rid = (rule.get("action_parameters") or {}).get("id")
                if rid in MANAGED_RULESET_IDS:
                    out.append(self._normalize(
                        rule, phase_label, scope=scope, ruleset_id=ruleset_id,
                        deploy_expression=deploy_expression,
                    ))
                    continue
                # Nested custom — expand one more level.
                if rid:
                    out.extend(self._expand_ruleset(
                        rid, phase_label, scope=scope,
                        deploy_expression=deploy_expression,
                    ))
                    continue
            out.append(self._normalize(
                rule, phase_label, scope=scope, ruleset_id=ruleset_id,
                deploy_expression=deploy_expression,
            ))
        return out

    def _normalize(
        self, rule: dict, phase_label: str, *, scope: str,
        ruleset_id: str | None, deploy_expression: str | None,
    ) -> DiscoveredRule:
        rule_type, adapter_class, params = classify(rule)

        from .testers import get_adapter

        testable = False
        manual_reason = None
        if adapter_class:
            # Tentative: adapter matched. Final testable is set by
            # TestEngine.apply_preflight / can_execute against live config.
            adapter = get_adapter(adapter_class)
            testable = adapter is not None
            if not testable:
                manual_reason = f"Adapter {adapter_class} is registered but unavailable."
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
            scope=scope,
            ruleset_id=ruleset_id,
            deploy_expression=deploy_expression,
            action_parameters=rule.get("action_parameters") or {},
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
    account: int = 0
    zone: int = 0

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "enabled": self.enabled,
            "disabled": self.disabled,
            "auto_testable": self.auto_testable,
            "manual": self.manual,
            "unknown": self.unknown,
            "account": self.account,
            "zone": self.zone,
        }


def compute_coverage(rules: list[DiscoveredRule]) -> CoverageStats:
    stats = CoverageStats()
    stats.total = len(rules)
    for r in rules:
        if r.scope == "account":
            stats.account += 1
        else:
            stats.zone += 1
        if r.enabled:
            stats.enabled += 1
        else:
            stats.disabled += 1
        if r.rule_type == "unknown":
            stats.unknown += 1
        if r.enabled and r.testable:
            stats.auto_testable += 1
        elif r.enabled and not r.testable:
            stats.manual += 1
    return stats
