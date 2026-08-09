"""Shared helpers for adapters (egress IP, target selection)."""

from __future__ import annotations

import logging
from functools import lru_cache

import requests

from ..discovery import hostname_matches_rule

log = logging.getLogger("waf_validator.testers.helpers")


@lru_cache(maxsize=1)
def detect_egress_ip(timeout: float = 5.0) -> str | None:
    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://1.1.1.1/cdn-cgi/trace",
    ):
        try:
            resp = requests.get(url, timeout=timeout)
            text = (resp.text or "").strip()
            if "cdn-cgi/trace" in url:
                for line in text.splitlines():
                    if line.startswith("ip="):
                        return line.split("=", 1)[1].strip()
            if text and " " not in text and len(text) < 64:
                return text
        except requests.RequestException as exc:
            log.debug("egress detect via %s failed: %s", url, exc)
    return None


def select_matching_target(rule, config):
    """Pick the first configured target whose hostname matches the rule."""
    params = rule.extracted_params or {}
    expr = rule.expression or ""
    for target in config.targets:
        if hostname_matches_rule(target.hostname, params, expr):
            return target
    # Wildcard / catch-all host rules → primary target.
    hosts = params.get("hosts") or params.get("host_wildcards") or []
    if any(h in {"*", "r\"*\"", "r*"} or h.endswith("*") and h.strip("*") == "" for h in hosts):
        return config.primary_target()
    if not params.get("hosts") and not params.get("host") and not params.get("host_contains"):
        return config.primary_target()
    return None


def target_url(target, path_key: str = "default") -> str:
    path = target.test_paths.get(path_key) or target.test_paths.get("default", "/")
    return f"{target.protocol}://{target.hostname}{path}"


def resolve_test_ip_for_list(config, list_name: str) -> str | None:
    """Resolve a configured test IP for a named Cloudflare list.

    Supports:
      test_ips:
        my_whitelist: 1.2.3.4          # by list name
        $my_blocklist: 5.6.7.8
        whitelisted: 1.2.3.4           # legacy role aliases
    """
    if not list_name:
        return None
    name = list_name.lstrip("$")
    ips = config.test_ips or {}
    for key in (name, f"${name}", name.lower()):
        val = ips.get(key)
        if val:
            return str(val)
    # Legacy role aliases → fuzzy match on list name.
    aliases = {
        "whitelisted": ("whitelist", "allow"),
        "blocked": ("blacklist", "block", "deny"),
        "bypass": ("bypass",),
        "rate_bypass": ("ratecontrol", "rate_bypass", "ratelimit_bypass"),
    }
    lname = name.lower()
    for alias, needles in aliases.items():
        if any(n in lname for n in needles):
            val = ips.get(alias)
            if val:
                return str(val)
    return None
