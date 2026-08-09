"""Configuration loading and validation.

One config object drives the whole pipeline. It is built either from a YAML
file (config-driven mode) or from CLI arguments (ad-hoc mode). All runtime
options have sensible defaults; only the zone/account identifiers and at least
one target hostname are required.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml


class ConfigError(Exception):
    """Raised when the configuration is missing required fields."""


_DEFAULT_OPTIONS = {
    "request_timeout": 10,
    "rate_limit_buffer": 5,
    "rate_limit_max_auto": 600,
    # GraphQL analytics can take 2-5 min to propagate.
    "event_poll_delay": 30,
    "event_poll_retries": 6,
    "event_poll_interval": 10,
    "hybrid_graphql_fill": True,
    "instant_logs_host_filter": False,
    "verify_ssl": True,
    "user_agent": "WAF-Validator/1.0",
    "socks_proxy": None,
    # Pace probes so Instant Logs can deliver one line per request.
    "inter_request_delay": 0.25,
}


@dataclass
class Target:
    hostname: str
    protocol: str = "https"
    test_paths: dict[str, str] = field(default_factory=lambda: {"default": "/"})


@dataclass
class Config:
    zone_name: str
    zone_id: str
    account_id: str | None
    api_token: str
    targets: list[Target]
    test_ips: dict[str, str | None] = field(default_factory=dict)
    options: dict = field(default_factory=lambda: dict(_DEFAULT_OPTIONS))
    output_format: str = "html"
    output_dir: str = "./reports"
    filename_template: str = "waf_validation_{zone}_{hostname}_{date}_{time}"
    # Attached at runtime by the CLI so adapters can query CF APIs (lists, etc.).
    _cf_client: object | None = field(default=None, repr=False, compare=False)

    # ------------------------------------------------------------------ #
    def primary_target(self) -> Target:
        if not self.targets:
            raise ConfigError("No targets configured.")
        return self.targets[0]

    def validate(self) -> None:
        if not self.zone_id:
            raise ConfigError("zone.zone_id is required.")
        if not self.api_token:
            raise ConfigError(
                "API token is required. Set it via the token env var "
                "(default CF_API_TOKEN) or --api-token."
            )
        if not self.targets:
            raise ConfigError("At least one target hostname is required.")


# ---------------------------------------------------------------------- #
# Builders
# ---------------------------------------------------------------------- #
def _resolve_token(token_env: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    return os.environ.get(token_env or "CF_API_TOKEN", "")


def from_yaml(path: str, api_token_override: str | None = None) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    zone = raw.get("zone", {})
    api = raw.get("api", {})
    token_env = api.get("token_env", "CF_API_TOKEN")
    token = _resolve_token(token_env, api_token_override)

    targets = []
    for t in raw.get("targets", []):
        targets.append(
            Target(
                hostname=t["hostname"],
                protocol=t.get("protocol", "https"),
                test_paths=t.get("test_paths", {"default": "/"}),
            )
        )

    options = dict(_DEFAULT_OPTIONS)
    options.update(raw.get("options", {}) or {})

    output = raw.get("output", {})

    cfg = Config(
        zone_name=zone.get("name", zone.get("zone_id", "unknown")),
        zone_id=zone.get("zone_id", ""),
        account_id=zone.get("account_id"),
        api_token=token,
        targets=targets,
        test_ips=raw.get("test_ips", {}) or {},
        options=options,
        output_format=output.get("format", "html"),
        output_dir=output.get("directory", "./reports"),
        filename_template=output.get(
            "filename_template", "waf_validation_{zone}_{hostname}_{date}_{time}"
        ),
    )
    cfg.validate()
    return cfg


def from_args(
    hostname: str,
    zone_id: str,
    api_token: str | None,
    account_id: str | None = None,
    zone_name: str | None = None,
    output_dir: str = "./reports",
    output_format: str = "html",
) -> Config:
    token = api_token or os.environ.get("CF_API_TOKEN", "")
    cfg = Config(
        zone_name=zone_name or hostname,
        zone_id=zone_id,
        account_id=account_id,
        api_token=token,
        targets=[Target(hostname=hostname)],
        test_ips={},
        options=dict(_DEFAULT_OPTIONS),
        output_format=output_format,
        output_dir=output_dir,
    )
    cfg.validate()
    return cfg
