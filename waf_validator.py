#!/usr/bin/env python3
"""Cloudflare WAF Validation Framework — CLI entry point.

Orchestrates the 6-stage pipeline:
  bootstrap → discovery → classification → execution → reconciliation → report

Two invocation modes:
  * config-driven:  --config zones/<zone>.yaml
  * ad-hoc:         --hostname H --zone-id Z [--api-token T]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone

from engine import __version__, config as config_mod
from engine.cf_client import (
    AuthenticationError,
    CloudflareClient,
    CFError,
)
from engine.correlator import Correlator
from engine.discovery import DiscoveryService, compute_coverage
from engine.reporter import render_html, render_json
from engine.test_engine import TestEngine


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="waf_validator",
        description="Validate Cloudflare WAF rules and produce an evidence-backed report.",
    )
    p.add_argument("-c", "--config", help="Path to YAML config file (config-driven mode).")
    p.add_argument("-H", "--hostname", help="Target hostname (ad-hoc mode).")
    p.add_argument("-z", "--zone-id", help="Cloudflare zone ID (ad-hoc mode).")
    p.add_argument("-a", "--account-id", help="Cloudflare account ID (auto-resolved from zone if omitted).")
    p.add_argument("-t", "--api-token", help="CF API token (else read from CF_API_TOKEN).")
    p.add_argument("-o", "--output-dir", default="./reports", help="Report output directory.")
    p.add_argument("-f", "--format", default="html", choices=["html", "json", "both"],
                   help="Output format.")
    p.add_argument("-p", "--phase", default=["all"], nargs="+",
                   choices=["all", "custom", "ratelimit", "managed"],
                   help="Scope to one or more phases.")
    p.add_argument("--dry-run", action="store_true",
                   help="Discover and classify only; print the plan, send no requests.")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def _build_config(args) -> config_mod.Config:
    if args.config:
        return config_mod.from_yaml(args.config, api_token_override=args.api_token)
    if args.hostname and args.zone_id:
        return config_mod.from_args(
            hostname=args.hostname,
            zone_id=args.zone_id,
            api_token=args.api_token,
            account_id=args.account_id,
            output_dir=args.output_dir,
            output_format=args.format,
        )
    raise config_mod.ConfigError(
        "Provide --config, or both --hostname and --zone-id for ad-hoc mode."
    )


def _print_plan(rules, phase_filter) -> None:
    print("\n=== Discovery / classification plan ===")
    print(f"{'STATE':<9} {'SCOPE':<8} {'PHASE':<10} {'TYPE':<18} {'ADAPTER':<22} DESCRIPTION")
    print("-" * 110)
    for r in rules:
        if "all" not in phase_filter and r.phase not in phase_filter:
            continue
        state = "enabled" if r.enabled else "disabled"
        adapter = r.adapter_class or "(manual)"
        print(
            f"{state:<9} {r.scope:<8} {r.phase:<10} {r.rule_type:<18} "
            f"{adapter:<22} {r.description}"
        )
    print()


def main(argv=None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger("waf_validator")

    # ---- Stage 1: bootstrap ---------------------------------------- #
    try:
        cfg = _build_config(args)
    except config_mod.ConfigError as exc:
        log.error("Config error: %s", exc)
        return 2

    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.format:
        cfg.output_format = args.format
    if args.account_id and not cfg.account_id:
        cfg.account_id = args.account_id

    client = CloudflareClient(
        api_token=cfg.api_token,
        zone_id=cfg.zone_id,
        account_id=cfg.account_id,
        max_rps=4.0,
        max_retries=int(cfg.options.get("event_poll_retries", 3)),
        timeout=int(cfg.options.get("request_timeout", 10)) + 5,
    )
    cfg._cf_client = client

    api_status = "connected"
    try:
        if not client.verify_token():
            log.error("API token is not active. Check its status in the Cloudflare dashboard.")
            return 3
        log.info("API token verified.")
        info = client.get_zone_info()
        if info.account_id:
            cfg.account_id = info.account_id
        log.info(
            "Zone %s (plan=%s) account=%s",
            info.name or cfg.zone_id,
            info.plan_legacy_id or info.plan_name or "?",
            cfg.account_id or "?",
        )
    except AuthenticationError as exc:
        log.error("Authentication failed: %s", exc)
        return 3
    except CFError as exc:
        log.warning("Token/zone bootstrap failed (%s); continuing.", exc)
        api_status = "unverified"

    # ---- Stage 2+3: discovery + classification --------------------- #
    log.info("Discovering account + zone rules for %s…", cfg.zone_id)
    try:
        rules = DiscoveryService(client).discover()
    except CFError as exc:
        log.error("Discovery failed: %s", exc)
        return 4

    if not rules:
        log.error("No rules discovered. Check zone/account IDs and token permissions.")
        return 4

    log.info("Discovered %s rules.", len(rules))

    if "all" not in args.phase:
        rules_scoped = [r for r in rules if r.phase in args.phase]
    else:
        rules_scoped = rules

    # Preflight against current config so auto_testable == can_execute, not
    # merely "an adapter class exists". Coverage is scoped to this run's
    # phase filter so auto % matches evidence (not the whole zone).
    engine = TestEngine(cfg)
    log.info("Running preflight (can_execute) for coverage…")
    engine.apply_preflight(rules)
    coverage = compute_coverage(rules_scoped)

    if args.dry_run:
        _print_plan(rules, args.phase)
        log.info(
            "Coverage (this run): total=%s enabled=%s auto_testable=%s "
            "account=%s zone=%s unknown=%s",
            coverage.total, coverage.enabled, coverage.auto_testable,
            coverage.account, coverage.zone, coverage.unknown,
        )
        log.info("Dry run complete — no requests sent.")
        return 0

    # ---- Stage 4: execution ---------------------------------------- #
    instant_logs_events = None
    il_session = None
    il_active = False

    host_filter = None
    if cfg.options.get("instant_logs_host_filter", True) and len(cfg.targets) == 1:
        host_filter = cfg.primary_target().hostname

    try:
        from engine.instant_logs import InstantLogsSession
        il_session = InstantLogsSession(client=client, zone_id=cfg.zone_id)
        il_active = il_session.start(host_filter=host_filter)
    except ImportError:
        log.info("websockets library not installed; using GraphQL fallback.")
        il_active = False
    except Exception as exc:
        log.warning("Instant Logs setup failed (%s); using GraphQL fallback.", exc)
        il_active = False

    if il_active:
        log.info("Instant Logs active — events captured in real-time.")
        # Warmup request so we know the stream is delivering before tests.
        try:
            import requests as _req
            warm = cfg.primary_target()
            warm_url = f"{warm.protocol}://{warm.hostname}{warm.test_paths.get('default', '/')}"
            wr = _req.get(
                warm_url,
                timeout=int(cfg.options.get("request_timeout", 10)),
                headers={"User-Agent": cfg.options.get("user_agent", "WAF-Validator/1.0")},
                verify=cfg.options.get("verify_ssl", True),
            )
            log.info(
                "Instant Logs warmup → HTTP %s ray=%s (buffered=%s)",
                wr.status_code,
                (wr.headers.get("cf-ray") or "").split("-")[0] or "?",
                il_session.event_count if il_session else 0,
            )
            time.sleep(1.0)
        except Exception as exc:
            log.warning("Instant Logs warmup failed: %s", exc)
    else:
        log.info("Using GraphQL Analytics for event correlation (may be slower/sampled).")

    log.info("Executing tests (live)…")
    results = engine.run(rules_scoped)
    # Refresh coverage for this run's scope after execution (can_execute may
    # update flags, e.g. IP-list membership).
    coverage = compute_coverage(rules_scoped)

    if il_active and il_session is not None:
        try:
            from engine.instant_logs import InstantLogsSession
            il_session.stop(drain_seconds=float(cfg.options.get("instant_logs_drain", 5.0)))
            instant_logs_events = InstantLogsSession.expand_events(
                il_session._raw_messages
            )
            log.info(
                "Instant Logs: %d raw messages → %d expanded events.",
                len(il_session._raw_messages), len(instant_logs_events),
            )
        except Exception as exc:
            log.warning("Instant Logs drain failed (%s); falling back to GraphQL.", exc)
            instant_logs_events = None

    # ---- Stage 5: reconciliation ----------------------------------- #
    log.info("Reconciling results against firewall/security events…")
    correlator = Correlator(client, cfg)
    # If Instant Logs returned an empty list, treat as "tried but empty" and
    # still allow hybrid/GraphQL fill via preloaded_events=[].
    evidence = correlator.reconcile(
        results,
        engine.window_start,
        engine.window_end,
        preloaded_events=instant_logs_events if il_active else None,
    )
    log.info(
        "Evidence source: %s — %s",
        correlator.evidence_source, correlator.evidence_note,
    )

    # ---- Stage 6: report ------------------------------------------- #
    disabled_rules = [r for r in rules_scoped if not r.enabled]
    os.makedirs(cfg.output_dir, exist_ok=True)
    hostname = cfg.primary_target().hostname
    now = datetime.now(timezone.utc)
    date = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H%M%S")
    stem = cfg.filename_template.format(
        zone=cfg.zone_name, hostname=hostname, date=date, time=time_str,
    )

    written = []
    if cfg.output_format in ("html", "both"):
        html = render_html(
            zone=cfg.zone_name, hostname=hostname, evidence=evidence,
            coverage=coverage, disabled_rules=disabled_rules, api_status=api_status,
            evidence_source=correlator.evidence_source,
            evidence_note=correlator.evidence_note,
        )
        path = os.path.join(cfg.output_dir, f"{stem}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        written.append(path)
    if cfg.output_format in ("json", "both"):
        js = render_json(
            zone=cfg.zone_name, hostname=hostname, evidence=evidence,
            coverage=coverage, disabled_rules=disabled_rules,
            evidence_source=correlator.evidence_source,
            evidence_note=correlator.evidence_note,
        )
        path = os.path.join(cfg.output_dir, f"{stem}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(js)
        written.append(path)

    # ---- Summary --------------------------------------------------- #
    from engine.testers import Verdict
    counts = {v.value: 0 for v in Verdict}
    verified = 0
    for e in evidence:
        counts[e.verdict.value] += 1
        if e.security_event_verified:
            verified += 1
    print("\n=== Summary ===")
    print(f"  Passed: {counts['PASS']}   Failed: {counts['FAIL']}   "
          f"Manual: {counts['MANUAL']}   Error: {counts['ERROR']}")
    print(f"  Security-event verified: {verified}/{len(evidence)}")
    print(f"  Evidence source: {correlator.evidence_source}")
    for path in written:
        print(f"  Report: {path}")

    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
