#!/usr/bin/env python3
"""Cloudflare WAF Validation Framework — CLI entry point.

Orchestrates the 6-stage pipeline:
  bootstrap → discovery → classification → execution → reconciliation → report

Two invocation modes:
  * config-driven:  --config zones/aptechdevlab.yaml
  * ad-hoc:         --hostname H --zone-id Z [--api-token T]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
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
    p.add_argument("-a", "--account-id", help="Cloudflare account ID (for IP-list reads).")
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
    print(f"{'STATE':<9} {'PHASE':<10} {'TYPE':<18} {'ADAPTER':<22} DESCRIPTION")
    print("-" * 96)
    for r in rules:
        if "all" not in phase_filter and r.phase not in phase_filter:
            continue
        state = "enabled" if r.enabled else "disabled"
        adapter = r.adapter_class or "(manual)"
        print(f"{state:<9} {r.phase:<10} {r.rule_type:<18} {adapter:<22} {r.description}")
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

    client = CloudflareClient(
        api_token=cfg.api_token,
        zone_id=cfg.zone_id,
        account_id=cfg.account_id,
        max_rps=4.0,
        max_retries=int(cfg.options.get("event_poll_retries", 3)),
        timeout=int(cfg.options.get("request_timeout", 10)) + 5,
    )

    api_status = "connected"
    try:
        if not client.verify_token():
            log.error("API token is not active. Check its status in the Cloudflare dashboard.")
            return 3
        log.info("API token verified.")
    except AuthenticationError as exc:
        log.error("Authentication failed: %s", exc)
        return 3
    except CFError as exc:
        log.warning("Token verify call failed (%s); continuing, but discovery may fail.", exc)
        api_status = "unverified"

    # ---- Stage 2+3: discovery + classification --------------------- #
    log.info("Discovering rules for zone %s…", cfg.zone_id)
    try:
        rules = DiscoveryService(client).discover()
    except CFError as exc:
        log.error("Discovery failed: %s", exc)
        return 4

    if not rules:
        log.error("No rules discovered. Check zone ID and token permissions.")
        return 4

    log.info("Discovered %s rules.", len(rules))
    coverage = compute_coverage(rules)

    if "all" not in args.phase:
        rules_scoped = [r for r in rules if r.phase in args.phase]
    else:
        rules_scoped = rules

    if args.dry_run:
        _print_plan(rules, args.phase)
        log.info("Dry run complete — no requests sent.")
        return 0

    # ---- Stage 4: execution ---------------------------------------- #
    # Open an Instant Logs WebSocket session BEFORE firing payloads.
    # Events stream in real-time — zero propagation delay.
    # If Instant Logs is unavailable, we fall back to GraphQL after execution.
    instant_logs_events = None
    il_session = None

    try:
        from engine.instant_logs import InstantLogsSession
        il_session = InstantLogsSession(client=client, zone_id=cfg.zone_id)
        il_active = il_session.start()
    except ImportError:
        log.info("websockets library not installed; using GraphQL fallback.")
        il_active = False
    except Exception as exc:
        log.warning("Instant Logs setup failed (%s); using GraphQL fallback.", exc)
        il_active = False

    if il_active:
        log.info("Instant Logs active — events will be captured in real-time.")
    else:
        log.info("Using GraphQL Analytics for event correlation (may be slower).")

    log.info("Executing tests (live)…")
    engine = TestEngine(cfg)
    results = engine.run(rules_scoped)

    # Close the Instant Logs session and collect events.
    if il_active and il_session is not None:
        try:
            from engine.instant_logs import InstantLogsSession
            raw_events = il_session.stop(drain_seconds=3.0)
            # Expand multi-match log lines into individual FirewallEvent objects.
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
    log.info("Reconciling results against firewall events…")
    correlator = Correlator(client, cfg)
    evidence = correlator.reconcile(
        results,
        engine.window_start,
        engine.window_end,
        preloaded_events=instant_logs_events,
    )

    # ---- Stage 6: report ------------------------------------------- #
    disabled_rules = [r for r in rules_scoped if not r.enabled]
    os.makedirs(cfg.output_dir, exist_ok=True)
    hostname = cfg.primary_target().hostname
    now = datetime.now(timezone.utc)
    date = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H%M%S")
    stem = cfg.filename_template.format(zone=cfg.zone_name, hostname=hostname, date=date, time=time_str)

    written = []
    if cfg.output_format in ("html", "both"):
        html = render_html(
            zone=cfg.zone_name, hostname=hostname, evidence=evidence,
            coverage=coverage, disabled_rules=disabled_rules, api_status=api_status,
        )
        path = os.path.join(cfg.output_dir, f"{stem}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        written.append(path)
    if cfg.output_format in ("json", "both"):
        js = render_json(
            zone=cfg.zone_name, hostname=hostname, evidence=evidence,
            coverage=coverage, disabled_rules=disabled_rules,
        )
        path = os.path.join(cfg.output_dir, f"{stem}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(js)
        written.append(path)

    # ---- Summary --------------------------------------------------- #
    from engine.testers import Verdict
    counts = {v.value: 0 for v in Verdict}
    for e in evidence:
        counts[e.verdict.value] += 1
    print("\n=== Summary ===")
    print(f"  Passed: {counts['PASS']}   Failed: {counts['FAIL']}   "
          f"Manual: {counts['MANUAL']}   Error: {counts['ERROR']}")
    for path in written:
        print(f"  Report: {path}")

    # Non-zero exit if any hard failures (useful for CI).
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
