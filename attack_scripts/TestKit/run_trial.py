#!/usr/bin/env python3
"""Run one bounded lab workload; default is an offline dry run."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import signal
import sys
import threading
import time
from pathlib import Path

from sentrix_lab import VERSION
from sentrix_lab.common import (
    ConfigError, JsonlLog, fingerprint, stamp, target_preflight,
    valid_trial_id, validate_config, wait_until, write_json,
)
from sentrix_lab.observers import make_observer
from sentrix_lab.traffic import run_actions

CASE_NAMES = {
    "B0": "benign successful HTTP authentication",
    "S1": "bounded TCP connect port scan",
    "S2": "repeated failed HTTP authentication with fixed dummy credentials",
}


def code_hashes():
    root = Path(__file__).resolve().parent
    files = list((root / "sentrix_lab").glob("*.py")) + [
        root / "run_trial.py", root / "lab_target.py", root / "sample_resources.py"]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}


def parser_for_cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--case", required=True, choices=CASE_NAMES)
    parser.add_argument("--engine", required=True, choices=("rf", "cnn", "hybrid", "snort", "none"))
    parser.add_argument("--trial-id", required=True, type=valid_trial_id)
    parser.add_argument("--output", default="evidence", help="Parent directory; existing Trial IDs are never overwritten.")
    parser.add_argument("--reference-evidence", action="append", default=[],
                        help="PCAP/service-log reference to retain for manual review; repeat as needed.")
    parser.add_argument("--pilot", action="store_true", help="Mark the run as an unscored pilot.")
    parser.add_argument("--smoke", action="store_true", help="Three-second loopback software check, never a physical result.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--execute", action="store_true", help="Actually send the configured lab traffic.")
    group.add_argument("--dry-run", action="store_true", help="Print a plan without network requests (the default).")
    return parser


def execute(args, cfg):
    if args.engine == "none" and not (args.pilot or args.smoke):
        raise ConfigError("--engine none is allowed only for an unscored --pilot or --smoke run.")
    trial_dir = Path(args.output).expanduser().resolve() / args.trial_id
    trial_dir.mkdir(parents=True, exist_ok=False)
    run_kind = "local_smoke" if args.smoke else "pilot" if args.pilot else "physical_trial_candidate"
    context = {"trial_id": args.trial_id, "case": args.case, "engine": args.engine,
               "kit_version": VERSION, "run_kind": run_kind}
    log = JsonlLog(trial_dir / "events.jsonl", context)
    manifest = {
        **context, "case_description": CASE_NAMES[args.case],
        "configuration": cfg, "configuration_sha256": fingerprint(cfg),
        "script_sha256": code_hashes(),
        "protocol_id": cfg["protocol_id"], "configuration_id": cfg["configuration_id"],
        "host": platform.node(), "platform": platform.platform(), "python": sys.version,
        "created": stamp(), "reference_evidence": args.reference_evidence,
        "adviser_protocol_approval": "not inferred by software",
        "capture_path_and_sensor_feature_validation": "requires independent verification",
    }
    write_json(trial_dir / "manifest.json", manifest)
    stop = threading.Event()
    previous_handlers = {}

    def interrupted(signum, _frame):
        log.write("interruption_requested", signal=signum)
        stop.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)
    observer = None
    scoring_start = scoring_end = None
    actions = {"planned": len(cfg["scan_ports"]) if args.case == "S1" else cfg["http_attempts"],
               "attempted": 0, "results": [], "all_actions_attempted": False,
               "expected_http_responses": None}
    status = "preflight_failed"
    failure = None
    complete_window = False
    try:
        target = target_preflight(cfg)
        log.write("target_preflight", **target)
        observer = make_observer(cfg, args.engine, log, target["client_ip"], args.case)
        if observer:
            observer.prime()
            observer.start()
        warmup_start = stamp()
        log.write("warmup_started", warmup_start=warmup_start,
                  duration_seconds=cfg["warmup_seconds"])
        print(f"[{args.trial_id}] Warm-up {cfg['warmup_seconds']:g}s; {run_kind}.", flush=True)
        if not wait_until(warmup_start["monotonic_ns"] / 1e9 + cfg["warmup_seconds"], stop):
            status = "interrupted"
        else:
            scoring_start = stamp()
            start = scoring_start["monotonic_ns"] / 1e9
            deadline = start + cfg["scoring_seconds"]
            log.write("scoring_started", scoring_start=scoring_start,
                      duration_seconds=cfg["scoring_seconds"],
                      first_action_window_seconds=cfg["action_window_seconds"])
            print(f"[{args.trial_id}] Scoring started: {CASE_NAMES[args.case]}.", flush=True)
            actions = run_actions(args.case, cfg, start, stop, log)
            complete_window = wait_until(deadline, stop)
            actual_end = stamp()
            # For a completed window, the planned monotonic boundary governs inclusion.
            if complete_window:
                scoring_end = {
                    "monotonic_ns": scoring_start["monotonic_ns"] + int(cfg["scoring_seconds"] * 1e9),
                    "unix_ns": scoring_start["unix_ns"] + int(cfg["scoring_seconds"] * 1e9),
                    "boundary_kind": "planned_boundary_from_start_clock",
                }
                status = "completed"
            else:
                scoring_end = actual_end
                status = "interrupted"
            log.write("scoring_finished", scoring_end=scoring_end, observed_end=actual_end,
                      complete_window=complete_window)
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
        status = "execution_failed" if scoring_start else "preflight_failed"
        if scoring_start and scoring_end is None:
            scoring_end = stamp()
        log.write("run_error", status=status, error=failure)
    finally:
        if observer:
            observer.close()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        alert_summary = (observer.summary(scoring_start, scoring_end) if observer else {
            "observer": None, "review_required": True, "detection_outcome": None,
            "detection_latency_seconds": None, "observer_issues": [],
            "candidate_alerts_in_scoring_window": []})
        for row in alert_summary.get("candidate_alerts_in_scoring_window", []):
            # This value is intentionally a candidate delay, never a confirmed detector latency.
            row["not_a_scored_latency_until_reviewed"] = True
        wall_drift = None
        if scoring_start and scoring_end:
            now = stamp()
            wall_drift = ((now["unix_ns"] - scoring_start["unix_ns"]) -
                          (now["monotonic_ns"] - scoring_start["monotonic_ns"])) / 1e9
        summary = {
            **context, "status": status, "error": failure,
            "complete_scoring_window": complete_window,
            "scoring_start": scoring_start, "scoring_end": scoring_end,
            "actions": {key: value for key, value in actions.items() if key != "results"},
            "alerts": alert_summary, "observer_wall_clock_drift_seconds": wall_drift,
            "trial_validity": "pending_manual_review",
            "ground_truth": "pending_independent_packet_or_service_evidence_review",
            "model_accuracy": None, "automatic_pass_or_fail": None,
        }
        write_json(trial_dir / "summary.json", summary)
        with (trial_dir / "review.csv").open("x", newline="", encoding="utf-8") as file:
            columns = ["trial_id", "case", "engine", "run_kind", "configuration_id",
                       "validity", "ground_truth", "relevant_alarm", "eligible_alert_ids",
                       "t0_unix_seconds", "first_eligible_alert_observed_unix_seconds",
                       "scoring_duration_seconds", "reference_evidence", "reviewer", "notes"]
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerow({
                "trial_id": args.trial_id, "case": args.case, "engine": args.engine,
                "run_kind": run_kind, "configuration_id": cfg["configuration_id"],
                "t0_unix_seconds": scoring_start["unix_ns"] / 1e9 if scoring_start else "",
                "scoring_duration_seconds": cfg["scoring_seconds"] if complete_window else "",
                "reference_evidence": " | ".join(args.reference_evidence),
                "notes": "Manual scope/exposure/timing review required; blank fields are not zeros.",
            })
        log.write("run_finished", status=status, evidence_directory=str(trial_dir))
        log.close()
    print(f"[{args.trial_id}] {status}; evidence: {trial_dir}", flush=True)
    print("Detection outcome remains blank until independent evidence and alert scope are reviewed.", flush=True)
    if status != "completed":
        return 2
    # B0 is passive baseline: no HTTP responses expected (expected_http_responses is None)
    http_check_ok = (
        args.case == "S1" or args.case == "B0" or
        actions["expected_http_responses"] == actions["planned"]
    )
    if (not actions["all_actions_attempted"] or alert_summary.get("observer_issues") or
            not http_check_ok):
        return 3
    return 0


def main(argv=None):
    parser = parser_for_cli()
    args = parser.parse_args(argv)
    try:
        path = Path(args.config).expanduser().resolve()
        cfg = validate_config(json.loads(path.read_text(encoding="utf-8")), smoke=args.smoke)
        # Relative log paths are relative to the config, not an unpredictable working directory.
        snort_path = Path(cfg["snort_json_file"]).expanduser()
        cfg["snort_json_file"] = str(snort_path if snort_path.is_absolute() else path.parent / snort_path)
        if args.engine == "none" and not (args.pilot or args.smoke):
            raise ConfigError("--engine none requires --pilot or --smoke.")
        if not args.execute:
            print(json.dumps({
                "dry_run": True, "network_requests_sent": 0, "case": args.case,
                "description": CASE_NAMES[args.case], "engine": args.engine,
                "trial_id": args.trial_id, "configuration": cfg,
                "configuration_sha256": fingerprint(cfg),
                "note": "Add --execute to run. No detector selection or settings are changed.",
            }, indent=2))
            return 0
        return execute(args, cfg)
    except (ConfigError, ValueError, OSError) as exc:
        parser.exit(2, f"Setup error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
