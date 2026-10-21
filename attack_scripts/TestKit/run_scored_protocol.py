#!/usr/bin/env python3
"""Automated runner for the 6 Scored Demonstration Trials.

Runs SCORED-B0-01 through SCORED-S2-02 sequentially, parses evidence bundles,
and updates SCORED_DEMO_PROTOCOL.md with exact observed counts and outcomes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

TRIALS = [
    ("SCORED-B0-01", "B0", "B0 passive"),
    ("SCORED-B0-02", "B0", "B0 passive"),
    ("SCORED-S1-01", "S1", "S1 scan"),
    ("SCORED-S1-02", "S1", "S1 scan"),
    ("SCORED-S2-01", "S2", "S2 failed logins"),
    ("SCORED-S2-02", "S2", "S2 failed logins"),
]

KIT_DIR = Path(__file__).resolve().parent
PROTOCOL_MD = KIT_DIR / "SCORED_DEMO_PROTOCOL.md"
CONFIG_FILE = KIT_DIR / "config.demo.json"


def run_single_trial(trial_id: str, case: str) -> dict:
    print(f"\n{'='*70}", flush=True)
    print(f"STARTING TRIAL: {trial_id} (Case: {case})", flush=True)
    print(f"{'='*70}\n", flush=True)

    cmd = [
        sys.executable,
        str(KIT_DIR / "run_trial.py"),
        "--config", str(CONFIG_FILE),
        "--case", case,
        "--engine", "hybrid",
        "--trial-id", trial_id,
        "--execute",
    ]

    start_time = time.time()
    proc = subprocess.run(cmd, cwd=str(KIT_DIR))
    elapsed = time.time() - start_time

    summary_file = KIT_DIR / "evidence" / trial_id / "summary.json"
    result = {
        "trial_id": trial_id,
        "case": case,
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 1),
        "eligible_alerts": 0,
        "first_alert_id": "-",
        "outcome": "Invalid",
        "notes": "",
    }

    if proc.returncode != 0:
        result["outcome"] = "Invalid"
        result["notes"] = f"Process exit code {proc.returncode}"
        return result

    if not summary_file.exists():
        result["outcome"] = "Invalid"
        result["notes"] = "Missing summary.json"
        return result

    try:
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

        candidates = summary.get("alerts", {}).get("candidate_alerts_in_scoring_window", [])
        eligible_count = len(candidates)
        first_alert = candidates[0].get("alert_id") if candidates else "-"

        result["eligible_alerts"] = eligible_count
        result["first_alert_id"] = first_alert or "-"

        if case == "B0":
            if eligible_count == 0:
                result["outcome"] = "Correct quiet"
                result["notes"] = "0 alerts in scoring window"
            else:
                result["outcome"] = "False positive"
                result["notes"] = f"{eligible_count} unexpected candidate(s)"
        else:  # S1 or S2
            if eligible_count >= 1:
                result["outcome"] = "Detection"
                result["notes"] = f"{eligible_count} alert(s) in window"
            else:
                result["outcome"] = "Miss"
                result["notes"] = "0 alerts in scoring window"

    except Exception as exc:
        result["outcome"] = "Invalid"
        result["notes"] = f"Parse error: {exc}"

    print(f"\n--> {trial_id} Finished: Outcome = {result['outcome']} (Alerts: {result['eligible_alerts']})", flush=True)
    return result


def update_protocol_sheet(results: list[dict]):
    if not PROTOCOL_MD.exists():
        print(f"Warning: {PROTOCOL_MD} not found, skipping sheet update.", flush=True)
        return

    content = PROTOCOL_MD.read_text(encoding="utf-8")

    # Build markdown table rows
    table_rows = []
    attacks_detected = 0
    total_attacks = 0
    passive_quiet = 0
    total_passive = 0

    for r in results:
        table_rows.append(
            f"| {r['trial_id']} | {r['case']} | {r['eligible_alerts']} | {r['first_alert_id']} | {r['outcome']} | {r['notes']} |"
        )
        if r["case"] in ("S1", "S2"):
            total_attacks += 1
            if r["outcome"] == "Detection":
                attacks_detected += 1
        elif r["case"] == "B0":
            total_passive += 1
            if r["outcome"] == "Correct quiet":
                passive_quiet += 1

    new_table_body = "\n".join(table_rows)

    # Replace results table
    table_pattern = re.compile(
        r"(\| Trial ID \| Case \| Eligible alerts \| First alert ID \| Outcome \| Notes \|\s*\n"
        r"\|---\|---\|---\|---\|---\|---\|\s*\n)"
        r"(?:\| SCORED-.*\n?)+",
        re.MULTILINE
    )

    replacement = r"\g<1>" + new_table_body + "\n"
    content = table_pattern.sub(replacement, content)

    # Replace summary line
    summary_line = (
        f'**Summary line (verified live hardware counts):**\n'
        f'"Of {total_attacks} attack runs, {attacks_detected} produced an alert in-window; '
        f'of {total_passive} passive windows, {passive_quiet} stayed quiet."'
    )

    summary_pattern = re.compile(
        r"\*\*Summary line \(.*?\):\*\*\s*\n\"Of 4 attack runs.*?\.\"",
        re.MULTILINE
    )
    content = summary_pattern.sub(summary_line, content)

    PROTOCOL_MD.write_text(content, encoding="utf-8")
    print(f"\n[UPDATED] {PROTOCOL_MD} successfully written with live results!", flush=True)
    print(summary_line, flush=True)


def main():
    print("=" * 70, flush=True)
    print("SENTRi-X 6-Trial Scored Demonstration Protocol Runner", flush=True)
    print(f"Config: {CONFIG_FILE.name} | Total Trials: {len(TRIALS)}", flush=True)
    print("Estimated duration: ~21-25 minutes total (~3.5 min/trial)", flush=True)
    print("=" * 70, flush=True)

    results = []
    for trial_id, case, label in TRIALS:
        res = run_single_trial(trial_id, case)
        results.append(res)
        # Update sheet incrementally after each trial
        update_protocol_sheet(results)
        # Settle delay between trials
        if trial_id != TRIALS[-1][0]:
            print("\nPausing 5 seconds for flows to settle...", flush=True)
            time.sleep(5)

    print("\n" + "=" * 70, flush=True)
    print("ALL 6 SCORED TRIALS COMPLETED!", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    main()
