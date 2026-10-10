#!/usr/bin/env python3
"""Automated batch evaluation orchestrator for Chapter 4 documentation.

Runs the complete comparative matrix across:
- Datasets: omni, ton_iot, bot_iot, cic_ids2017
- Engines: rf, cnn, hybrid
- Cases: B0 (Benign), S1 (Port Scan), S2 (Credential Probe)
- Baseline: Snort (B0, S1, S2)

Hot-swaps models via /api/switch, executes trials via run_trial.py, parses
evidence bundles, and produces a master CSV and Markdown tables for Chapter 4.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ALL_DATASETS = ["omni", "ton_iot", "bot_iot", "cic_ids2017"]
ALL_ENGINES = ["rf", "cnn", "hybrid"]
ALL_CASES = ["B0", "S1", "S2"]

CASE_DESCRIPTIONS = {
    "B0": "Baseline observation (verify passive/synthetic variant in trial configuration)",
    "S1": "TCP Port Scan (50 ports)",
    "S2": "Credential Probing (20 attempts)",
}


def observation_outcome(status: str, exit_code: int | str | None) -> str:
    """Execution and alert counts cannot establish ground truth or detection."""
    if status != "completed" or str(exit_code) != "0":
        return "inconclusive"
    return "pending_review"


def http_json(url: str, method: str = "GET", payload: dict | None = None, timeout: float = 10.0) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload else None
    headers = {"Content-Type": "application/json"} if payload else {}
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_for_backend(backend_url: str, max_retries: int = 15) -> dict:
    status_url = f"{backend_url.rstrip('/')}/api/status"
    print(f"Connecting to backend API at {status_url}...", flush=True)
    for attempt in range(1, max_retries + 1):
        try:
            status = http_json(status_url, timeout=5.0)
            print(f"[OK] Backend online: Model={status.get('current_model')}, Mode={status.get('execution_mode')}, LiveSensor={status.get('is_hardware_live')}")
            return status
        except Exception as exc:
            if attempt == max_retries:
                raise RuntimeError(f"Backend unreachable at {status_url}: {exc}") from exc
            print(f"  Attempt {attempt}/{max_retries} failed ({exc}). Retrying in 2s...", flush=True)
            time.sleep(2.0)
    raise RuntimeError("Backend did not respond.")


def switch_backend_model(backend_url: str, dataset: str, mode: str) -> None:
    switch_url = f"{backend_url.rstrip('/')}/api/switch"
    payload = {"model_type": dataset, "dataset": dataset, "mode": mode}
    print(f"[SWITCH] Requesting backend switch -> Model={dataset}, Mode={mode}...", flush=True)
    resp = http_json(switch_url, method="POST", payload=payload, timeout=30.0)
    print(f"  Switch acknowledged: {resp.get('status')}. Verifying state...", flush=True)
    
    # Wait for models and LIME to initialize
    for _ in range(30):
        status = http_json(f"{backend_url.rstrip('/')}/api/status", timeout=5.0)
        if status.get("switching"):
            time.sleep(1.0)
            continue
        if status.get("current_model") == dataset and status.get("execution_mode") == mode:
            print(f"  [READY] Backend active: {dataset} ({mode})", flush=True)
            return
        time.sleep(1.0)
    raise RuntimeError(f"Backend did not complete switch to {dataset}/{mode}")


def check_target_health(target_ip: str, port: int = 8088, timeout: float = 3.0) -> bool:
    health_url = f"http://{target_ip}:{port}/__sentrix_lab__/health"
    try:
        data = http_json(health_url, timeout=timeout)
        return data.get("application") == "sentrix-disposable-lab-target"
    except Exception:
        return False


def build_trial_config(template_path: Path, output_path: Path, dataset: str, target_ip: str, target_mac: str, backend_url: str) -> None:
    with template_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["model_domain"] = dataset
    cfg["target_ip"] = target_ip
    cfg["target_mac"] = target_mac.lower()
    cfg["backend_url"] = backend_url
    cfg["configuration_id"] = f"CH4-{dataset.upper()}"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def run_single_trial(kit_dir: Path, config_file: Path, case: str, engine: str, trial_id: str) -> dict:
    cmd = [
        sys.executable,
        str(kit_dir / "run_trial.py"),
        "--config", str(config_file),
        "--case", case,
        "--engine", engine,
        "--trial-id", trial_id,
        "--execute",
    ]
    print(f"\n[{trial_id}] Executing: Case={case}, Engine={engine}...", flush=True)
    start_wall = time.time()
    proc = subprocess.run(cmd, cwd=str(kit_dir), capture_output=True, text=True)
    elapsed_wall = time.time() - start_wall
    
    evidence_dir = kit_dir / "evidence" / trial_id
    summary_file = evidence_dir / "summary.json"
    
    trial_data = {
        "trial_id": trial_id,
        "case": case,
        "engine": engine,
        "exit_code": proc.returncode,
        "elapsed_seconds": round(elapsed_wall, 1),
        "status": "failed",
        "alerts_count": 0,
        "detection_outcome": "inconclusive",
        "detection_latency": None,
        "review_required": True,
        "error": None,
    }
    
    if summary_file.exists():
        try:
            with summary_file.open("r", encoding="utf-8") as f:
                summary = json.load(f)
            alerts = summary.get("alerts", {})
            candidates = alerts.get("candidate_alerts_in_scoring_window", [])
            # The observer produces candidates, not independently scored results.
            # Even an old summary's outcome/latency must not bypass evidence review.
            outcome = observation_outcome(summary.get("status"), proc.returncode)
            if (summary.get("complete_scoring_window") is not True or
                    alerts.get("observer_issues")):
                outcome = "inconclusive"
            trial_data.update({
                "status": summary.get("status", "unknown"),
                "alerts_count": len(candidates),
                "detection_outcome": outcome,
                "detection_latency": None,
                "error": summary.get("error"),
            })
        except Exception as exc:
            trial_data["error"] = f"Failed to parse summary.json: {exc}"
    else:
        trial_data["error"] = proc.stderr.strip() or f"Process failed with exit code {proc.returncode}"

    print(f"[{trial_id}] Outcome: Status={trial_data['status']}, Alerts={trial_data['alerts_count']}, Outcome={trial_data['detection_outcome']} ({trial_data['elapsed_seconds']}s)", flush=True)
    return trial_data


def observation_cell(rows: list[dict]) -> str:
    if not rows:
        return "Not run"
    return " / ".join(
        f"{r['alerts_count']} candidates ({r['detection_outcome']}; `{r['trial_id']}`)"
        if r['status'] == "completed" else
        f"No valid observation ({r['status']}; `{r['trial_id']}`)"
        for r in rows
    )


def normalize_observations(results: list[dict]) -> list[dict]:
    """Preserve recorded values while withdrawing unreviewed legacy scores."""
    normalized = []
    for original in results:
        row = dict(original)
        previous = row.get("detection_outcome")
        if previous not in ("pending_review", "inconclusive"):
            row.setdefault("legacy_detection_outcome", previous)
        if row.get("detection_latency") not in (None, ""):
            row.setdefault("legacy_detection_latency", row["detection_latency"])
        row.update(detection_outcome=observation_outcome(row.get("status"), row.get("exit_code")),
                   detection_latency=None, review_required=True)
        # Keep any stricter invalidity identified while parsing the raw summary.
        if previous == "inconclusive":
            row["detection_outcome"] = "inconclusive"
        normalized.append(row)
    return normalized


def generate_markdown_report(results: list[dict], output_md: Path, output_csv: Path) -> None:
    results = normalize_observations(results)
    if results:
        keys = list(dict.fromkeys(key for row in results for key in row))
        with output_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys, lineterminator="\n")
            writer.writeheader()
            writer.writerows(results)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Chapter 4 Hardware Trial Observations — Evidence Review Pending",
        f"\n**Report generated:** {generated} (not the trial execution date)\n",
        "Candidate counts are recorded observations, not confirmed detections, false positives, "
        "true negatives, or misses. No detector superiority or accuracy is established by this table. "
        "Detection latency remains unavailable until scope, ground truth, exposure, and timing are reviewed.",
        "\n`pending_review` means the run completed with exit code 0 but is unscored. "
        "`inconclusive` means execution or trial checks require investigation; "
        "exit code 3 can reflect incomplete actions, unexpected responses, or observer issues. "
        "Failed preflight is not a missed attack. An empty alert log is not proof of a clean baseline.",
        "\n## 1. Recorded trials\n",
        "| Trial ID | Domain | Engine | Case | Status | Exit code | Candidate count | Review state | Duration (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        count = r['alerts_count'] if r['status'] == 'completed' else '—'
        lines.append(
            f"| `{r['trial_id']}` | {r.get('dataset', 'snort')} | {r['engine']} | {r['case']} | "
            f"{r['status']} | {r.get('exit_code', '—')} | {count} | {r['detection_outcome']} | {r['elapsed_seconds']} |"
        )
    lines.extend([
        "\n## 2. Snort and OMNI Hybrid observations\n",
        "Counts below are derived from the recorded rows. Repeats are retained separately. "
        "Matched traffic exposure, enabled Snort rules, capture/log continuity, and identical "
        "baseline variants must be verified before comparing detectors.",
        "\n| Case | Workload | Snort | OMNI Hybrid |",
        "|---|---|---|---|",
    ])
    for case in ALL_CASES:
        snort = [r for r in results if r['engine'] == 'snort' and r['case'] == case]
        hybrid = [r for r in results if r.get('dataset') == 'omni' and r['engine'] == 'hybrid' and r['case'] == case]
        lines.append(f"| {case} | {CASE_DESCRIPTIONS[case]} | {observation_cell(snort)} | {observation_cell(hybrid)} |")
    lines.extend([
        "\n## 3. Observations by model domain and engine\n",
        "| Domain | Engine | B0 candidates | S1 candidates | S2 candidates |",
        "|---|---|---|---|---|",
    ])
    groups = sorted({(r.get('dataset', 'unknown'), r['engine']) for r in results if r['engine'] != 'snort'})
    for domain, engine in groups:
        cells = [observation_cell([r for r in results if r.get('dataset') == domain and r['engine'] == engine and r['case'] == case])
                 for case in ALL_CASES]
        lines.append(f"| {domain} | {engine} | " + " | ".join(cells) + " |")
    lines.extend([
        "\n## 4. Evidence required for scoring\n",
        "1. Preserve each trial's summary.json, events.jsonl, frozen configuration, observer logs, "
        "and independent packet capture or target service logs. These bundles are not included in the committed matrix CSV.",
        "2. Complete each trial's review.csv: validity, independently established ground truth, "
        "relevant_alarm, eligible_alert_ids, reference_evidence, reviewer, and timing fields. "
        "Correlate endpoints, ports, flow IDs, scoring windows, and preflight/background traffic.",
        "3. Investigate nonzero exit codes and observer continuity issues. Keep invalid trials "
        "separate from scored negatives and document every repeat rather than silently replacing rows.",
        "4. Verify passive versus synthetic B0 from saved configurations; the existing CSV "
        "does not encode this distinction. Review benign exposure before counting false positives.",
        "5. Verify Snort version, configuration, enabled rule set, capture interface, packet counters, "
        "and log output. Zero logged candidates alone cannot establish a missed attack.",
        "6. Compute latency only for independently eligible alerts with a reviewed attack start "
        "and clock/polling uncertainty. Candidate delay and whole-run duration are not detection latency.",
        "\nPrior detection labels in the CSV are retained only in legacy_detection_outcome for auditability. "
        "They are withdrawn as scored results. Historical narrative claims about cloud traffic, "
        "preflight attribution, and confirmed attack efficacy require the original evidence bundles.",
    ])
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[REPORT] Saved unscored observations to {output_md} and {output_csv}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="http://127.0.0.1:8000", help="SENTRi-X Backend URL")
    parser.add_argument("--target-ip", default="192.168.254.184", help="Defending Target IPv4")
    parser.add_argument("--target-mac", default="b8:27:eb:98:08:95", help="Target MAC address")
    parser.add_argument("--datasets", nargs="+", default=ALL_DATASETS, choices=ALL_DATASETS)
    parser.add_argument("--engines", nargs="+", default=ALL_ENGINES, choices=ALL_ENGINES)
    parser.add_argument("--cases", nargs="+", default=ALL_CASES, choices=ALL_CASES)
    parser.add_argument("--include-snort", action="store_true", default=True, help="Include Snort baseline runs")
    parser.add_argument("--skip-snort", action="store_true", help="Skip Snort baseline runs")
    parser.add_argument("--output-report", default="CHAPTER_4_FULL_RESULTS.md", help="Output Markdown report")
    parser.add_argument("--output-csv", default="chapter_4_matrix_results.csv", help="Output CSV results file")
    parser.add_argument("--report-only", type=Path,
                        help="Regenerate an unscored report from an existing CSV; executes no trials")
    args = parser.parse_args()
    if args.report_only:
        with args.report_only.open(newline="", encoding="utf-8") as f:
            results = list(csv.DictReader(f))
        generate_markdown_report(results, Path(args.output_report), Path(args.output_csv))
        return

    kit_dir = Path(__file__).resolve().parent
    template_config = kit_dir / "lab_config.json"
    temp_config = kit_dir / "_current_batch_config.json"

    print("=" * 60)
    print("  SENTRi-X Chapter 4 Full Evaluation Matrix Orchestrator")
    print("=" * 60)
    print(f"Backend API : {args.backend}")
    print(f"Target IP   : {args.target_ip} (Port 8088)")
    print(f"Target MAC  : {args.target_mac}")
    print(f"Datasets    : {args.datasets}")
    print(f"Engines     : {args.engines}")
    print(f"Cases       : {args.cases}")
    print("=" * 60)

    # 1. Verify target health
    if not check_target_health(args.target_ip, 8088):
        print(f"\n[WARNING] Target service (lab_target.py) is NOT responding on http://{args.target_ip}:8088/__sentrix_lab__/health")
        print("Please start lab_target.py on the defending device before proceeding:")
        print(f"  python3 lab_target.py --bind {args.target_ip} --port 8088 --log target_evidence/service.jsonl\n")
        resp = input("Proceed anyway (preflight will check)? [y/N]: ").strip().lower()
        if resp != "y":
            sys.exit(1)

    # 2. Verify backend status
    wait_for_backend(args.backend)

    results = []
    total_runs = (len(args.datasets) * len(args.engines) * len(args.cases)) + (len(args.cases) if not args.skip_snort else 0)
    current_run = 0

    # Execute SENTRi-X runs
    for dataset in args.datasets:
        for engine in args.engines:
            try:
                switch_backend_model(args.backend, dataset, engine)
            except Exception as exc:
                print(f"[ERROR] Failed to switch backend to {dataset}/{engine}: {exc}")
                continue

            build_trial_config(template_config, temp_config, dataset, args.target_ip, args.target_mac, args.backend)

            for case in args.cases:
                current_run += 1
                trial_id = f"CH4-{dataset.upper()}-{engine.upper()}-{case}-{int(time.time()) % 10000:04d}"
                print(f"\n>>> Progress: [{current_run}/{total_runs}] Running {dataset} | {engine} | {case} <<<")
                res = run_single_trial(kit_dir, temp_config, case, engine, trial_id)
                res["dataset"] = dataset
                results.append(res)
                # Small cool-down to let Pi and backend finish queue flush
                time.sleep(5.0)

    # Execute Snort runs if requested
    if not args.skip_snort:
        build_trial_config(template_config, temp_config, "omni", args.target_ip, args.target_mac, args.backend)
        for case in args.cases:
            current_run += 1
            trial_id = f"CH4-SNORT-{case}-{int(time.time()) % 10000:04d}"
            print(f"\n>>> Progress: [{current_run}/{total_runs}] Running Snort Baseline | {case} <<<")
            res = run_single_trial(kit_dir, temp_config, case, "snort", trial_id)
            res["dataset"] = "snort"
            results.append(res)
            time.sleep(5.0)

    # Clean up temp config
    if temp_config.exists():
        temp_config.unlink()

    # Generate final report
    out_md = kit_dir / args.output_report
    out_csv = kit_dir / args.output_csv
    generate_markdown_report(results, out_md, out_csv)
    print("\n" + "=" * 60)
    print("  CHAPTER 4 FULL EVALUATION MATRIX COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()

