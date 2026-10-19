#!/usr/bin/env python3
"""SENTRi-X live demo matrix.

Runs the SENTRi-X lab test kit as a live, narrated demonstration: for every
dataset x model-mode combination it switches the backend to that model
(via POST /api/switch), runs the kit's B0/S1/S2 cases against the lab
target, and records what the dashboard's threat logs show -- alongside
Snort baseline runs for comparison. It then builds a self-contained HTML
report with charts comparing candidate-alert counts across models and
Snort.

Everything it measures is a *candidate alert in the scoring window*. This
script never scores detections, false positives, or misses: detection
outcome stays blank until the kit's independent evidence review is done,
exactly like the kit itself.

Safety: the script only shells out to the kit's run_trial.py, so all of the
kit's safety bounds apply (private-IP-only targets, bounded action
windows, no catch-up bursts). It refuses to run against a non-RFC1918
target unless the kit's own --smoke path is used.

Usage (from the extracted kit folder, with this file placed beside
run_trial.py):

    # Fast live demo: all 4 datasets x hybrid x B0/S1/S2 + Snort (~30 min)
    python3 demo_matrix.py --config config.example.json --pace fast

    # Full matrix: all datasets x rf/cnn/hybrid x all cases + Snort
    python3 demo_matrix.py --config config.example.json --pace full --modes rf cnn hybrid

    # Print the plan without running anything
    python3 demo_matrix.py --config config.example.json --dry-run

Requires: the kit folder (run_trial.py, sentrix_lab/), the lab target
running (lab_target.py), the SENTRi-X backend reachable, and for --snort
the Snort JSON alert log configured in the trial config.

Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

DATASETS = ["omni", "ton_iot", "bot_iot", "cic_ids2017"]
MODES = ["rf", "cnn", "hybrid"]
CASES = ["B0", "S1", "S2"]
ENGINE_LABEL = {"rf": "Random Forest", "cnn": "CNN", "hybrid": "Hybrid RF+CNN",
                "snort": "Snort", "none": "No observer"}
CASE_LABEL = {
    "B0": "B0 - passive benign baseline (no synthetic traffic)",
    "S1": "S1 - bounded TCP connect scan, 50 ports, banner grab",
    "S2": "S2 - 20 failed HTTP logins (credential probing proxy)",
}

PACINGS = {
    # warmup / scoring / action window / settle after a model switch
    "fast": {"warmup_seconds": 10.0, "scoring_seconds": 60.0,
             "action_window_seconds": 30.0, "settle_seconds": 12.0},
    "full": {"warmup_seconds": 60.0, "scoring_seconds": 120.0,
             "action_window_seconds": 30.0, "settle_seconds": 20.0},
}

TRIAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
DISCLAIMER = (
    "Demonstration only. Candidate alerts in the scoring window are shown "
    "exactly as the dashboard recorded them; detection outcome, false-positive "
    "rates, misses, and any model-vs-Snort superiority claim remain unscored "
    "until the kit's independent evidence review is completed."
)


class DemoError(Exception):
    pass


# ---------------------------------------------------------------- backend API

def api_request(backend, method, path, payload=None, timeout=15):
    url = backend.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    api_key = os.environ.get("SENTRIX_ADMIN_KEY") or os.environ.get("SENTRIX_API_KEY") or "sentrix-admin-2026"
    if api_key:
        headers["X-API-Key"] = api_key
    request = urllib.request.Request(
        url, data=data, method=method,
        headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:500]
        raise DemoError(f"{method} {path} -> HTTP {exc.code}: {body}")
    except urllib.error.URLError as exc:
        raise DemoError(f"Cannot reach backend at {url}: {exc.reason}")


def check_backend(backend):
    status = api_request(backend, "GET", "/api/status")
    if status.get("api_version") != 2:
        raise DemoError("Backend is not API version 2.")
    if status.get("data_source") != "live_hardware":
        raise DemoError("Backend is not on the live_hardware data source.")
    if status.get("simulation_active"):
        raise DemoError("Simulation is active; demo requires it off.")
    if not status.get("is_hardware_live"):
        raise DemoError("Hardware is not live (no sensor heartbeat seen).")
    settings = status.get("settings", {})
    threshold = settings.get("alert_threshold")
    if settings.get("active_alerting") is not True or not isinstance(threshold, (int, float)):
        raise DemoError("Backend alerting is not active; check dashboard settings.")
    return status, float(threshold)


def switch_model(backend, dataset, mode, settle_seconds):
    """Switch the live backend to (dataset, mode); verify it took effect."""
    result = api_request(backend, "POST", "/api/switch",
                         {"model_type": dataset, "dataset": dataset, "mode": mode},
                         timeout=120)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        status = api_request(backend, "GET", "/api/status")
        if (status.get("current_model") == dataset
                and status.get("execution_mode") == mode):
            needed = ["rf_online"] if mode == "rf" else (
                ["cnn_online"] if mode == "cnn" else ["rf_online", "cnn_online"])
            if all(status.get(key) is True for key in needed):
                time.sleep(settle_seconds)
                return status
        time.sleep(3)
    raise DemoError(f"Backend did not settle on {dataset}/{mode} within 180s: {result}")


# ------------------------------------------------------------------ planning

def build_plan(datasets, modes, cases, with_snort):
    plan = []
    for dataset in datasets:
        for mode in modes:
            for case in cases:
                plan.append({"dataset": dataset, "mode": mode, "case": case,
                             "engine": mode})
    if with_snort:
        for case in cases:
            plan.append({"dataset": "n/a", "mode": "snort", "case": case,
                         "engine": "snort"})
    return plan


def trial_id_for(stamp, item):
    trial_id = f"DEMO-{stamp}-{item['dataset']}-{item['mode']}-{item['case']}"
    trial_id = trial_id.replace("_", "-")
    if not TRIAL_ID_RE.fullmatch(trial_id):
        raise DemoError(f"Bad trial id: {trial_id}")
    return trial_id


def estimate_minutes(plan, pacing):
    per_trial = (pacing["warmup_seconds"] + pacing["scoring_seconds"]
                 + pacing["settle_seconds"]) / 60.0
    return per_trial * len(plan)


# ------------------------------------------------------------------ running

def run_one(kit_dir, config_path, item, trial_id, report_dir, backend):
    """Run one kit trial; return a result record for the report."""
    trial_dir = report_dir / "evidence" / trial_id
    cmd = [sys.executable, str(kit_dir / "run_trial.py"),
           "--config", str(config_path), "--case", item["case"],
           "--engine", item["engine"], "--trial-id", trial_id,
           "--output", str(report_dir / "evidence"), "--execute"]
    started = datetime.now().isoformat(timespec="seconds")
    proc = subprocess.run(cmd, cwd=str(kit_dir), capture_output=True, text=True,
                          timeout=900)
    record = {"trial_id": trial_id, "dataset": item["dataset"],
              "mode": item["mode"], "case": item["case"],
              "engine": item["engine"], "started": started,
              "returncode": proc.returncode,
              "stdout_tail": proc.stdout[-1500:] if proc.stdout else "",
              "stderr_tail": proc.stderr[-1500:] if proc.stderr else "",
              "status": None, "complete_window": None,
              "planned": None, "attempted": None,
              "candidate_alerts": None, "alert_ids": [],
              "observer_issues": [], "detection_outcome": None,
              "evidence_dir": str(trial_dir) if trial_dir.exists() else None}
    summary_path = trial_dir / "summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            summary = None
        if summary:
            record["status"] = summary.get("status")
            record["complete_window"] = summary.get("complete_scoring_window")
            actions = summary.get("actions", {})
            record["planned"] = actions.get("planned")
            record["attempted"] = actions.get("attempted")
            alerts = summary.get("alerts", {})
            candidates = alerts.get("candidate_alerts_in_scoring_window") or []
            record["candidate_alerts"] = len(candidates)
            record["alert_ids"] = [c.get("id") for c in candidates
                                   if isinstance(c, dict) and c.get("id")]
            record["observer_issues"] = alerts.get("observer_issues") or []
            record["detection_outcome"] = alerts.get("detection_outcome")
    return record


def banner(text):
    line = "=" * 64
    print(f"\n{line}\n{text}\n{line}", flush=True)


# ------------------------------------------------------------------ report

def svg_grouped_bars(title, groups, series, colors):
    """Inline-SVG grouped bar chart. groups: labels; series: {name: [values]}."""
    width, height = 720, 320
    pad_l, pad_r, pad_t, pad_b = 56, 16, 44, 96
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    all_vals = [v for vals in series.values() for v in vals]
    vmax = max(all_vals) if all_vals else 0
    top = vmax * 1.15 if vmax else 1
    n_groups = max(len(groups), 1)
    n_series = max(len(series), 1)
    group_w = plot_w / n_groups
    bar_w = min(46, (group_w * 0.8) / n_series)
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img">',
             f'<text x="{width/2}" y="22" text-anchor="middle" font-size="15" '
             f'font-weight="bold" fill="#111">{html.escape(title)}</text>']
    # gridlines + y labels
    ticks = 5
    for i in range(ticks + 1):
        val = top * i / ticks
        y = pad_t + plot_h - (plot_h * i / ticks)
        parts.append(f'<line x1="{pad_l}" y1="{y}" x2="{width-pad_r}" y2="{y}" '
                     f'stroke="#ddd" stroke-width="1"/>')
        parts.append(f'<text x="{pad_l-8}" y="{y+4}" text-anchor="end" '
                     f'font-size="11" fill="#555">{val:.0f}</text>')
    names = list(series.keys())
    for gi, glabel in enumerate(groups):
        gx = pad_l + gi * group_w
        for si, name in enumerate(names):
            val = series[name][gi]
            bw = bar_w
            bx = gx + (group_w - bw * n_series) / 2 + si * bw
            bh = plot_h * val / top if top else 0
            by = pad_t + plot_h - bh
            color = colors[si % len(colors)]
            parts.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" '
                         f'height="{bh:.1f}" fill="{color}"/>')
            parts.append(f'<text x="{bx+bw/2:.1f}" y="{by-5:.1f}" text-anchor="middle" '
                         f'font-size="11" font-weight="bold" fill="#111">{val}</text>')
        parts.append(f'<text x="{gx+group_w/2:.1f}" y="{height-pad_b+18}" text-anchor="middle" '
                     f'font-size="11" fill="#333">{html.escape(glabel)}</text>')
    # legend
    lx = pad_l
    for si, name in enumerate(names):
        color = colors[si % len(colors)]
        parts.append(f'<rect x="{lx}" y="{height-16}" width="14" height="14" fill="{color}"/>')
        parts.append(f'<text x="{lx+19}" y="{height-4}" font-size="12" fill="#333">'
                     f'{html.escape(name)}</text>')
        lx += 19 + len(name) * 7 + 18
    parts.append('</svg>')
    return "\n".join(parts)


def build_report(report_dir, records, meta):
    matrix = {}
    for item in meta["plan"]:
        key = (item["dataset"], item["mode"])
        label = "Snort" if item["engine"] == "snort" else f"{item['dataset']} {item['mode']}"
        if key not in matrix:
            matrix[key] = label
    ordered = sorted(matrix, key=lambda k: (k[0] == "n/a", k[0], k[1]))
    labels = [matrix[k] for k in ordered]
    colors = ["#2f6fed", "#7aa2f7", "#9fd08a", "#e0a458", "#c25e5e", "#8a6fbf",
              "#5bc0be", "#f4a259", "#6d6875", "#b5838d", "#ffb703", "#219ebc",
              "#e76f51"]
    by_case = {}
    for case in meta["cases"]:
        by_case[case] = []
        for key in ordered:
            rec = next((r for r in records
                        if r["case"] == case and (r["dataset"], r["mode"]) == key), None)
            by_case[case].append(rec["candidate_alerts"] if rec and rec["candidate_alerts"] is not None else -1)
    charts = []
    for case in meta["cases"]:
        vals = by_case[case]
        charts.append(svg_grouped_bars(
            f"{case}: candidate alerts in scoring window (unreviewed)",
            labels, {"candidate alerts": [max(v, 0) for v in vals]}, colors))
    rows = []
    for rec in records:
        label = "Snort" if rec["engine"] == "snort" else f"{rec['dataset']} {rec['mode']}"
        issues = "; ".join(rec["observer_issues"]) if rec["observer_issues"] else "-"
        count = rec["candidate_alerts"]
        cell = ("n/a" if count is None else
                f"<b>{count}</b>" if count else "0")
        style = ("background:#fde8e8" if isinstance(count, int) and count > 0
                 else "background:#e6f4ea" if count == 0 else "")
        rows.append(
            f"<tr><td>{html.escape(label)}</td><td>{html.escape(rec['case'])}</td>"
            f"<td>{html.escape(str(rec['status']))}</td>"
            f"<td>{rec['attempted']}/{rec['planned']}</td>"
            f'<td style="{style}">{cell}</td>'
            f"<td>{html.escape(issues)}</td>"
            f"<td><code>{html.escape(rec['trial_id'])}</code></td></tr>")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SENTRi-X live demo matrix - {now}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #111; }}
.disclaimer {{ background: #fff3cd; border: 1px solid #d9a821; padding: 12px 16px;
  border-radius: 6px; margin: 16px 0; }}
table {{ border-collapse: collapse; margin: 16px 0; width: 100%; }}
th, td {{ border: 1px solid #bbb; padding: 6px 10px; text-align: left; font-size: 13px; }}
th {{ background: #eee; }}
.chart {{ margin: 24px 0; max-width: 760px; }}
.meta li {{ margin: 4px 0; }}
</style></head><body>
<h1>SENTRi-X live demo matrix</h1>
<div class="disclaimer"><b>Demonstration only.</b> {html.escape(DISCLAIMER)}</div>
<ul class="meta">
<li><b>Run:</b> {html.escape(now)}</li>
<li><b>Backend:</b> <code>{html.escape(meta['backend'])}</code> (threshold {meta['threshold']})</li>
<li><b>Datasets:</b> {html.escape(', '.join(meta['datasets']))}</li>
<li><b>Model modes:</b> {html.escape(', '.join(meta['modes']))}</li>
<li><b>Cases:</b> {html.escape(', '.join(meta['cases']))}</li>
<li><b>Snort comparison:</b> {'yes' if meta['with_snort'] else 'no'}</li>
<li><b>Trials:</b> {len(records)} planned, {sum(1 for r in records if r['status']=='completed')} completed</li>
</ul>
<h2>Candidate alerts per case (unreviewed)</h2>
{''.join(f'<div class="chart">{c}</div>' for c in charts)}
<h2>Trial detail</h2>
<table><tr><th>Model</th><th>Case</th><th>Status</th><th>Actions attempted/planned</th>
<th>Candidate alerts</th><th>Observer issues</th><th>Trial ID</th></tr>
{''.join(rows)}
</table>
<div class="disclaimer"><b>Reminder.</b> {html.escape(DISCLAIMER)} Evidence bundles live under
<code>evidence/&lt;trial_id&gt;/</code> next to this report.</div>
</body></html>"""
    path = report_dir / "demo_matrix_report.html"
    path.write_text(page, encoding="utf-8")
    return path


# --------------------------------------------------------------------- main

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config.example.json",
                        help="Base trial config from the kit (default: config.example.json).")
    parser.add_argument("--kit-dir", default=None,
                        help="Kit folder containing run_trial.py (default: this script's folder).")
    parser.add_argument("--backend", default="http://192.168.254.156:8000",
                        help="SENTRi-X backend base URL.")
    parser.add_argument("--datasets", nargs="*", default=DATASETS, choices=DATASETS)
    parser.add_argument("--modes", nargs="*", default=["hybrid"], choices=MODES)
    parser.add_argument("--cases", nargs="*", default=CASES, choices=CASES)
    parser.add_argument("--snort", dest="with_snort", action="store_true",
                        help="Include Snort baseline runs for each case.")
    parser.add_argument("--no-snort", dest="with_snort", action="store_false")
    parser.set_defaults(with_snort=True)
    parser.add_argument("--pace", default="fast", choices=PACINGS,
                        help="fast: ~2 min/trial; full: kit defaults (~3.5 min/trial).")
    parser.add_argument("--report-dir", default=None,
                        help="Where to write evidence + report (default: demo_YYYYMMDD_HHMMSS).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the plan and exit without touching the backend or network.")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    kit_dir = Path(args.kit_dir).resolve() if args.kit_dir else Path(__file__).resolve().parent
    if not (kit_dir / "run_trial.py").exists():
        raise DemoError(f"No run_trial.py in kit dir {kit_dir}; use --kit-dir.")
    base_cfg_path = Path(args.config)
    if not base_cfg_path.is_absolute():
        base_cfg_path = kit_dir / args.config
    try:
        base_cfg = json.loads(base_cfg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoError(f"Cannot read base config: {exc}")

    pacing = PACINGS[args.pace]
    plan = build_plan(args.datasets, args.modes, args.cases, args.with_snort)
    stamp = datetime.now().strftime("%m%d-%H%M")
    report_dir = (Path(args.report_dir).resolve() if args.report_dir
                  else Path.cwd() / f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    minutes = estimate_minutes(plan, pacing)

    print("SENTRi-X live demo matrix")
    print(f"  Backend : {args.backend}")
    print(f"  Trials  : {len(plan)} planned (~{minutes:.0f} min at '{args.pace}' pace)")
    print(f"  Report  : {report_dir}")
    for i, item in enumerate(plan, 1):
        who = "Snort" if item["engine"] == "snort" else f"{item['dataset']} / {item['engine']}"
        print(f"    {i:2d}. {who:28s} {CASE_LABEL[item['case']]}")
    print(f"\nNote: {DISCLAIMER}")
    if args.dry_run:
        print("\nDry run: no backend calls, no trials executed.")
        return 0

    if not args.yes:
        answer = input("\nRun this live demo plan? Type 'yes' to proceed: ").strip().lower()
        if answer != "yes":
            print("Aborted; nothing was executed.")
            return 0

    status, threshold = check_backend(args.backend)
    print(f"\nBackend OK: model={status.get('current_model')} "
          f"mode={status.get('execution_mode')} threshold={threshold}")
    print(f"Dashboard: {args.backend.rstrip('/')}  (open Threat Logs to watch alerts land live)")

    report_dir.mkdir(parents=True, exist_ok=False)
    (report_dir / "configs").mkdir()
    records = []
    current_combo = (None, None)
    try:
        for i, item in enumerate(plan, 1):
            combo = (item["dataset"], item["mode"])
            if item["engine"] != "snort" and combo != current_combo:
                banner(f"STAGE {i}/{len(plan)}: switching backend to "
                       f"{item['dataset']} / {ENGINE_LABEL[item['mode']]}")
                switch_model(args.backend, item["dataset"], item["mode"],
                             pacing["settle_seconds"])
                current_combo = combo
                print("Switch confirmed by /api/status.", flush=True)
            banner(f"STAGE {i}/{len(plan)}: {CASE_LABEL[item['case']]} "
                   f"[{'Snort' if item['engine'] == 'snort' else item['dataset'] + ' ' + item['mode']}]")
            trial_id = trial_id_for(stamp, item)
            cfg = dict(base_cfg)
            cfg["model_domain"] = item["dataset"] if item["engine"] != "snort" else status.get("current_model")
            cfg["expected_alert_threshold"] = threshold
            cfg["warmup_seconds"] = pacing["warmup_seconds"]
            cfg["scoring_seconds"] = pacing["scoring_seconds"]
            cfg["action_window_seconds"] = pacing["action_window_seconds"]
            cfg_path = report_dir / "configs" / f"{trial_id}.json"
            cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            record = run_one(kit_dir, cfg_path, item, trial_id, report_dir, args.backend)
            records.append(record)
            print(f"[{trial_id}] returncode={record['returncode']} "
                  f"status={record['status']} attempted={record['attempted']}/"
                  f"{record['planned']} candidate_alerts={record['candidate_alerts']}",
                  flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted by user; writing partial report.", flush=True)
    except DemoError as exc:
        print(f"\nDemo error: {exc}", flush=True)
    finally:
        meta = {"plan": plan, "backend": args.backend, "threshold": threshold,
                "datasets": args.datasets, "modes": args.modes,
                "cases": args.cases, "with_snort": args.with_snort}
        report_path = build_report(report_dir, records, meta)
    done = sum(1 for r in records if r["status"] == "completed")
    print(f"\nFinished: {done}/{len(records)} trials completed. "
          f"Report: {report_path}")
    print(f"Reminder: {DISCLAIMER}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"Setup error: {exc}", file=sys.stderr)
        raise SystemExit(2)
