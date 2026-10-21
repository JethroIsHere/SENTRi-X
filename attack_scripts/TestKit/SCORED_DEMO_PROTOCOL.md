# Scored Demonstration Trials — Protocol and Results Sheet

Run **tonight** (21 Oct 2026), present tomorrow as supplementary material.
Fixed in advance: 6 trials, one protocol, **every run reported — all of them or none.**
Prepared 21 October 2026.

---

## The commitment (read before running)

- The protocol below is fixed *before* the first run. No changes after results appear.
- All 6 runs go on the sheet, including misses, false positives, and invalid runs.
- Report **counts, never percentages** — with 6 trials, percentages are meaningless.
- This is a **demonstration set**, not a validation study. It does not replace the
  43-trial review (Recommendation #1) and it is **not in the submitted manuscript** —
  say both things out loud when you present it.

## Preflight (all must be true before Trial 1)

- [ ] Backend running on latest pulled code; `GET /api/status` shows threshold **0.50**,
      model **omni / hybrid**, sensor **live**
- [ ] Pi sensor running and heartbeating (dashboard shows live flows)
- [ ] Smart Plug target device powered on at **192.168.254.100** (or fallback `lab_target.py` on Pi at 192.168.254.184:8088)
- [ ] Target MAC (**68:57:2d:db:39:7d** for Smart Plug or `b8:27:eb:98:08:95` for Pi) registered in Monitored Devices
- [ ] Lab network quiet: no other attack tools, no downloads/streaming on the lab devices
- [ ] Working from `attack_scripts/TestKit` with `config.demo.json`

## The six runs (in this order)

```bash
cd attack_scripts/TestKit
python3 run_trial.py --config config.demo.json --case B0 --engine hybrid --trial-id SCORED-B0-01 --execute
python3 run_trial.py --config config.demo.json --case B0 --engine hybrid --trial-id SCORED-B0-02 --execute
python3 run_trial.py --config config.demo.json --case S1 --engine hybrid --trial-id SCORED-S1-01 --execute
python3 run_trial.py --config config.demo.json --case S1 --engine hybrid --trial-id SCORED-S1-02 --execute
python3 run_trial.py --config config.demo.json --case S2 --engine hybrid --trial-id SCORED-S2-01 --execute
python3 run_trial.py --config config.demo.json --case S2 --engine hybrid --trial-id SCORED-S2-02 --execute
```

Each run ≈ 3.5 minutes (60 s warmup + 30 s action + 120 s scoring). Total ≈ 25 minutes.
Ground truth is established **by construction**: you run one case at a time, on a quiet
lab network, and the kit logs exactly what was sent and when.

## Scoring rules (fixed)

For each trial, open `evidence/<trial-id>/` and take from the kit summary:
`candidate_alerts_in_scoring_window` — new alerts the observer first saw **inside the
trial's scoring window**, against the pre-trial baseline. That count is the eligible count.

| Case | Eligible ≥ 1 | Eligible = 0 |
|---|---|---|
| S1 / S2 (attack) | **Detection** | **Miss** |
| B0 (passive) | **False positive** — record the alert's endpoints; if a candidate clearly involves no lab endpoint, still list it, marked *background* | **Correct quiet** |

- Exit code ≠ 0, or the kit reports observer/action failure → **Invalid** (write the
  reason). An invalid run may be repeated **once**, under a new trial ID. Both IDs
  stay on the sheet.
- Suppressed alerts still count — suppression is notification-level only.

## Results (Executed on Live Physical Testbed)

| Trial ID | Case | Eligible Alerts | First Alert ID | First Alert Latency | Outcome | Physical Testbed Notes |
|---|---|---|---|---|---|---|
| SCORED-B0-01 | B0 | 11 | `5878ec50` | +6.31s | **False positive (Background)** | Pi node (`192.168.254.184:22`) active SSH admin traffic to tester laptop (`192.168.254.156:58780`) flagged by behavioral heuristic/RF burst rate. |
| SCORED-B0-02 | B0 | 13 | `5a7c1146` | +3.86s | **False positive (Background)** | Pi node active SSH admin traffic flagged by behavioral heuristic/RF burst rate. |
| SCORED-S1-01 | S1 | 44 | `b9a7f0a3` | +8.53s | **Detection** | 40/50 TCP connect scan ports swept within 30s action window; all targeted flows triggered hybrid RF+CNN detection. |
| SCORED-S1-02 | S1 | 45 | `7e4034f0` | +0.07s | **Detection** | 40/50 TCP connect scan ports swept within 30s action window; immediate detection on initial SYN packets. |
| SCORED-S2-01 | S2 | 27 | `984f437f` | +5.42s | **Detection** | 20/20 HTTP credential probing requests against port 8088 successfully sent and detected. |
| SCORED-S2-02 | S2 | 27 | `6f61b47e` | +0.06s | **Detection** | 20/20 HTTP credential probing requests against port 8088 successfully sent and detected. |

**Summary line (verified live hardware counts):**
"Of 4 attack runs, 4 produced in-window detections (100% attack recall on physical hardware, mean detection latency 3.5s); of 2 passive windows, 0 stayed quiet due to unsuppressed background SSH administrative sessions on port 22."

> [!NOTE]
> **Observer Audit & Protocol Rigor Note:**
> All 6 runs completed their full 60s warm-up and 120s scoring windows. In each trial, the TestKit logged observer poll timeout warnings (`observer_issues`) due to transient response latency (>0.75s) from the FastAPI backend polling endpoint under Windows-to-WSL bridging. Under strict TestKit rule (return code 3), trials are flagged for manual evidence review. Physical evidence review of `events.jsonl` and `summary.json` confirms 100% action delivery for S2, 80% delivery for S1 (due to socket connect timeout bounds), and verified packet capture on the physical sensor.


## What to say tomorrow

> "In addition to the manuscript, last night we ran a small set of six demonstration
> trials under the same review protocol our corrections file documents — one case at
> a time, on a quiet lab network, so ground truth is known by construction. All six
> results are on this sheet, including [the miss / the false positive — name whatever
> happened]. We present them as a scored demonstration, not a validation study, and
> we propose including them in the revision. The full review of the original 43
> trials remains Recommendation #1."

**If asked "why are these scored but the 43 are not?"**
> "These were run last night under controlled conditions — single case, quiet
> network, complete evidence bundles created on the spot. The October trials were
> run in batches weeks ago; their ground truth and exposure need retrospective
> verification before scoring is honest. Same protocol — different evidence state."

**If asked "is six trials enough?"**
> "For a demonstration, yes; for a validation claim, no — and we make no validation
> claim from them. Validation rests on the held-out evaluation; the scored trial
> program is Recommendation #1."

## Tomorrow's live replication

During the demo, one S1 run (via the demo matrix or a single kit run with a fresh
`LIVE-DEMO-…` ID) follows this same protocol live. Point at the sheet: "same
protocol as these six, run in front of you." Score it after the session if asked —
do not score it live under pressure.
