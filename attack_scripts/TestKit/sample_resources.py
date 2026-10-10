#!/usr/bin/env python3
"""Optional process/host resource recorder. Run separately on each measured host."""
from __future__ import annotations

import argparse
import math
import platform
import time
from pathlib import Path

from sentrix_lab.common import JsonlLog, stamp, wait_until, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="For example pi_sensor, backend, snort, or host.")
    parser.add_argument("--pid", type=int, help="Process PID. Omit only for an explicitly whole-host run.")
    parser.add_argument("--duration", type=float, default=180)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--output", required=True, help="New JSONL filename; never overwrites existing data.")
    args = parser.parse_args()
    if (not math.isfinite(args.duration) or not math.isfinite(args.interval) or
            not 1 <= args.duration <= 86400 or not 0.25 <= args.interval <= 60 or
            args.interval > args.duration or (args.pid is not None and args.pid <= 0)):
        parser.error("Use duration 1..86400s, interval 0.25..60s within duration, and a positive PID.")
    try:
        import psutil
    except ImportError:
        parser.exit(2, "Optional dependency missing. In your environment run: python -m pip install psutil\n")
    output = Path(args.output)
    summary_path = Path(str(output) + ".summary.json")
    if output.exists() or summary_path.exists():
        parser.exit(2, "Output already exists; choose a fresh filename.\n")
    log = JsonlLog(output, {"scope": args.scope, "host": platform.node(), "pid": args.pid})
    process = None
    count = errors = 0
    interrupted = False
    cpu_values, memory_values = [], []
    started = stamp()
    try:
        process = psutil.Process(args.pid) if args.pid else None
        if process:
            creation_time = process.create_time()
            process.cpu_percent(None)  # Prime; this first value is not a measured sample.
        else:
            creation_time = None
            psutil.cpu_percent(None)
        log.write("resource_recording_started", started=started,
                  duration_seconds=args.duration, interval_seconds=args.interval,
                  psutil_version=psutil.__version__,
                  logical_cpu_count=psutil.cpu_count(),
                  cpu_basis="one_core_100_percent" if process else "whole_host_0_to_100_percent",
                  memory_basis="process_RSS_bytes" if process else "host_used_bytes",
                  process_create_time=creation_time,
                  note="Child processes are not automatically included; clocks across hosts need alignment.")
        deadline = started["monotonic_ns"] / 1e9 + args.duration
        due = started["monotonic_ns"] / 1e9 + args.interval
        while due <= deadline:
            wait_until(due)
            try:
                if process:
                    if not process.is_running() or process.create_time() != creation_time:
                        raise RuntimeError("The original process ended or its PID was reused.")
                    cpu = float(process.cpu_percent(None))
                    memory = int(process.memory_info().rss)
                else:
                    cpu = float(psutil.cpu_percent(None))
                    memory = int(psutil.virtual_memory().used)
                if not math.isfinite(cpu):
                    raise RuntimeError("Non-finite CPU sample.")
                log.write("resource_sample", cpu_percent=cpu, memory_bytes=memory,
                          memory_mib=memory / (1024 * 1024))
                cpu_values.append(cpu)
                memory_values.append(memory)
                count += 1
            except (psutil.Error, RuntimeError, OSError) as exc:
                errors += 1
                log.write("resource_error", error=f"{type(exc).__name__}: {exc}")
            due = max(due + args.interval, time.monotonic() + 0.001)
    except (psutil.Error, OSError) as exc:
        errors += 1
        log.write("resource_error", error=f"{type(exc).__name__}: {exc}")
    except KeyboardInterrupt:
        interrupted = True
        log.write("resource_recording_interrupted")
    finally:
        summary = {
            "scope": args.scope, "pid": args.pid, "started": started, "ended": stamp(),
            "sample_count": count, "error_count": errors,
            "interrupted": interrupted,
            "cpu_mean_percent": sum(cpu_values) / count if count else None,
            "cpu_peak_percent": max(cpu_values) if count else None,
            "memory_mean_bytes": sum(memory_values) / count if count else None,
            "memory_peak_bytes": max(memory_values) if count else None,
            "note": "This summary covers this recorder's whole interval. Select scoring-window samples for trial comparison.",
        }
        log.write("resource_recording_finished", summary=summary)
        log.close()
        write_json(summary_path, summary)
    print(f"{count} measured samples, {errors} errors. Raw evidence: {output.resolve()}")
    return 0 if count and not errors and not interrupted else 3


if __name__ == "__main__":
    raise SystemExit(main())
