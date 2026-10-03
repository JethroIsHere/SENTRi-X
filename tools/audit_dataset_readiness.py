"""Read-only dataset audit: measured evidence, not a training readiness gate."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import csv
from datetime import datetime
from importlib import metadata as package_metadata
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import warnings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import psutil

from sentrix_ml.adapters.bot_iot import (
    load_bot_iot, MANDATORY_RAW_COLUMNS as BOT_REQUIRED, SCHEMA_MAPPING_BASE,
)
from sentrix_ml.adapters.cic_ids2017 import (
    load_cic_ids2017, MANDATORY_RAW_COLUMNS as CIC_REQUIRED, SCHEMA_MAPPING,
)
from sentrix_ml.datasets import load_omni
from sentrix_ml.provenance import (
    IDENTITY_POLICY, GROUP_POLICY, _ANNOTATIONS, _COUNTERS, _digest, _value, sampling_audit,
)
from sentrix_ml.sampler import file_sha256
from sentrix_ml.schema import REQUIRED_NUMERIC_FEATURES
from sentrix_ml.splits import _prepare, _partition, clean_labels, validate_partition_support

AUDIT_VERSION = "3"
TUPLES = {
    "bot_iot": ["saddr", "sport", "daddr", "dport", "proto"],
    "cic_ids2017": ["source ip", "source port", "destination ip", "destination port", "protocol"],
}
TIMES = {"bot_iot": "stime", "cic_ids2017": "timestamp"}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def compute_row_raw_id(domain, columns, row_tuple):
    """Use production normalization, including missing/nonfinite values."""
    return _digest([domain, [(c, _value(v)) for c, v in zip(columns, row_tuple)]])


def source_files(data_root, domain):
    directory = Path(data_root) / domain
    if domain == "bot_iot":
        files = sorted(directory.glob("UNSW_2018_IoT_Botnet_Full5pc_*.csv"))
        files = files or sorted(directory.glob("*.csv"))
    else:
        files = sorted(p for p in directory.glob("*.csv") if not p.name.endswith("mapped.csv"))
    if not files:
        raise FileNotFoundError(f"No raw {domain} CSV files in {directory}")
    return files


def valid_raw_rows(chunk, domain):
    """Mirror raw-adapter eligibility; parity is checked against real adapters."""
    raw = chunk.reset_index(drop=True).copy()
    if domain == "cic_ids2017":
        raw.columns = raw.columns.str.strip().str.lower()
    if not raw.columns.is_unique:
        raise ValueError(f"{domain}: duplicate normalized column names")
    mapping = SCHEMA_MAPPING_BASE if domain == "bot_iot" else SCHEMA_MAPPING
    required = BOT_REQUIRED if domain == "bot_iot" else CIC_REQUIRED
    missing = [c for c in required if c not in raw and mapping.get(c) not in raw]
    if missing:
        raise ValueError(f"{domain}: missing mandatory traffic columns: {missing}")
    label_col = "attack" if domain == "bot_iot" and "attack" in raw else "label"
    if label_col not in raw:
        raise ValueError(f"{domain}: missing label column")
    if domain == "bot_iot" and "attack" in raw and "label" in raw:
        raise ValueError("BoT input has both attack and label; production rename is ambiguous")
    labels, exclusions = clean_labels(raw[label_col], domain=domain)
    invalid_numeric = pd.Series(False, index=raw.index)
    for canonical in REQUIRED_NUMERIC_FEATURES:
        candidates = [c for c in raw if mapping.get(c, c) == canonical]
        if len(candidates) != 1:
            raise ValueError(f"{domain}: ambiguous/missing required field {canonical}")
        values = pd.to_numeric(raw[candidates[0]].replace("-", np.nan), errors="coerce")
        if domain == "cic_ids2017" and canonical == "duration":
            values = values / 1e6
        invalid_numeric |= ~np.isfinite(values) | (values < 0)
    exclusions = dict(exclusions)
    if invalid_numeric.any():
        exclusions["invalid_or_missing_required_numerics"] = int(invalid_numeric.sum())
    return raw, labels, labels.notna() & ~invalid_numeric, exclusions, label_col


def iter_raw_chunks(files, domain, chunksize):
    for path in files:
        offset = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, dtype=str, low_memory=False):
            raw, y, valid, exclusions, label_col = valid_raw_rows(chunk, domain)
            yield path, offset, raw, y, valid, exclusions, label_col
            offset += len(raw)


def raw_identity(domain, row, columns):
    """Scalar counterpart of raw_metadata_factory, checked for exact parity."""
    def fingerprint():
        return f"{domain}:raw:{compute_row_raw_id(domain, columns, [row[c] for c in columns])}"
    fields = TUPLES[domain]
    if all(c in row for c in fields):
        values = [_value(row[c]) for c in fields]
        if all(v not in (None, "", "-") for v in values):
            src_ip, src_port, dst_ip, dst_port, proto = values
            parts = [domain, sorted([(src_ip, src_port), (dst_ip, dst_port)]), proto]
            scope = "tuple_without_session_start"
            start = _value(row.get(TIMES[domain]))
            if start not in (None, "", "-"):
                parts.append(start)
                scope = "tuple_and_session_start"
            return f"{domain}:session:{_digest(parts)}", scope, fingerprint
    return fingerprint(), "raw_record_only", fingerprint


def trace_split(X, y, metadata, *, domain, seed, test_fraction, val_fraction=.10, conflict_policy="retain_and_group"):
    """Execute production preparation and both group allocations; retain failures."""
    trace = {"seed": seed, "test_fraction": test_fraction, "val_fraction": val_fraction}
    stage = "prepare"
    try:
        input_counts = {str(k): int(v) for k, v in pd.Series(y).dropna().astype(int).value_counts().items()}
        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter("always")
            X, y, meta, invalid, duplicates, conflict_rows = _prepare(
                X, y, metadata, domain, conflict_policy=conflict_policy
            )
        prepared_counts = {str(k): int(v) for k, v in y.value_counts().items()}
        trace.update(rows_after_preparation=len(y), duplicates_excluded=duplicates,
                     invalid_labels_excluded=invalid, unique_groups=int(meta.group_id.nunique()),
                     input_class_counts=input_counts, prepared_class_counts=prepared_counts,
                     removed_class_counts={k: n-prepared_counts.get(k, 0) for k, n in input_counts.items()},
                     conflicting_label_rows_before_preparation=conflict_rows,
                     preparation_warnings=[str(w.message) for w in observed],
                     label_integrity_status="UNRESOLVED_LABEL_CONFLICTS" if conflict_rows else "NO_CONFLICTS_IN_SELECTED_SAMPLE")
        domains = meta.domain if domain == "omni" else None
        stage = "pool_test_split"
        pool, exam = _partition(X.index, y, meta.group_id, test_fraction, seed, domains)
        def counts(index):
            return {str(k): int(v) for k, v in y.loc[index].value_counts().items()}
        trace["pool_class_counts"] = counts(pool)
        trace["test_class_counts"] = counts(exam)
        trace["pool_benign_source_ids"] = meta.loc[pool[y.loc[pool].to_numpy() == 0], "source_flow_id"].tolist()
        stage = "train_validation_split"
        train, val = _partition(pool, y, meta.group_id, val_fraction, seed, domains)
        trace["train_class_counts"] = counts(train)
        trace["validation_class_counts"] = counts(val)
        stage = "class_support"
        trace["partition_support"] = validate_partition_support(
            y.loc[train], y.loc[val], y.loc[exam], domains=domains, indices=(train, val, exam))
        trace["production_partition_status"] = "READY"
        is_review = bool(conflict_rows and duplicates)
        trace["status"] = "REVIEW_REQUIRED" if is_review else "READY"
        trace["scope_note"] = (
            "Production class-support gates passed after keep-first discarded ambiguous rows; "
            "this does not resolve label correctness or authorize training."
            if is_review else
            "Configured partition support only; this is not a validation of the research sampling or identity protocol."
        )
    except (ValueError, KeyError) as exc:
        trace.update(status="FAILED", production_partition_status="FAILED", failed_stage=stage, error=str(exc))
    return trace


def fresh_artifacts(output_dir, names):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = [str(output_dir / n) for n in names if (output_dir / n).exists()]
    if existing:
        raise FileExistsError(f"Use a fresh audit directory; existing evidence will not be reused or overwritten: {existing}")


def audit_bot_iot(data_root, output_dir, seed=42, chunksize=50_000,
                  sample_n=50_000, sample_per_domain=30_000):
    files = source_files(data_root, "bot_iot")
    output_dir = Path(output_dir)
    fresh_artifacts(output_dir, ["bot_audit.db", "bot_iot_benign_inventory.csv"])
    hashes = {p.name: file_sha256(p) for p in files}
    stats = {p.name: {"total_rows": 0, "valid_rows": 0, "benign_rows": 0, "attack_rows": 0} for p in files}
    exclusions = Counter()
    fields = ["source_file", "source_file_hash", "source_row_index", "source_flow_id",
              "original_label", "binary_label", "pkSeqID", "saddr", "sport", "daddr",
              "dport", "proto", "stime", "category", "subcategory",
              "duplicate_id", "group_id", "group_scope"]
    with closing(sqlite3.connect(output_dir / "bot_audit.db")) as db:
        db.execute("PRAGMA temp_store=FILE")
        db.execute("CREATE TABLE groups (group_id TEXT PRIMARY KEY, benign INTEGER, attack INTEGER)")
        db.execute("CREATE TABLE benign (fingerprint TEXT, group_id TEXT)")
        with (output_dir / "bot_iot_benign_inventory.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for path, offset, raw, y, valid, dropped, label_col in iter_raw_chunks(files, "bot_iot", chunksize):
                name, digest = path.name, hashes[path.name]
                fstats = stats[name]
                fstats["total_rows"] += len(raw)
                fstats["valid_rows"] += int(valid.sum())
                exclusions.update(dropped)
                columns = sorted(c for c in raw if c.lower() not in _ANNOTATIONS | _COUNTERS)
                batch, benign_batch = Counter(), []
                for pos, row in zip(np.flatnonzero(valid.to_numpy()), raw.loc[valid].to_dict("records")):
                    label = int(y.iloc[pos])
                    fstats["benign_rows" if label == 0 else "attack_rows"] += 1
                    group, scope, fingerprint = raw_identity("bot_iot", row, columns)
                    batch[(group, label)] += 1
                    if label == 0:
                        duplicate = fingerprint()
                        benign_batch.append((duplicate, group))
                        record = {c: _value(row.get(c)) for c in fields}
                        record.update(source_file=name, source_file_hash=digest,
                            source_row_index=offset + int(pos),
                            source_flow_id=f"bot_iot:{name}:{digest}:row:{offset + int(pos)}",
                            original_label=_value(row[label_col]), binary_label=0,
                            duplicate_id=duplicate, group_id=group, group_scope=scope)
                        writer.writerow(record)
                db.executemany(
                    "INSERT INTO groups VALUES (?,?,?) ON CONFLICT(group_id) DO UPDATE SET "
                    "benign=benign+excluded.benign, attack=attack+excluded.attack",
                    [(g, n if label == 0 else 0, n if label == 1 else 0) for (g, label), n in batch.items()])
                db.executemany("INSERT INTO benign VALUES (?,?)", benign_batch)
                db.commit()
                print(f"[BoT] {name}: {fstats['total_rows']:,} raw rows scanned", flush=True)
        benign_count, fingerprints, groups = db.execute(
            "SELECT COUNT(*),COUNT(DISTINCT fingerprint),COUNT(DISTINCT group_id) FROM benign").fetchone()
        mixed = db.execute("SELECT group_id,benign,attack FROM groups WHERE benign>0 AND attack>0 ORDER BY group_id").fetchall()
        group_total = db.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    summary = {
        "files_considered": [p.name for p in files], "file_hashes": hashes, "file_stats": stats,
        "total_rows_considered": sum(s["total_rows"] for s in stats.values()),
        "total_valid_rows": sum(s["valid_rows"] for s in stats.values()),
        "total_benign_rows": benign_count,
        "total_attack_rows": sum(s["attack_rows"] for s in stats.values()),
        "unique_benign_fingerprints": fingerprints, "unique_benign_groups": groups,
        "unique_source_groups": group_total,
        "duplicate_benign_rows_under_current_policy": benign_count - fingerprints,
        "mixed_label_groups_count": len(mixed),
        "mixed_groups_detail": {g: {"benign": b, "attack": a} for g, b, a in mixed},
        "exclusion_reasons": dict(exclusions), "inventory_policy": "fresh_full_source_scan",
    }
    summary["benign_prevalence"] = benign_count / summary["total_valid_rows"] if summary["total_valid_rows"] else None
    samples = {}
    for name, size in [("adaptation", sample_n), ("omni_bot_slice_only", sample_per_domain)]:
        X, y, info = load_bot_iot(Path(data_root) / "bot_iot", sample_n=size, seed=seed, chunksize=chunksize)
        benign = info["metadata"].loc[y == 0]
        samples[name] = {
            "sample_n": size, "seed": seed, "class_counts": {str(k): int(v) for k, v in y.value_counts().items()},
            "sampling_metadata": sampling_audit(info),
            "benign_rows_selected": benign[["source_file", "source_row_index", "duplicate_id", "group_id"]].to_dict("records"),
            "split_trace": trace_split(X, y, info["metadata"], domain="bot_iot", seed=seed,
                                      test_fraction=.8 if name == "adaptation" else .2),
        }
        if name == "omni_bot_slice_only":
            samples[name]["scope_note"] = "BoT-only diagnostic; this is not a replay of the combined Omni group allocation."
    summary["sample_reproductions"] = samples
    return summary

def cic_statistics(db):
    db.execute("""CREATE TEMP TABLE fingerprint_stats AS
        SELECT fingerprint,COUNT(*) AS n,COUNT(DISTINCT binary_label) AS labels,
               SUM(binary_label=0) AS benign,SUM(binary_label=1) AS attack,
               COUNT(DISTINCT source_file) AS files,COUNT(DISTINCT raw_label) AS raw_labels
        FROM cic_records GROUP BY fingerprint""")
    def scalar(sql):
        return db.execute(sql).fetchone()[0] or 0
    conflicts = db.execute("""SELECT s.fingerprint,s.n,s.benign,s.attack,s.files,s.raw_labels,
        GROUP_CONCAT(DISTINCT r.raw_label),GROUP_CONCAT(DISTINCT r.source_file)
        FROM fingerprint_stats s JOIN cic_records r USING(fingerprint)
        WHERE s.labels>1 GROUP BY s.fingerprint ORDER BY s.n DESC,s.fingerprint""").fetchall()
    db.execute("""CREATE TEMP TABLE within_file_conflicts AS
        SELECT DISTINCT fingerprint FROM (
            SELECT fingerprint,source_file FROM cic_records GROUP BY fingerprint,source_file
            HAVING COUNT(DISTINCT binary_label)>1)""")
    within = {r[0] for r in db.execute("SELECT fingerprint FROM within_file_conflicts")}
    spanning = {r[0] for r in conflicts if r[4] > 1}
    return {
        "unique_fingerprints": scalar("SELECT COUNT(*) FROM fingerprint_stats"),
        "singleton_fingerprints": scalar("SELECT COUNT(*) FROM fingerprint_stats WHERE n=1"),
        "repeated_fingerprints": scalar("SELECT COUNT(*) FROM fingerprint_stats WHERE n>1"),
        "same_label_repeated_groups": scalar("SELECT COUNT(*) FROM fingerprint_stats WHERE n>1 AND labels=1"),
        "same_label_removable_duplicates_under_current_policy": scalar("SELECT SUM(n-1) FROM fingerprint_stats WHERE labels=1"),
        "binary_conflict_groups": len(conflicts),
        "binary_conflict_rows": sum(r[1] for r in conflicts),
        "binary_conflict_benign_rows": sum(r[2] for r in conflicts),
        "binary_conflict_attack_rows": sum(r[3] for r in conflicts),
        "within_file_conflict_groups": len(within),
        "conflict_groups_spanning_files": len(spanning),
        "both_within_and_across_files": len(within & spanning),
        "across_files_only_conflict_groups": len(spanning - within),
        "attack_only_name_divergence_groups": scalar(
            "SELECT COUNT(*) FROM fingerprint_stats WHERE labels=1 AND benign=0 AND raw_labels>1"),
    }, conflicts


def export_cic_examples(db, files, hashes, conflicts, output_dir, chunksize, group_limit, per_class):
    requested, selected = {}, {}
    for conflict in conflicts[:group_limit]:
        fp = conflict[0]
        instances = []
        for label in (0, 1):
            instances += db.execute(
                "SELECT source_file,row_index,raw_label,binary_label FROM cic_records "
                "WHERE fingerprint=? AND binary_label=? ORDER BY source_file,row_index LIMIT ?",
                (fp, label, per_class)).fetchall()
        selected[fp] = instances
        for fname, row, _, _ in instances:
            requested.setdefault(fname, set()).add(row)
    found = {}
    for path in files:
        wanted = requested.get(path.name, set())
        if not wanted:
            continue
        offset = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, dtype=str, low_memory=False):
            for i in sorted(i for i in wanted if offset <= i < offset + len(chunk)):
                found[(path.name, i)] = {c: _value(v) for c, v in chunk.iloc[i-offset].items()}
            offset += len(chunk)
    with (Path(output_dir) / "cic_conflict_examples.jsonl").open("w", encoding="utf-8") as handle:
        for fp, total, *_ in conflicts[:group_limit]:
            instances = []
            for fname, row, label, binary in selected[fp]:
                instances.append({"source_file": fname, "file_sha256": hashes[fname],
                    "source_row_index": row, "raw_label": label, "binary_label": binary,
                    "raw_fields": found[(fname, row)]})
            handle.write(json.dumps({
                "fingerprint": fp, "total_rows_in_source": total,
                "evidence_classification": "UNRESOLVED_AMBIGUITY",
                "interpretation": "Matching measurements do not establish event identity or which annotation is correct.",
                "instances": instances,
            }, allow_nan=False) + "\n")


def audit_cic_ids2017(data_root, output_dir, seed=42, chunksize=50_000,
                     sample_n=50_000, example_groups=50, examples_per_class=3):
    files = source_files(data_root, "cic_ids2017")
    output_dir = Path(output_dir)
    fresh_artifacts(output_dir, ["cic_audit.db", "cic_column_inventory.json", "cic_conflict_groups.csv",
                                "cic_conflict_examples.jsonl", "cic_fingerprint_summary.json"])
    hashes = {p.name: file_sha256(p) for p in files}
    inventory, stats, exclusions = {}, {}, Counter()
    aliases = {
        "flow_id": ["flow id"], "source_ip": ["source ip", "src ip"],
        "destination_ip": ["destination ip", "dst ip"], "source_port": ["source port", "src port"],
        "destination_port": ["destination port", "dst port"], "protocol": ["protocol", "proto"],
        "timestamp": ["timestamp", "ts"],
    }
    with closing(sqlite3.connect(output_dir / "cic_audit.db")) as db:
        db.execute("PRAGMA temp_store=FILE")
        db.execute("CREATE TABLE cic_records (fingerprint TEXT,source_file TEXT,row_index INTEGER,raw_label TEXT,binary_label INTEGER)")
        for path, offset, raw, y, valid, dropped, label_col in iter_raw_chunks(files, "cic_ids2017", chunksize):
            name = path.name
            if name not in inventory:
                inventory[name] = {
                    "file_sha256": hashes[name], "columns_normalized": list(raw.columns),
                    "column_count": len(raw.columns),
                    "network_identifiers": {k: {"columns": [c for c in v if c in raw], "usable_rows": 0}
                                            for k, v in aliases.items()},
                }
                stats[name] = {"total_rows": 0, "valid_rows": 0}
            for entry in inventory[name]["network_identifiers"].values():
                usable = pd.Series(False, index=raw.index)
                for col in entry["columns"]:
                    usable |= raw[col].notna() & ~raw[col].astype(str).str.strip().isin(["", "-"])
                entry["usable_rows"] += int(usable.sum())
            stats[name]["total_rows"] += len(raw)
            stats[name]["valid_rows"] += int(valid.sum())
            exclusions.update(dropped)
            cols = sorted(c for c in raw if c.lower() not in _ANNOTATIONS | _COUNTERS)
            positions = np.flatnonzero(valid.to_numpy())
            values = raw.loc[valid, cols].itertuples(index=False, name=None)
            labels = raw.loc[valid, label_col].astype(str).str.strip()
            db.executemany("INSERT INTO cic_records VALUES (?,?,?,?,?)", (
                (f"cic_ids2017:raw:{compute_row_raw_id('cic_ids2017', cols, row)}",
                 name, offset + int(pos), label, int(binary))
                for pos, row, label, binary in zip(positions, values, labels, y.loc[valid])))
            db.commit()
            print(f"[CIC] {name}: {stats[name]['total_rows']:,} raw rows scanned", flush=True)
        db.execute("CREATE INDEX cic_fingerprint ON cic_records(fingerprint,binary_label)")
        fingerprint_stats, conflicts = cic_statistics(db)
        with (output_dir / "cic_conflict_groups.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["fingerprint", "total_rows", "benign_count", "attack_count",
                             "file_count", "raw_label_count", "raw_labels", "source_files"])
            writer.writerows(conflicts)
        export_cic_examples(db, files, hashes, conflicts, output_dir, chunksize, example_groups, examples_per_class)
        db.commit()
    write_json(output_dir / "cic_column_inventory.json", inventory)
    write_json(output_dir / "cic_fingerprint_summary.json", fingerprint_stats)
    X, y, info = load_cic_ids2017(Path(data_root) / "cic_ids2017", sample_n=sample_n, seed=seed, chunksize=chunksize)
    conflict_ids = y.groupby(info["metadata"].duplicate_id).nunique()
    sample_conflicts = []
    for fp in conflict_ids[conflict_ids > 1].index:
        rows = info["metadata"].loc[info["metadata"].duplicate_id == fp]
        sample_conflicts.append({"fingerprint": fp, "rows": [
            {"source_file": row.source_file, "source_row_index": int(row.source_row_index),
             "binary_label": int(y.loc[i])} for i, row in rows.iterrows()]})
    return {
        "files_considered": [p.name for p in files], "file_hashes": hashes, "file_row_counts": stats,
        "total_rows_considered": sum(s["total_rows"] for s in stats.values()),
        "total_valid_rows": sum(s["valid_rows"] for s in stats.values()),
        "exclusion_reasons": dict(exclusions), "fingerprint_statistics": fingerprint_stats,
        "example_selection": {"groups": example_groups, "rows_per_class_per_group": examples_per_class},
        "sample_reproduction": {"sample_n": sample_n, "seed": seed, "conflicts": sample_conflicts,
            "sampling_metadata": sampling_audit(info),
            "split_trace": trace_split(X, y, info["metadata"], domain="cic_ids2017", seed=seed, test_fraction=.8)},
    }


def compare_source_hashes(previous, current):
    """Detect changed, added AND removed domain-qualified files."""
    changes = {k: {"previous": previous.get(k), "current": current.get(k)}
               for k in sorted(previous.keys() | current.keys()) if previous.get(k) != current.get(k)}
    return {"status": "ALL_MATCH" if not changes else "MISMATCH",
            "matched_count": sum(previous.get(k) == v for k, v in current.items()),
            "changes": changes}


class MemoryMonitor:
    """Sample this process's RSS; do not claim an exact kernel high-water mark."""
    def __init__(self, interval=.1, process=None):
        self.interval = interval
        self.error = None
        try:
            self.process = process if process is not None else psutil.Process()
        except (psutil.Error, OSError) as exc:
            self.process = None
            self.error = str(exc)
        self.stop = threading.Event()
        self.peak = None
        self.end = None
        self.thread = None

    def sample(self):
        if self.process is None:
            return
        try:
            self.end = self.process.memory_info().rss
            self.peak = max(self.peak or 0, self.end)
        except (psutil.Error, OSError) as exc:
            self.error = str(exc)
            self.end = None

    def __enter__(self):
        self.sample()
        def poll():
            while not self.stop.wait(self.interval):
                self.sample()
        self.thread = threading.Thread(target=poll, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()
        self.sample()

    def result(self):
        self.sample()
        return {"status": "UNAVAILABLE" if self.peak is None else ("PARTIAL" if self.error else "AVAILABLE"),
                "error": self.error,
                "sampled_peak_rss_mb": round(self.peak / 1024**2, 2) if self.peak is not None else None,
                "end_rss_mb": round(self.end / 1024**2, 2) if self.end is not None else None,
                "sample_interval_seconds": self.interval,
                "scope": "audit process only; sampled maximum may miss brief peaks; excludes child processes"}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=PROJECT_ROOT / "data/raw")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--chunksize", type=int, default=10_000)
    parser.add_argument("--sample-n", type=int, default=50_000)
    parser.add_argument("--sample-per-domain", type=int, default=30_000)
    parser.add_argument("--example-groups", type=int, default=50)
    parser.add_argument("--examples-per-class", type=int, default=3)
    parser.add_argument("--include-omni", action="store_true", help="Also replay full Omni, including a ToN source scan")
    parser.add_argument("--previous-preflight", type=Path,
                        default=PROJECT_ROOT / "outputs/local-verification/run_20261003_083357/preflight-local.json")
    args = parser.parse_args(argv)
    for name in ("chunksize", "sample_n", "sample_per_domain", "example_groups", "examples_per_class"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    return args


def main(argv=None):
    args = parse_args(argv)
    output = args.output_dir or PROJECT_ROOT / "outputs/dataset-audit" / datetime.now().strftime("run_%Y%m%d_%H%M%S_%f")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"Use a fresh output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    version = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    versions = {}
    for package in ("numpy", "pandas", "psutil", "scikit-learn", "tensorflow"):
        try:
            versions[package] = package_metadata.version(package)
        except package_metadata.PackageNotFoundError:
            versions[package] = "NOT_INSTALLED"
    environment = {
        "python_executable": sys.executable, "python_version": sys.version.split()[0],
        "git_commit": version.stdout.strip() if version.returncode == 0 else "UNAVAILABLE",
        "packages": versions, "ram_available_gb": round(psutil.virtual_memory().available / 1024**3, 2),
        "disk_free_gb": round(psutil.disk_usage(str(output)).free / 1024**3, 2),
    }
    domains, errors = {}, {}
    omni = {"status": "NOT_RUN", "reason": "Use --include-omni for a combined ToN/BoT/CIC replay."}
    with MemoryMonitor() as memory:
        for name, function in (("bot_iot", audit_bot_iot), ("cic_ids2017", audit_cic_ids2017)):
            try:
                kwargs = {"seed": args.seed, "chunksize": args.chunksize, "sample_n": args.sample_n}
                if name == "bot_iot":
                    kwargs["sample_per_domain"] = args.sample_per_domain
                else:
                    kwargs.update(example_groups=args.example_groups, examples_per_class=args.examples_per_class)
                domains[name] = function(args.data_root, output, **kwargs)
            except Exception as exc:
                errors[name] = f"{type(exc).__name__}: {exc}"
                print(f"[ERROR] {name}: {errors[name]}", file=sys.stderr, flush=True)
        if args.include_omni:
            try:
                X, y, info = load_omni(args.data_root, sample_per_domain=args.sample_per_domain, seed=args.seed)
                omni = trace_split(X, y, info["metadata"], domain="omni", seed=args.seed, test_fraction=.2)
                omni["source_file_hashes"] = info["source_file_hashes"]
                omni["sampling_metadata"] = info["sampling_metadata"]
                omni["loader_chunk_policy"] = "Production defaults; --chunksize applies to the individual BoT/CIC audits and replays."
            except Exception as exc:
                omni = {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}"}
                errors["omni_reproduction"] = omni["error"]
    current = {f"{d}/{f}": h for d, result in domains.items() for f, h in result["file_hashes"].items()}
    comparison = {"status": "NO_PREVIOUS_PREFLIGHT"}
    if args.previous_preflight.exists():
        try:
            previous_report = json.loads(args.previous_preflight.read_text(encoding="utf-8-sig"))
            previous = {f"{d}/{f}": h for d in ("bot_iot", "cic_ids2017")
                        for f, h in previous_report["datasets"][d]["sampling_metadata"]["source_file_hashes"].items()}
            comparison = compare_source_hashes(previous, current)
        except (ValueError, KeyError) as exc:
            errors["previous_preflight"] = str(exc)
            comparison = {"status": "INVALID_PREVIOUS_REPORT", "error": str(exc)}
    # Fresh scans and sample replays must refer to stable source bytes.
    before = dict(current)
    replay_changes = {}
    for key, digest in omni.get("source_file_hashes", {}).items():
        if key in before and before[key] != digest:
            replay_changes[key] = {"scan": before[key], "omni_replay": digest}
        before.setdefault(key, digest)
    try:
        checked_domains = sorted({key.split("/", 1)[0] for key in before})
        after = {f"{d}/{p.name}": file_sha256(p) for d in checked_domains for p in source_files(args.data_root, d)}
        stability = compare_source_hashes(before, after)
        if replay_changes:
            stability.update(status="MISMATCH", replay_changes=replay_changes)
    except (OSError, ValueError) as exc:
        stability = {"status": "FAILED", "error": str(exc)}
    if stability["status"] != "ALL_MATCH":
        errors["source_stability"] = "Source files changed during the audit; rerun on stable data."
    summary = {
        "audit_version": AUDIT_VERSION, "audit_status": "FAILED" if errors else "COMPLETED",
        "training_readiness": "NOT_ESTABLISHED_BY_AUDIT",
        "timestamp": datetime.now().isoformat(), "elapsed_seconds": round(time.monotonic()-started, 2),
        "environment": environment, "memory_observation": memory.result(),
        "config": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "identity_policy": IDENTITY_POLICY, "grouping_policy": GROUP_POLICY,
        "source_stability": stability, "hash_verification_vs_previous_preflight": comparison,
        "domains": domains, "omni_reproduction": omni, "errors": errors,
    }
    summary["config"]["output_dir"] = str(output)
    write_json(output / "audit_summary.json", summary)
    exit_code = 1 if errors else 0
    (output / "audit_exit_code.txt").write_text(f"{exit_code}\n", encoding="utf-8")
    print(f"Audit {summary['audit_status']}: {output / 'audit_summary.json'}", flush=True)
    print("Audit completion does not establish training readiness; inspect actual split traces.", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
