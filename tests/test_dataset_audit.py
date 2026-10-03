"""Regressions for the dataset audit; all source files are temporary fixtures."""
import csv
import json
import sqlite3
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from tools import audit_dataset_readiness as audit
from sentrix_ml.datasets import LOADERS
from sentrix_ml.provenance import raw_metadata_factory
from tests.synthetic_data import bot_rows, cic_rows, write_datasets


def save_raw(root, domain, frame, filename="raw.csv"):
    directory = root / domain
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    frame.to_csv(path, index=False)
    return path


@pytest.mark.parametrize("domain,maker,duration,label", [
    ("bot_iot", bot_rows, "dur", "attack"),
    ("cic_ids2017", cic_rows, "Flow Duration", "Label"),
])
def test_audit_eligibility_and_identity_match_production(tmp_path, domain, maker, duration, label):
    frame = maker(14).astype(object)
    frame.loc[2, duration] = -1
    frame.loc[4, duration] = np.inf
    frame.loc[6, duration] = np.nan
    frame.loc[8, duration] = "invalid"
    frame.loc[10, label] = np.nan
    path = save_raw(tmp_path, domain, frame)
    _, y, info = LOADERS[domain](path.parent, sample_n=100, chunksize=3)
    positions, labels, fingerprints, groups = [], [], [], []
    for _, offset, raw, y_raw, valid, _, _ in audit.iter_raw_chunks([path], domain, 3):
        columns = sorted(c for c in raw if c.lower() not in audit._ANNOTATIONS | audit._COUNTERS)
        factory = raw_metadata_factory(raw, domain=domain, filename=path.name, row_offset=offset,
                                       tuple_columns=audit.TUPLES[domain], time_column=audit.TIMES[domain])
        for pos in np.flatnonzero(valid.to_numpy()):
            group, scope, fp = audit.raw_identity(domain, raw.iloc[pos].to_dict(), columns)
            expected = factory(pos)
            assert group == expected["__meta_group_id__"]
            assert scope == expected["__meta_group_scope__"]
            assert fp() == expected["__meta_duplicate_id__"]
            positions.append(offset + int(pos))
            labels.append(int(y_raw.iloc[pos]))
            fingerprints.append(fp())
            groups.append(group)
    # A class-stratified buffer can return class blocks; compare by source row.
    order = np.argsort(info["metadata"].source_row_index.to_numpy())
    produced = info["metadata"].iloc[order]
    assert positions == produced.source_row_index.tolist()
    assert positions == [0, 1, 3, 5, 7, 9, 11, 12, 13]
    assert labels == y.iloc[order].tolist()
    assert fingerprints == produced.duplicate_id.tolist()
    assert groups == produced.group_id.tolist()


@pytest.mark.parametrize("domain,maker,column", [
    ("bot_iot", bot_rows, "spkts"),
    ("cic_ids2017", cic_rows, "Total Fwd Packets"),
])
def test_missing_mandatory_fields_fail(tmp_path, domain, maker, column):
    path = save_raw(tmp_path, domain, maker(8).drop(columns=[column]))
    with pytest.raises(ValueError, match="mandatory"):
        list(audit.iter_raw_chunks([path], domain, 3))


@pytest.mark.parametrize("start", [None, "", "-", "100"])
def test_group_fallback_and_fingerprint_parity(start):
    raw = pd.DataFrame([{"saddr": "a", "sport": "1", "daddr": "b", "dport": "2",
                         "proto": "tcp", "stime": start, "attack": "0", "dur": np.inf}])
    columns = sorted(c for c in raw if c.lower() not in audit._ANNOTATIONS | audit._COUNTERS)
    for fields in (raw, raw.drop(columns=["sport"])):
        cols = [c for c in columns if c in fields]
        expected = raw_metadata_factory(fields, domain="bot_iot", filename="f", row_offset=0,
            tuple_columns=audit.TUPLES["bot_iot"], time_column="stime")(0)
        group, scope, fp = audit.raw_identity("bot_iot", fields.iloc[0].to_dict(), cols)
        assert (group, scope, fp()) == (expected["__meta_group_id__"],
            expected["__meta_group_scope__"], expected["__meta_duplicate_id__"])


@pytest.mark.parametrize("reverse,chunksize", [(False, 1), (True, 3)])
def test_bot_counts_are_order_independent_and_use_valid_rows(tmp_path, reverse, chunksize):
    raw = bot_rows(8)
    raw["attack"] = [1, 0, 1, 0, 1, 0, 1, 0]
    for field in audit.TUPLES["bot_iot"] + ["stime"]:
        raw.loc[1, field] = raw.loc[0, field]
    raw.loc[2, "dur"] = -1
    if reverse:
        raw = raw.iloc[::-1].reset_index(drop=True)
    path = save_raw(tmp_path, "bot_iot", raw)
    source_before = path.read_bytes()
    result = audit.audit_bot_iot(tmp_path, tmp_path / "out", chunksize=chunksize,
                                 sample_n=8, sample_per_domain=6)
    assert result["total_rows_considered"] == 8
    assert result["total_valid_rows"] == 7
    assert result["total_benign_rows"] == 4
    assert result["total_attack_rows"] == 3
    assert result["mixed_label_groups_count"] == 1
    assert list(result["mixed_groups_detail"].values()) == [{"benign": 1, "attack": 1}]
    assert result["exclusion_reasons"]["invalid_or_missing_required_numerics"] == 1
    assert path.read_bytes() == source_before
    with (tmp_path / "out/bot_iot_benign_inventory.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    for row in rows:
        assert raw.iloc[int(row["source_row_index"])].attack == 0


def test_existing_inventory_never_substitutes_population_counts(tmp_path):
    save_raw(tmp_path, "bot_iot", bot_rows(4))
    output = tmp_path / "out"
    result = audit.audit_bot_iot(tmp_path, output, sample_n=4, sample_per_domain=4)
    before = (output / "bot_iot_benign_inventory.csv").read_bytes()
    assert result["total_rows_considered"] == 4
    with pytest.raises(FileExistsError, match="fresh"):
        audit.audit_bot_iot(tmp_path, output)
    assert (output / "bot_iot_benign_inventory.csv").read_bytes() == before


def test_seed_and_sample_caps_reach_real_sampler(tmp_path):
    path = save_raw(tmp_path, "bot_iot", bot_rows(120))
    result = audit.audit_bot_iot(tmp_path, tmp_path / "out", seed=17, chunksize=7,
                                 sample_n=40, sample_per_domain=25)
    for name, size in [("adaptation", 40), ("omni_bot_slice_only", 25)]:
        _, y, info = LOADERS["bot_iot"](path.parent, sample_n=size, seed=17, chunksize=7)
        got = result["sample_reproductions"][name]
        assert got["seed"] == 17 and got["sample_n"] == size
        assert got["sampling_metadata"]["selection_policy"] == "stratified_reservoir_sampling"
        assert got["sampling_metadata"]["source_class_counts"] == info["source_class_counts"]
        assert [r["source_row_index"] for r in got["benign_rows_selected"]] == info["metadata"].loc[y == 0].source_row_index.tolist()
        assert got["split_trace"]["seed"] == 17


def test_split_trace_measures_actual_study_pool_before_failure():
    y = pd.Series([1] * 49996 + [0] * 4)
    X = pd.DataFrame({"duration": np.arange(len(y))})
    meta = pd.DataFrame({"source_flow_id": [f"r:{i}" for i in y.index]})
    result = audit.trace_split(X, y, meta, domain="bot_iot", seed=42, test_fraction=.8)
    assert result["pool_class_counts"] == {"1": 9999, "0": 1}
    assert result["test_class_counts"] == {"1": 39997, "0": 3}
    assert result["failed_stage"] == "train_validation_split"
    assert result["status"] == "FAILED"


def test_mixed_label_group_profiles_are_not_inherently_invalid():
    y = pd.Series([0, 1] * 100)
    X = pd.DataFrame({"duration": np.repeat(np.arange(100), 2)})
    meta = pd.DataFrame({"source_flow_id": [f"r:{i}" for i in y.index],
                         "group_id": [f"g:{i//2}" for i in y.index]})
    result = audit.trace_split(X, y, meta, domain="cic_ids2017", seed=42, test_fraction=.2)
    assert result["status"] == "READY"
    assert result["validation_class_counts"] == {"0": 8, "1": 8}


def test_rare_mixed_profile_failure_is_not_hidden():
    y = pd.Series([0, 1] * 100)
    X = pd.DataFrame({"duration": np.arange(200)})
    meta = pd.DataFrame({"source_flow_id": [f"r:{i}" for i in y.index],
                         "group_id": ["mixed", "mixed"] + [f"g:{i}" for i in range(2, 200)]})
    result = audit.trace_split(X, y, meta, domain="cic_ids2017", seed=42, test_fraction=.2)
    assert result["status"] == "FAILED"
    assert result["failed_stage"] == "pool_test_split"


def test_cic_sql_counts_overlapping_file_conflicts_and_attack_only_groups():
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE cic_records(fingerprint,source_file,row_index,raw_label,binary_label)")
        rows = [
            ("both", "a", "BENIGN", 0), ("both", "a", "DoS", 1), ("both", "b", "DoS", 1),
            ("across", "a", "BENIGN", 0), ("across", "b", "DoS", 1),
            ("attacks", "a", "DoS", 1), ("attacks", "b", "Scan", 1),
            ("mixed_names", "a", "BENIGN", 0), ("mixed_names", "a", "DoS", 1), ("mixed_names", "a", "Scan", 1),
        ]
        db.executemany("INSERT INTO cic_records VALUES (?,?,?,?,?)",
                       [(g, f, i, label, y) for i, (g, f, label, y) in enumerate(rows)])
        result, conflicts = audit.cic_statistics(db)
    assert result["binary_conflict_groups"] == 3
    assert result["within_file_conflict_groups"] == 2
    assert result["conflict_groups_spanning_files"] == 2
    assert result["both_within_and_across_files"] == 1
    assert result["across_files_only_conflict_groups"] == 1
    assert result["attack_only_name_divergence_groups"] == 1


def test_cic_exports_both_classes_and_strict_json_without_altering_data(tmp_path):
    columns = list(audit.CIC_REQUIRED)
    base = cic_rows(3)
    base.columns = base.columns.str.lower()
    base = base[columns + ["label", "destination port"]]
    base["unused"] = np.nan
    first = pd.concat([base.iloc[[0]].assign(label="BENIGN")] * 6, ignore_index=True)
    second = pd.concat([base.iloc[[0]].assign(label="DoS"), base.iloc[[1]].assign(label="Scan")], ignore_index=True)
    a = save_raw(tmp_path, "cic_ids2017", first, "a.csv")
    b = save_raw(tmp_path, "cic_ids2017", second, "b.csv")
    snapshots = {p: p.read_bytes() for p in (a, b)}
    result = audit.audit_cic_ids2017(tmp_path, tmp_path / "out", seed=17, chunksize=2,
                                    sample_n=8, example_groups=1, examples_per_class=1)
    assert result["total_valid_rows"] == 8
    assert result["fingerprint_statistics"]["binary_conflict_rows"] == 7
    assert result["sample_reproduction"]["seed"] == 17
    trace = result["sample_reproduction"]["split_trace"]
    assert trace["failed_stage"] == "pool_test_split"
    assert trace["conflicting_label_rows_before_preparation"] == 7
    assert trace["label_integrity_status"] == "UNRESOLVED_LABEL_CONFLICTS"
    text = (tmp_path / "out/cic_conflict_examples.jsonl").read_text()
    def reject(value):
        raise AssertionError(f"Non-JSON constant {value}")
    example = json.loads(text, parse_constant=reject)
    assert {r["binary_label"] for r in example["instances"]} == {0, 1}
    assert all(r["raw_fields"]["unused"] is None for r in example["instances"])
    assert example["evidence_classification"] == "UNRESOLVED_AMBIGUITY"
    for path, before in snapshots.items():
        assert path.read_bytes() == before


def test_passing_class_gate_does_not_hide_conflicting_label_deletion():
    n = 180
    X = pd.DataFrame({"duration": np.repeat(np.arange(30), 6)})
    labels = [label for g in range(30) for label in ([g % 2] * 3 + [1-g % 2] * 3)]
    y = pd.Series(labels)
    meta = pd.DataFrame({"source_flow_id": [f"row:{i}" for i in range(n)],
                         "duplicate_id": [f"fp:{i//6}" for i in range(n)],
                         "group_id": [f"fp:{i//6}" for i in range(n)]})
    trace = audit.trace_split(X, y, meta, domain="cic_ids2017", seed=42, test_fraction=.2)
    assert trace["production_partition_status"] == "READY"
    assert trace["status"] == "REVIEW_REQUIRED"
    assert trace["input_class_counts"] == {"0": 90, "1": 90}
    assert trace["prepared_class_counts"] == {"0": 15, "1": 15}
    assert trace["removed_class_counts"] == {"0": 75, "1": 75}
    assert trace["duplicates_excluded"] == 150
    assert trace["conflicting_label_rows_before_preparation"] == 180
    assert "keep-first" in trace["preparation_warnings"][0]


def test_hash_comparison_detects_removed_and_added_files():
    result = audit.compare_source_hashes({"bot/a": "x", "cic/b": "y"}, {"bot/a": "x", "cic/c": "z"})
    assert result["status"] == "MISMATCH"
    assert set(result["changes"]) == {"cic/b", "cic/c"}
    assert result["matched_count"] == 1


def test_memory_observation_distinguishes_sampled_maximum_from_end():
    class FakeProcess:
        value = 1024**2
        def memory_info(self):
            return SimpleNamespace(rss=self.value)
    process = FakeProcess()
    monitor = audit.MemoryMonitor(process=process)
    monitor.sample()
    process.value = 10 * 1024**2
    monitor.sample()
    process.value = 2 * 1024**2
    result = monitor.result()
    assert result["sampled_peak_rss_mb"] == 10
    assert result["end_rss_mb"] == 2
    assert "sampled maximum" in result["scope"]


def test_unavailable_process_metrics_are_reported_without_fabrication(monkeypatch):
    def unavailable():
        raise audit.psutil.AccessDenied(pid=123)
    monkeypatch.setattr(audit.psutil, "Process", unavailable)
    with audit.MemoryMonitor() as monitor:
        pass
    result = monitor.result()
    assert result["status"] == "UNAVAILABLE"
    assert result["sampled_peak_rss_mb"] is None
    assert result["end_rss_mb"] is None


def test_cic_sample_replay_respects_seed_and_capacity(tmp_path):
    base = cic_rows(60)
    base.columns = base.columns.str.lower()
    base = base[list(audit.CIC_REQUIRED) + ["label", "destination port"]]
    opposite = base.copy()
    opposite["label"] = np.where(base.label == "BENIGN", "DoS", "BENIGN")
    path = save_raw(tmp_path, "cic_ids2017", pd.concat([base, opposite], ignore_index=True))
    result = audit.audit_cic_ids2017(tmp_path, tmp_path / "out", seed=17, chunksize=7,
                                    sample_n=40, example_groups=1, examples_per_class=1)
    _, _, source = LOADERS["cic_ids2017"](path.parent, seed=17, sample_n=40, chunksize=7)
    selected = set(source["metadata"].source_row_index)
    expected = {i for i in selected if (i + 60 if i < 60 else i - 60) in selected}
    observed = {r["source_row_index"] for group in result["sample_reproduction"]["conflicts"] for r in group["rows"]}
    assert expected and observed == expected


def test_cli_completes_fresh_run_and_does_not_claim_training_ready(tmp_path):
    data = write_datasets(tmp_path / "raw", n=80)
    output = tmp_path / "out"
    args = ["--data-root", str(data), "--output-dir", str(output), "--seed", "17",
            "--sample-n", "80", "--sample-per-domain", "60", "--chunksize", "9",
            "--example-groups", "1", "--include-omni",
            "--previous-preflight", str(tmp_path / "absent.json")]
    assert audit.main(args) == 0
    result = json.loads((output / "audit_summary.json").read_text())
    assert result["audit_status"] == "COMPLETED"
    assert result["training_readiness"] == "NOT_ESTABLISHED_BY_AUDIT"
    assert result["source_stability"]["status"] == "ALL_MATCH"
    assert result["source_stability"]["matched_count"] == 3
    assert result["omni_reproduction"]["status"] == "READY"
    assert result["omni_reproduction"]["seed"] == 17
    with pytest.raises(FileExistsError):
        audit.main(args)


def test_cli_records_failed_domain_and_completes_other_audit(tmp_path):
    save_raw(tmp_path, "bot_iot", bot_rows(80))
    output = tmp_path / "out"
    assert audit.main(["--data-root", str(tmp_path), "--output-dir", str(output),
                       "--sample-n", "80", "--sample-per-domain", "60",
                       "--previous-preflight", str(tmp_path / "absent.json")]) == 1
    result = json.loads((output / "audit_summary.json").read_text())
    assert result["audit_status"] == "FAILED"
    assert "bot_iot" in result["domains"] and "cic_ids2017" in result["errors"]
    assert result["omni_reproduction"]["status"] == "NOT_RUN"
