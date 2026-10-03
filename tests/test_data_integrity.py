"""Regressions for the bbea010 review: record identity, lineage and support."""
import json
import numpy as np
import pandas as pd
import pytest
from sentrix_ml.datasets import LOADERS
from sentrix_ml.splits import stratified_split, adaptation_split, PartitionSupportError
from sentrix_ml.balancing import balance_training_rows
from sentrix_ml.preflight import check_bot_iot
from tests.synthetic_data import ton_rows, bot_rows, cic_rows


@pytest.mark.parametrize("domain,maker,filename,marker", [
    ("ton_iot", ton_rows, "Network_dataset_1.csv", "duration"),
    ("bot_iot", bot_rows, "UNSW_2018_IoT_Botnet_Full5pc_1.csv", "dur"),
    ("cic_ids2017", cic_rows, "Monday_fixture.csv", "Flow Duration"),
])
def test_chunk_row_ids_resolve_to_raw_records(tmp_path, domain, maker, filename, marker):
    raw = maker(32)
    raw.loc[6, marker] = -1  # Excluded raw row must not renumber subsequent records.
    raw.to_csv(tmp_path / filename, index=False)
    X, y, info = LOADERS[domain](tmp_path, chunksize=5, sample_n=19, seed=42)
    for (_, features), record in zip(X.iterrows(), info["metadata"].to_dict("records")):
        row = record["source_row_index"]
        assert 0 <= row < 32 and row != 6
        expected = raw.loc[row, marker] / (1e6 if domain == "cic_ids2017" else 1)
        assert features.duration == pytest.approx(expected)
        assert info["source_file_hashes"][filename] == record["source_file_hash"]
        assert record["source_flow_id"].endswith(f":row:{row}")
    _, _, other = LOADERS[domain](tmp_path, chunksize=11, sample_n=19, seed=42)
    assert info["metadata"].source_flow_id.tolist() == other["metadata"].source_flow_id.tolist()
    assert info["metadata"].duplicate_id.tolist() == other["metadata"].duplicate_id.tolist()


def test_reused_tuple_preserves_distinct_sessions_and_labels(tmp_path):
    raw = ton_rows(200)
    raw["src_port"] = 5000
    raw.to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = LOADERS["ton_iot"](tmp_path, sample_n=200)
    for splitter in (stratified_split, adaptation_split):
        parts = splitter(X, y, metadata=info["metadata"], require_class_support=True)
        assert sum(map(len, parts[:3])) == 200
        assert sum(int(labels.sum()) for labels in parts[3:6]) == 100
        assert parts[-1].duplicate_rows_excluded == 0


def test_true_raw_duplicates_removed_without_identifiers(tmp_path):
    raw = ton_rows(100).drop(columns=["src_ip", "src_port", "dst_ip", "dst_port"])
    copies = pd.concat([raw] * 3, ignore_index=True)
    copies.to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = LOADERS["ton_iot"](tmp_path)
    parts = stratified_split(X, y, metadata=info["metadata"], require_class_support=True)
    assert sum(map(len, parts[:3])) == 100
    assert parts[-1].duplicate_rows_excluded == 200
    groups = [set(getattr(parts[-1], p + "_group_ids")) for p in ("train", "val", "test")]
    assert not (groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])


def test_group_retains_distinct_measurements_together(tmp_path):
    raw = ton_rows(200)
    raw["ts"] = np.arange(200) // 4
    raw["src_port"] = 5000  # Four distinct rows per session, including both labels.
    raw.to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = LOADERS["ton_iot"](tmp_path)
    parts = stratified_split(X, y, metadata=info["metadata"], require_class_support=True)
    assert sum(map(len, parts[:3])) == 200
    for group in info["metadata"].group_id.unique():
        assert sum(group in set(getattr(parts[-1], p + "_group_ids")) for p in ("train", "val", "test")) == 1


def test_conflicting_duplicate_labels_resolved_by_dedup(tmp_path):
    """Conflicting labels on identical raw records are resolved by keep-first dedup.

    Previously this raised ValueError.  Now it warns and deduplicates, keeping
    the first label encountered — matching the CIC-IDS2017 measurement fingerprint
    collision handling.
    """
    raw = ton_rows(100)
    conflict = raw.iloc[[0]].copy(); conflict["label"] = 1
    pd.concat([raw, conflict]).to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = LOADERS["ton_iot"](tmp_path)
    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        parts = stratified_split(X, y, metadata=info["metadata"], require_class_support=True)
        conflict_warnings = [x for x in w if "conflicting labels" in str(x.message)]
        assert len(conflict_warnings) >= 1, "Expected a warning about conflicting labels"
    # The conflict row is deduplicated; first occurrence's label is kept
    manifest = parts[-1]
    assert manifest.duplicate_rows_excluded >= 1
    assert manifest.exclusion_reasons.get("conflicting_label_duplicates_resolved", 0) >= 1
    # All partitions should still be disjoint
    groups = [set(getattr(manifest, p + "_group_ids")) for p in ("train", "val", "test")]
    assert not (groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])


def test_equal_features_without_identity_are_not_deleted():
    X = pd.DataFrame({"duration": [1.] * 200})
    y = pd.Series([0, 1] * 100)
    parts = stratified_split(X, y, require_class_support=True)
    assert sum(map(len, parts[:3])) == 200
    assert parts[-1].identity_policy == "source_identity_only"


def test_rare_class_preflight_blocks_before_fitting(tmp_path):
    raw = bot_rows(3000); raw["attack"] = 1; raw.loc[:3, "attack"] = 0
    raw.to_csv(tmp_path / "UNSW_2018_IoT_Botnet_Full5pc_1.csv", index=False)
    result = check_bot_iot(tmp_path, sample_n=3000)
    assert result["status"] == "FAILED"
    assert "group" in result["error"].lower() or "class" in result["error"].lower()


def test_balancing_only_duplicates_original_training_rows():
    X = np.arange(80).reshape(20, 4); y = np.array([0] * 4 + [1] * 16)
    before = X.copy()
    sampled, labels, audit = balance_training_rows(X, y, seed=42)
    np.testing.assert_array_equal(X, before)
    assert dict(zip(*np.unique(labels, return_counts=True))) == {0: 16, 1: 16}
    assert all(tuple(row) in set(map(tuple, X)) for row in sampled)
    again, _, again_audit = balance_training_rows(X, y, seed=42)
    np.testing.assert_array_equal(sampled, again)
    assert audit == again_audit and not audit["validation_test_resampled"]


def test_stratified_reservoir_guarantees_minority_class(tmp_path):
    """StratifiedReservoirBuffer must include ALL minority records in the sample.

    Simulates a BoT-IoT-like scenario: 3000 rows with only 20 benign (0.67%).
    Under uniform Algorithm R, many benign rows would be lost. The stratified
    buffer must preserve all 20.
    """
    from sentrix_ml.sampler import StratifiedReservoirBuffer

    raw = bot_rows(3000)
    raw["attack"] = 1
    raw.loc[:19, "attack"] = 0  # 20 benign rows
    raw.to_csv(tmp_path / "UNSW_2018_IoT_Botnet_Full5pc_1.csv", index=False)

    X, y, info = LOADERS["bot_iot"](tmp_path, sample_n=500, seed=42)
    benign_count = int((y == 0).sum())
    # All 20 benign rows must be in the 500-row sample
    assert benign_count == 20, f"Expected 20 benign rows, got {benign_count}"
    assert len(y) == 500
    # Verify metadata tracks stratified policy
    assert info.get("selection_policy") == "stratified_reservoir_sampling"
    assert info.get("minority_records_collected") == 20


def test_stratified_reservoir_deterministic_seed(tmp_path):
    """Stratified reservoir must produce identical results for the same seed."""
    raw = bot_rows(1000)
    raw["attack"] = 1
    raw.loc[:9, "attack"] = 0  # 10 benign rows
    raw.to_csv(tmp_path / "UNSW_2018_IoT_Botnet_Full5pc_1.csv", index=False)

    X1, y1, _ = LOADERS["bot_iot"](tmp_path, sample_n=200, seed=99)
    X2, y2, _ = LOADERS["bot_iot"](tmp_path, sample_n=200, seed=99)
    pd.testing.assert_frame_equal(X1, X2)
    pd.testing.assert_series_equal(y1, y2)


def test_mixed_label_fingerprint_groups_split_correctly():
    """Mixed-label measurement groups must split without error.

    Simulates CIC-IDS2017 scenario: rows with identical measurement fingerprints
    (same group_id) but different labels.
    Under retain-and-group (default):
    1. Warns about conflicting labels
    2. Retains ALL original observations and original labels (no keep-first deletion)
    3. Partitions whole measurement groups into disjoint splits
    """
    n_groups = 30
    rows_per_group = 6
    n_rows = n_groups * rows_per_group
    rng = np.random.default_rng(42)
    X = pd.DataFrame(rng.standard_normal((n_rows, 3)), columns=["a", "b", "c"])
    # Each group has 3 benign + 3 attack rows (mixed-label fingerprint).
    labels = []
    for g in range(n_groups):
        if g % 2 == 0:
            labels.extend([0] * 3 + [1] * 3)
        else:
            labels.extend([1] * 3 + [0] * 3)
    y = pd.Series(labels, dtype=int)
    meta = pd.DataFrame({
        "source_flow_id": [f"cic:{i}" for i in range(n_rows)],
        "duplicate_id": [f"fp:{i // rows_per_group}" for i in range(n_rows)],
        "group_id": [f"fp:{i // rows_per_group}" for i in range(n_rows)],
    })

    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        parts = stratified_split(X, y, metadata=meta, require_class_support=True, conflict_policy="retain_and_group")
        conflict_warnings = [x for x in w if "conflicting labels" in str(x.message)]
        assert len(conflict_warnings) >= 1

    manifest = parts[-1]
    # Under retain-and-group, all observations are retained with their original labels
    total_rows = sum(map(len, parts[:3]))
    assert total_rows == n_rows  # All 180 rows retained!
    assert manifest.duplicate_rows_excluded == 0
    assert manifest.exclusion_reasons.get("conflicting_label_groups_retained", 0) == n_rows
    # Partitions must be disjoint
    groups = [set(getattr(manifest, p + "_group_ids")) for p in ("train", "val", "test")]
    assert not (groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])

    # Also test legacy keep_first policy when explicitly requested
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        parts_kf = stratified_split(X, y, metadata=meta, require_class_support=True, conflict_policy="keep_first")
        assert sum(map(len, parts_kf[:3])) == n_groups
        assert parts_kf[-1].duplicate_rows_excluded == n_rows - n_groups

