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


def test_conflicting_duplicate_labels_rejected(tmp_path):
    raw = ton_rows(100)
    conflict = raw.iloc[[0]].copy(); conflict["label"] = 1
    pd.concat([raw, conflict]).to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = LOADERS["ton_iot"](tmp_path)
    with pytest.raises(ValueError, match="conflicting labels"):
        stratified_split(X, y, metadata=info["metadata"])


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
