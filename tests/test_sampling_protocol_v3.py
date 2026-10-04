"""v3 sampling protocol regression tests (REVISED_SAMPLING_PROPOSAL.md).

Covers:
1. retain_and_group_disjoint is the default duplicate-group policy; mixed-label
   measurement groups are retained whole, never keep-first deleted.
2. keep_first_disjoint remains available as an explicitly requested
   sensitivity-analysis option (and only then deletes).
3. Rare (singleton-profile) groups use the deterministic seed-ordered dealing
   rule; allocation is reproducible and groups stay intact.
4. Infeasible class support is reported, never silently repaired.
5. Design weights / provenance flow from split-manifest records into
   prediction evidence and weighted metric variants.
6. /api metric formatting labels the evaluation population and metric variant.
"""

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.splits import (
    stratified_split,
    adaptation_split,
    PartitionSupportError,
    RARE_PROFILE_POLICY,
    SplitManifest,
)
from sentrix_ml.evaluation import (
    compute_multimode_metrics,
    eval_weights_from_manifest_records,
    eval_provenance_from_manifest_records,
    format_metrics_for_api,
    save_prediction_evidence,
)


def _mixed_label_frame(n_pure=120, n_mixed_groups=12, mixed_size=5, seed=0):
    """CIC-like fixture: pure singleton groups + mixed-label measurement groups."""
    rng = np.random.default_rng(seed)
    groups, labels = [], []
    gid = 0
    for i in range(n_pure):
        groups.append(f"pure{gid}")
        labels.append(i % 2)
        gid += 1
    for i in range(n_mixed_groups):
        for j in range(mixed_size):
            groups.append(f"mixed{gid}")
            labels.append(j % 2)
        gid += 1
    n = len(groups)
    X = pd.DataFrame(rng.normal(size=(n, 4)), columns=list("abcd"))
    y = pd.Series(labels)
    meta = pd.DataFrame({
        "source_flow_id": [f"cic:raw:{i}" for i in range(n)],
        "duplicate_id": [f"cic:raw:{i}" for i in range(n)],
        "group_id": groups,
        "domain": ["cic_ids2017"] * n,
        "source_file": ["f.csv"] * n,
        "source_file_hash": ["sha256:x"] * n,
        "source_row_index": list(range(n)),
        "inclusion_probability": [0.5] * n,
        "sampling_weight": [2.0 if lab == 0 else 1.0 for lab in labels],
    })
    return X, y, meta


def _partition_group_sets(manifest):
    tr = set(manifest.train_group_ids)
    va = set(manifest.val_group_ids)
    te = set(manifest.test_group_ids)
    return tr, va, te


def test_v3_retain_and_group_is_default():
    X, y, meta = _mixed_label_frame()
    _, _, _, _, _, _, manifest = stratified_split(
        X, y, metadata=meta, seed=42, domain="cic_ids2017",
        require_class_support=True, source_file_hashes={"f.csv": "sha256:x"},
    )
    assert manifest.duplicate_group_policy == "retain_and_group_disjoint"
    assert manifest.conflict_policy == "retain_and_group"
    # No source observation deleted for label conflict.
    assert manifest.exclusion_reasons.get("conflicting_label_groups_retained", 0) == 60
    assert "conflicting_label_duplicates_resolved" not in manifest.exclusion_reasons
    assert manifest.train_count + manifest.val_count + manifest.test_count == len(X)


def test_v3_mixed_groups_stay_intact_and_disjoint():
    X, y, meta = _mixed_label_frame()
    _, _, _, _, _, _, manifest = stratified_split(
        X, y, metadata=meta, seed=42, domain="cic_ids2017",
        require_class_support=True, source_file_hashes={"f.csv": "sha256:x"},
    )
    tr, va, te = _partition_group_sets(manifest)
    assert not (tr & va) and not (tr & te) and not (va & te)
    from collections import Counter
    counts = Counter(manifest.train_group_ids + manifest.val_group_ids + manifest.test_group_ids)
    mixed = [g for g in counts if g.startswith("mixed")]
    assert len(mixed) == 12
    assert all(counts[g] == 5 for g in mixed)


def test_v3_keep_first_opt_in_still_deletes_with_warning():
    # True identical raw records (shared duplicate_id) with conflicting labels:
    # the actual CIC-IDS2017 case. keep_first is an explicit opt-in only.
    rng = np.random.default_rng(9)
    groups, labels, dupids = [], [], []
    gid = 0
    for i in range(120):
        groups.append(f"pure{gid}")
        dupids.append(f"dup:pure{gid}")
        labels.append(i % 2)
        gid += 1
    for i in range(12):
        for j in range(5):
            groups.append(f"mixed{gid}")
            dupids.append(f"dup:mixed{gid}")  # identical raw record, 5 observations
            labels.append(j % 2)             # ... with conflicting labels
        gid += 1
    n = len(groups)
    X = pd.DataFrame(rng.normal(size=(n, 4)), columns=list("abcd"))
    y = pd.Series(labels)
    meta = pd.DataFrame({
        "source_flow_id": [f"cic:raw:{i}" for i in range(n)],
        "duplicate_id": dupids,
        "group_id": groups,
        "domain": ["cic_ids2017"] * n,
    })
    with pytest.warns(UserWarning, match="conflicting labels"):
        _, _, _, _, _, _, manifest = stratified_split(
            X, y, metadata=meta, seed=42, domain="cic_ids2017",
            duplicate_group_policy="keep_first_disjoint",
            require_class_support=True, source_file_hashes={"f.csv": "sha256:x"},
        )
    assert manifest.duplicate_group_policy == "keep_first_disjoint"
    assert manifest.conflict_policy == "keep_first"
    # keep-first deletes all but one row per conflicting raw identity.
    assert manifest.exclusion_reasons.get("conflicting_label_duplicates_resolved", 0) == 60
    assert manifest.train_count + manifest.val_count + manifest.test_count < n


def test_v3_rare_profile_dealing_is_deterministic():
    rng = np.random.default_rng(3)
    groups = [f"b{i}" for i in range(50)] + [f"a{i}" for i in range(50)] + ["rare1"]
    labels = [0] * 50 + [1] * 50 + [0]
    doms = ["d"] * 100 + ["rare_dom"]
    X = pd.DataFrame(rng.normal(size=(101, 3)), columns=list("abc"))
    y = pd.Series(labels)

    def mkmeta():
        return pd.DataFrame({
            "source_flow_id": [f"r:{i}" for i in range(101)],
            "duplicate_id": [f"r:{i}" for i in range(101)],
            "group_id": groups,
            "domain": doms,
        })

    kwargs = dict(seed=11, domain="omni", test_fraction=0.2, val_fraction=0.1,
                  source_file_hashes={"f": "h"})
    m1 = stratified_split(X, y, metadata=mkmeta(), **kwargs)[-1]
    m2 = stratified_split(X, y, metadata=mkmeta(), **kwargs)[-1]
    assert m1.rare_profile_policy == RARE_PROFILE_POLICY
    # The rare group is dealt once per _partition call it participates in
    # (test split, then validation split within the pool).
    assert m1.rare_singleton_groups_dealt >= 1
    assert m1.train_group_ids == m2.train_group_ids
    assert m1.val_group_ids == m2.val_group_ids
    assert m1.test_group_ids == m2.test_group_ids
    # The rare group landed in exactly one partition, intact.
    locations = [p for p, ids in (("train", m1.train_group_ids), ("val", m1.val_group_ids),
                                  ("test", m1.test_group_ids)) if "rare1" in ids]
    assert locations and len(locations) == 1


def test_v3_infeasible_support_is_reported_not_repaired():
    # Old BoT failure shape: hundreds of attack groups, a single benign group.
    rng = np.random.default_rng(4)
    groups = [f"a{i}" for i in range(200)] + ["only_benign"]
    labels = [1] * 200 + [0]
    X = pd.DataFrame(rng.normal(size=(201, 3)), columns=list("abc"))
    y = pd.Series(labels)
    meta = pd.DataFrame({
        "source_flow_id": [f"r:{i}" for i in range(201)],
        "duplicate_id": [f"r:{i}" for i in range(201)],
        "group_id": groups,
    })
    with pytest.raises(PartitionSupportError, match="lacks class support"):
        adaptation_split(X, y, metadata=meta, seed=42, domain="bot_iot",
                         study_fraction=0.20, val_fraction_of_study=0.10,
                         require_class_support=True,
                         source_file_hashes={"f": "h"})


def test_v3_eval_weights_from_records():
    records = [
        {"inclusion_probability": 0.5, "sampling_weight": 2.0},
        {"inclusion_probability": 1.0, "sampling_weight": 1.0},
        {},  # missing -> uniform defaults
        {"inclusion_probability": "bad", "sampling_weight": -3.0},  # invalid -> 1.0
    ]
    probs, weights = eval_weights_from_manifest_records(records)
    assert list(probs) == [0.5, 1.0, 1.0, 1.0]
    assert list(weights) == [2.0, 1.0, 1.0, 1.0]
    p0, w0 = eval_weights_from_manifest_records(None)
    assert len(p0) == 0 and len(w0) == 0
    prov = eval_provenance_from_manifest_records(
        [{"source_file": "a.csv"}, {}], "source_file", default="?")
    assert prov == ["a.csv", "?"]


def test_v3_weighted_metric_variants_are_labelled():
    rng = np.random.default_rng(5)
    n = 200
    y_true = np.array([0] * 100 + [1] * 100)
    p_rf = np.clip(rng.normal(0.3, 0.2, n), 0, 1)
    p_rf[100:] = np.clip(rng.normal(0.7, 0.2, 100), 0, 1)
    p_cnn = np.clip(p_rf + rng.normal(0, 0.05, n), 0, 1)
    p_hybrid = (p_rf + p_cnn) / 2
    weights = np.array([4.0] * 100 + [1.0] * 100)  # enriched minority

    res = compute_multimode_metrics(
        y_true, p_rf=p_rf, p_cnn=p_cnn, p_hybrid=p_hybrid,
        sample_weight=weights, population_weights={"0": 4.0, "1": 1.0},
        domain="bot_iot", run_type="full", dataset="bot_iot",
    )
    assert res.has_sampling_weights is True
    assert set(res.weighted_modes) == {"rf", "cnn", "hybrid"}
    # Weighted accuracy differs from the unweighted enriched-sample value.
    assert res.weighted_modes["hybrid"]["accuracy"] != pytest.approx(
        res.modes["hybrid"]["accuracy"])

    out = format_metrics_for_api(res, mode="hybrid", active_manifest=None)
    assert out["available"] is True
    assert out["metric_variant"] == "enriched_holdout_sample_unweighted"
    assert "population_metrics" in out
    assert out["population_metric_variant"] == "source_heldout_population_weighted"
    assert "live-network" in out["population_label"]
    assert out["has_sampling_weights"] is True

    # Uniform weights -> no population variant, plain empirical response.
    res2 = compute_multimode_metrics(
        y_true, p_rf=p_rf, p_cnn=p_cnn, p_hybrid=p_hybrid,
        sample_weight=np.ones(n), domain="bot_iot", run_type="full",
    )
    assert res2.has_sampling_weights is False
    out2 = format_metrics_for_api(res2, mode="hybrid", active_manifest=None)
    assert "population_metrics" not in out2


def test_v3_prediction_evidence_carries_weights(tmp_path):
    n = 50
    rng = np.random.default_rng(6)
    y_true = rng.integers(0, 2, n)
    p = rng.random(n)
    probs = np.full(n, 0.25)
    weights = np.where(y_true == 0, 4.0, 1.0)
    path = tmp_path / "evidence.csv"
    h = save_prediction_evidence(
        path, y_true=y_true, p_rf=p, p_cnn=p, p_hybrid=p,
        sample_ids=list(range(n)),
        source_files=["f.csv"] * n,
        source_row_indices=list(range(n)),
        group_ids=[f"g{i}" for i in range(n)],
        inclusion_probabilities=probs,
        sampling_weights=weights,
    )
    assert h.startswith("sha256:")
    import csv
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert "inclusion_probability" in rows[0] and "sampling_weight" in rows[0]
    assert float(rows[0]["sampling_weight"]) == (4.0 if y_true[0] == 0 else 1.0)
    assert float(rows[0]["inclusion_probability"]) == pytest.approx(0.25)


def test_v3_manifest_roundtrip_keeps_new_policy_fields(tmp_path):
    m = SplitManifest(
        seed=42, duplicate_group_policy="retain_and_group_disjoint",
        conflict_policy="retain_and_group",
        rare_profile_policy=RARE_PROFILE_POLICY, rare_singleton_groups_dealt=3,
    )
    p = tmp_path / "manifest.json"
    m.save(p)
    m2 = SplitManifest.load(p)
    assert m2.duplicate_group_policy == "retain_and_group_disjoint"
    assert m2.conflict_policy == "retain_and_group"
    assert m2.rare_profile_policy == RARE_PROFILE_POLICY
    assert m2.rare_singleton_groups_dealt == 3
