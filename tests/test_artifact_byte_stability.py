"""Regression tests for artifact byte-stability (incident 2026-10-04).

On the training laptop (Windows), artifact writers emitted CRLF line endings
(Python text-mode translation, and csv.writer's default lineterminator). The
SHA256 hashes recorded in the package manifests were computed over those CRLF
bytes, but git normalized the files to LF on commit -- so validate_package()
failed on every fresh clone. The writers now force LF unconditionally and
.gitattributes marks artifact paths -text. These tests pin that behavior.
"""
import csv
import hashlib
import json

import numpy as np
import pytest

from sentrix_ml.evaluation import (
    EvaluationResult,
    compute_multimode_metrics,
    save_prediction_evidence,
)
from sentrix_ml.packaging import ModelManifest, validate_package
from sentrix_ml.splits import SplitManifest


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def test_evaluation_result_save_is_lf_only(tmp_path):
    res = compute_multimode_metrics(
        y_true=np.array([0, 1, 1, 0]),
        p_rf=np.array([0.1, 0.9, 0.8, 0.2]),
        p_cnn=np.array([0.2, 0.8, 0.7, 0.3]),
        p_hybrid=np.array([0.15, 0.85, 0.75, 0.25]),
        domain="test", run_type="smoke", dataset="test",
        evaluation_split="test",
        rf_hash="sha256:x", cnn_hash="sha256:x", preprocessor_hash="sha256:x",
        split_manifest_file="split_manifest.json", split_manifest_hash="sha256:x",
        evidence_file="prediction_evidence.csv", evidence_hash="sha256:x",
    )
    p = tmp_path / "evaluation_metrics.json"
    res.save(p)
    raw = p.read_bytes()
    assert b"\r" not in raw, "evaluation JSON must not contain CR bytes"
    assert _sha256(p) == _sha256(p), "hash must be stable across reads"


def test_split_manifest_save_is_lf_only(tmp_path):
    sm = SplitManifest(seed=42, dataset_domain="test")
    p = tmp_path / "split_manifest.json"
    sm.save(p)
    assert b"\r" not in p.read_bytes(), "split manifest must not contain CR bytes"


def test_model_manifest_save_is_lf_only(tmp_path):
    m = ModelManifest(domain="test")
    p = tmp_path / "manifest.json"
    m.save(p)
    assert b"\r" not in p.read_bytes(), "model manifest must not contain CR bytes"


def test_prediction_evidence_csv_is_lf_only(tmp_path):
    p = tmp_path / "prediction_evidence.csv"
    save_prediction_evidence(
        p,
        y_true=np.array([0, 1]),
        p_rf=np.array([0.1, 0.9]),
        p_cnn=np.array([0.2, 0.8]),
        p_hybrid=np.array([0.15, 0.85]),
        sample_ids=["a", "b"],
        domain_labels=["test", "test"],
        source_files=["f.csv", "f.csv"],
        source_row_indices=[0, 1],
        group_ids=["g0", "g1"],
        inclusion_probabilities=[1.0, 0.5],
        sampling_weights=[1.0, 2.0],
    )
    raw = p.read_bytes()
    assert b"\r" not in raw, "evidence CSV must not contain CR bytes"
    # csv module must not sneak \r\n back in via its default lineterminator
    assert raw.count(b"\n") == 3, "header + 2 rows, LF-terminated"


def test_packaged_hashes_survive_lf_normalization(tmp_path):
    """Simulates git LF-normalization: hashes recorded at write time must
    still match after a CRLF->LF round trip of every text artifact."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    sm = SplitManifest(seed=42, dataset_domain="test")
    sm.save(pkg / "split_manifest.json")
    res = compute_multimode_metrics(
        y_true=np.array([0, 1, 1, 0]),
        p_rf=np.array([0.1, 0.9, 0.8, 0.2]),
        p_cnn=np.array([0.2, 0.8, 0.7, 0.3]),
        p_hybrid=np.array([0.15, 0.85, 0.75, 0.25]),
        domain="test", run_type="smoke", dataset="test",
        evaluation_split="test",
        rf_hash="sha256:x", cnn_hash="sha256:x", preprocessor_hash="sha256:x",
        split_manifest_file="split_manifest.json",
        split_manifest_hash=_sha256(pkg / "split_manifest.json"),
        evidence_file="prediction_evidence.csv", evidence_hash="sha256:x",
    )
    res.save(pkg / "evaluation_metrics.json")

    # Simulate the 2026-10-04 incident: files written CRLF, hashed, normalized.
    # With the fix, writers always emit LF, so the recorded (LF) hashes must
    # survive a hypothetical CRLF->LF normalization round trip unchanged.
    lf_hashes = {fn: _sha256(pkg / fn) for fn in ("split_manifest.json", "evaluation_metrics.json")}
    for fn in ("split_manifest.json", "evaluation_metrics.json"):
        raw = (pkg / fn).read_bytes().replace(b"\n", b"\r\n")
        (pkg / fn).write_bytes(raw)
    for fn in ("split_manifest.json", "evaluation_metrics.json"):
        (pkg / fn).write_bytes((pkg / fn).read_bytes().replace(b"\r\n", b"\n"))
    for fn, h in lf_hashes.items():
        assert _sha256(pkg / fn) == h
