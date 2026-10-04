"""ToN rebuild regressions and real notebook execution on isolated fixture data."""
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.splits import stratified_split
from sentrix_ml.train_source import split_source_data
from sentrix_ml.evaluation import compute_multimode_metrics, save_prediction_evidence
from tests.synthetic_data import ton_rows

ROOT = Path(__file__).resolve().parents[1]


def test_source_retains_rare_mixed_group_and_preflight_agrees(tmp_path):
    from sentrix_ml.adapters.ton_iot import load_ton_iot
    from sentrix_ml.preflight import check_ton_iot

    data = ton_rows(198)
    duplicate = data.iloc[[0]].copy()
    duplicate["label"] = 1  # Same observed session, different original annotation.
    raw = pd.concat([data, duplicate], ignore_index=True)
    raw.to_csv(tmp_path / "Network_dataset_1.csv", index=False)
    X, y, info = load_ton_iot(tmp_path, sample_n=300, seed=42)
    with pytest.warns(UserWarning, match="conflicting labels"):
        parts = split_source_data(X, y, info)
    manifest = parts[-1]
    assert sum(map(len, parts[:3])) == len(raw)
    assert manifest.duplicate_rows_excluded == 0
    assert manifest.conflict_policy == "retain_and_group"
    assert manifest.duplicate_group_policy == "retain_and_group_disjoint"
    for features, labels in zip(parts[:3], parts[3:6]):
        pd.testing.assert_series_equal(labels, y.loc[features.index])
    sets = [set(getattr(manifest, p + "_group_ids")) for p in ("train", "val", "test")]
    assert all(sets[i].isdisjoint(sets[j]) for i, j in ((0, 1), (0, 2), (1, 2)))
    with pytest.warns(UserWarning, match="conflicting labels"):
        again = split_source_data(X, y, info)[-1]
    assert again.train_flow_ids == manifest.train_flow_ids
    assert again.val_flow_ids == manifest.val_flow_ids
    assert again.test_flow_ids == manifest.test_flow_ids
    with pytest.warns(UserWarning, match="conflicting labels"):
        preflight = check_ton_iot(tmp_path, sample_n=300, seed=42)
    assert preflight["status"] == "READY"
    assert preflight["partition_class_counts"] == manifest.partition_support
    assert preflight["duplicate_group_policy"] == manifest.duplicate_group_policy


def test_explicit_policy_is_reflected_and_contradictions_fail():
    X = pd.DataFrame({"x": np.arange(100)})
    y = pd.Series(np.arange(100) % 2)
    manifest = stratified_split(X, y, conflict_policy="retain_and_group")[-1]
    assert manifest.duplicate_group_policy == "retain_and_group_disjoint"
    with pytest.raises(ValueError, match="Contradictory"):
        stratified_split(X, y, duplicate_group_policy="keep_first_disjoint",
                         conflict_policy="retain_and_group")
    with pytest.raises(ValueError, match="Unsupported conflict_policy"):
        stratified_split(X, y, conflict_policy="typo")


@pytest.mark.parametrize("with_lineage", [False, True])
def test_saved_probabilities_reproduce_decisions_near_threshold(tmp_path, with_lineage):
    probabilities = np.array([.49999999, .50000001, 1e-12, .999999999999])
    extras = dict(source_files=["raw.csv"] * 4, inclusion_probabilities=[1e-12] * 4) if with_lineage else {}
    path = tmp_path / "evidence.csv"
    save_prediction_evidence(path, y_true=np.array([0, 1, 0, 1]), p_rf=probabilities,
                             p_cnn=probabilities, p_hybrid=probabilities, **extras)
    evidence = pd.read_csv(path, float_precision="round_trip")
    for mode in ("rf", "cnn", "hybrid"):
        np.testing.assert_array_equal(evidence[f"p_{mode}"], probabilities)
        np.testing.assert_array_equal(evidence[f"pred_{mode}"], evidence[f"p_{mode}"] >= .5)
    if with_lineage:
        assert (evidence.inclusion_probability > 0).all()


@pytest.mark.parametrize("working_directory", ["root", "notebooks"])
def test_real_baseline_notebook(tmp_path, working_directory):
    """Execute every Python cell in a fresh process and verify real model artifacts.

    Only run configuration is overridden: generated CSV path, tiny declared training
    budget and temporary outputs. No loader, trainer, prediction or export is mocked.
    """
    pytest.importorskip("tensorflow", reason="Notebook smoke must use a real CNN")
    nbformat = pytest.importorskip("nbformat")
    from sentrix_ml.packaging import validate_package, PackageValidationError

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    ton_rows(400).to_csv(raw_dir / "Network_dataset_1.csv", index=False)
    candidate = tmp_path / "candidate"
    report_dir = tmp_path / "run"
    notebook = nbformat.read(ROOT / "notebooks/01_ToN_IoT_Baseline.ipynb", as_version=4)
    for cell in notebook.cells:
        if "parameters" in cell.metadata.get("tags", []):
            cell.source += (
                f"\nargs.data_dir = {str(raw_dir)!r}\nargs.output_dir = {str(candidate)!r}"
                f"\nRUN_DIR = Path({str(report_dir)!r})"
                "\nargs.sample_n = 200\nargs.rf_estimators = 3\nargs.batch_size = 32"
            )

    # The notebook uses Python cells only. A subprocess gives a clean namespace
    # without depending on Jupyter kernel sockets (unavailable in some CI hosts).
    configured = tmp_path / "configured.ipynb"
    nbformat.write(notebook, configured)
    runner = r"""
import contextlib, io, json, sys
from pathlib import Path
path = Path(sys.argv[1])
notebook = json.loads(path.read_text())
namespace = {"__name__": "__main__"}
executed = 0
for i, cell in enumerate(notebook["cells"]):
    if cell["cell_type"] != "code":
        continue
    source = "".join(cell["source"])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(source, f"{path.name}:cell{i}", "exec"), namespace)
    executed += 1
    cell["execution_count"] = executed
    cell["outputs"] = [{"output_type": "stream", "name": "stdout", "text": output.getvalue()}]
    print(output.getvalue(), flush=True)
path.with_name("executed.ipynb").write_text(json.dumps(notebook))
"""
    cwd = ROOT if working_directory == "root" else ROOT / "notebooks"
    result = subprocess.run([sys.executable, "-c", runner, str(configured)],
        cwd=cwd, env=dict(os.environ, MPLBACKEND="Agg"), capture_output=True, text=True, timeout=180)
    (tmp_path / "execution.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    executed = nbformat.read(tmp_path / "executed.ipynb", as_version=4)
    nbformat.validate(executed)
    assert all(c.execution_count is not None for c in executed.cells if c.cell_type == "code")
    package = validate_package(candidate)
    assert not package.is_mock and package.evaluation_run_type == "smoke"
    assert package.training_config["protocol"] == "ton_baseline_v1"
    with pytest.raises(PackageValidationError, match="smoke"):
        validate_package(candidate, strict_deployable=True)
    split = json.loads((candidate / "split_manifest.json").read_text())
    evidence = pd.read_csv(candidate / "prediction_evidence.csv", float_precision="round_trip")
    assert evidence.sample_id.tolist() == split["test_flow_ids"]
    assert evidence.group_id.tolist() == split["test_group_ids"]
    raw = pd.read_csv(raw_dir / "Network_dataset_1.csv")
    np.testing.assert_array_equal(evidence.y_true, raw.iloc[evidence.source_row_index].label)
    recomputed = compute_multimode_metrics(evidence.y_true, p_rf=evidence.p_rf,
        p_cnn=evidence.p_cnn, p_hybrid=evidence.p_hybrid)
    saved = json.loads((candidate / "evaluation_metrics.json").read_text())
    assert saved["modes"] == recomputed.modes
    assert saved["evaluation_split"] == "sampled_group_disjoint_holdout"
    assert saved["weighted_modes"] == {}
    assert (report_dir / "cnn_training.png").stat().st_size > 0
    assert (report_dir / "holdout_confusion_matrices.png").stat().st_size > 0
