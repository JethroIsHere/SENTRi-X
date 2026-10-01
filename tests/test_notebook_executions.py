"""Test clean execution of all rewritten notebooks.

Guarantees:
* Executes code cells from fresh namespaces against the actual package interfaces.
* Verifies no import errors, signature errors, or data loading crashes occur.
"""

import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
NOTEBOOKS_DIR = ROOT_DIR / "notebooks"


def _execute_notebook(nb_filename: str):
    nb_path = NOTEBOOKS_DIR / nb_filename
    assert nb_path.exists(), f"Notebook not found: {nb_path}"

    with open(nb_path, "r", encoding="utf-8") as f:
        nb_data = json.load(f)

    # Ensure working directory is NOTEBOOKS_DIR just like a Jupyter kernel
    old_cwd = os.getcwd()
    os.chdir(NOTEBOOKS_DIR)
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))

    from unittest.mock import patch
    import sentrix_ml.adapters.ton_iot
    import sentrix_ml.adapters.bot_iot
    import sentrix_ml.adapters.cic_ids2017

    orig_load_ton = sentrix_ml.adapters.ton_iot.load_ton_iot
    orig_load_bot = sentrix_ml.adapters.bot_iot.load_bot_iot
    orig_load_cic = sentrix_ml.adapters.cic_ids2017.load_cic_ids2017

    def _bounded_load_ton(*args, **kwargs):
        kwargs.setdefault("nrows_per_file", 200)
        return orig_load_ton(*args, **kwargs)

    def _bounded_load_bot(*args, **kwargs):
        kwargs.setdefault("nrows_per_file", 200)
        return orig_load_bot(*args, **kwargs)

    def _bounded_load_cic(*args, **kwargs):
        kwargs.setdefault("nrows_per_file", 200)
        return orig_load_cic(*args, **kwargs)

    try:
        # Fresh isolated namespace for the notebook execution
        ns = {
            "__file__": str(nb_path),
            "__name__": "__main__",
        }

        with patch("sentrix_ml.adapters.ton_iot.load_ton_iot", side_effect=_bounded_load_ton), \
             patch("sentrix_ml.adapters.bot_iot.load_bot_iot", side_effect=_bounded_load_bot), \
             patch("sentrix_ml.adapters.cic_ids2017.load_cic_ids2017", side_effect=_bounded_load_cic):
            # Execute cells in sequence
            for i, cell in enumerate(nb_data.get("cells", [])):
                if cell.get("cell_type") == "code":
                    source_lines = cell.get("source", [])
                    code = "".join(source_lines)
                    if not code.strip():
                        continue
                    try:
                        exec(compile(code, f"{nb_filename}_cell_{i}", "exec"), ns)
                    except Exception as e:
                        raise RuntimeError(f"Error in {nb_filename} cell {i}:\n{code}\n--> Error: {e}") from e
    finally:
        os.chdir(old_cwd)


def test_notebook_01_etl_ton_iot():
    _execute_notebook("01_ETL_Pipeline_ToN_IoT.ipynb")


def test_notebook_03_cnn_ton_iot():
    _execute_notebook("03_Model_Training_CNN_ToN_IoT.ipynb")


def test_notebook_04_hybrid_fusion_ton_iot():
    _execute_notebook("04_Hybrid_Ensemble_Fusion_ToN_IoT.ipynb")


def test_notebook_06_universal_schema_mapper():
    _execute_notebook("06_Universal_Schema_Mapper.ipynb")


def test_notebook_07_cross_validation_bot_iot():
    _execute_notebook("07_Cross_Validation_BoT_IoT.ipynb")


def test_notebook_10_omni_training():
    try:
        _execute_notebook("10_Omni_Model_Training.ipynb")
    finally:
        import shutil
        shutil.rmtree(ROOT_DIR / "models" / "candidates" / "omni_smoke_nb", ignore_errors=True)


if __name__ == "__main__":
    print("Testing notebook executions...")
    test_notebook_01_etl_ton_iot()
    print("Notebook 01 passed!")
    test_notebook_03_cnn_ton_iot()
    print("Notebook 03 passed!")
    test_notebook_04_hybrid_fusion_ton_iot()
    print("Notebook 04 passed!")
    test_notebook_06_universal_schema_mapper()
    print("Notebook 06 passed!")
    test_notebook_07_cross_validation_bot_iot()
    print("Notebook 07 passed!")
    test_notebook_10_omni_training()
    print("Notebook 10 passed!")
    print("All 6 rewritten notebooks executed cleanly without errors!")
