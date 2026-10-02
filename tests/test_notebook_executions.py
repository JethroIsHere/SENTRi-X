"""Execute all rewritten notebooks on isolated synthetic data and outputs."""
import argparse
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
from tests.synthetic_data import write_datasets

ROOT_DIR = Path(__file__).resolve().parent.parent
NOTEBOOKS_DIR = ROOT_DIR / "notebooks"


@pytest.mark.parametrize("nb_filename", [
    "01_ETL_Pipeline_ToN_IoT.ipynb", "03_Model_Training_CNN_ToN_IoT.ipynb",
    "04_Hybrid_Ensemble_Fusion_ToN_IoT.ipynb", "06_Universal_Schema_Mapper.ipynb",
    "07_Cross_Validation_BoT_IoT.ipynb", "10_Omni_Model_Training.ipynb",
])
def test_notebook_execution(nb_filename):
    from contextlib import ExitStack
    from sentrix_ml.datasets import LOADERS
    import sentrix_ml.train_omni as omni
    original_omni = omni.run_train_omni
    nb_path = NOTEBOOKS_DIR / nb_filename
    nb_data = json.loads(nb_path.read_text(encoding="utf-8"))
    old_cwd = Path.cwd()
    try:
        os.chdir(NOTEBOOKS_DIR)
        with tempfile.TemporaryDirectory(prefix="sentrix-notebook-") as td, ExitStack() as stack:
            raw_root = write_datasets(Path(td) / "raw", n=400)
            def isolated_omni(args):
                values = dict(vars(args), data_root=str(raw_root), output_dir=str(Path(td) / "candidate"))
                return original_omni(argparse.Namespace(**values))
            stack.enter_context(patch.object(omni, "run_train_omni", side_effect=isolated_omni))
            for domain, loader in list(LOADERS.items()):
                def isolated_loader(*args, original=loader, domain_name=domain, **kwargs):
                    return original(raw_root / domain_name, **kwargs)
                stack.enter_context(patch(f"sentrix_ml.adapters.{domain}.load_{domain}", side_effect=isolated_loader))
            ns = {"__file__": str(nb_path), "__name__": "__main__"}
            for i, cell in enumerate(nb_data["cells"]):
                if cell["cell_type"] == "code":
                    source = "".join(cell["source"])
                    exec(compile(source, f"{nb_filename}:cell{i}", "exec"), ns)
    finally:
        os.chdir(old_cwd)
