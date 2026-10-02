"""Shared Omni ingestion contract for preflight and training."""
from pathlib import Path
import pandas as pd
from sentrix_ml.adapters.ton_iot import load_ton_iot
from sentrix_ml.adapters.bot_iot import load_bot_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
from sentrix_ml.provenance import sampling_audit


LOADERS = {"ton_iot": load_ton_iot, "bot_iot": load_bot_iot, "cic_ids2017": load_cic_ids2017}


def load_omni(data_root, *, sample_per_domain=30000, seed=42):
    features, labels, metadata = [], [], []
    info = {"source_file_hashes": {}, "exclusion_reasons": {}, "sampling_metadata": {}}
    for domain, loader in LOADERS.items():
        X, y, source = loader(Path(data_root) / domain, sample_n=sample_per_domain, seed=seed)
        features.append(X); labels.append(y); metadata.append(source["metadata"])
        info["source_file_hashes"].update({domain + "/" + k: v for k, v in source["source_file_hashes"].items()})
        info["sampling_metadata"][domain] = sampling_audit(source)
        for key, count in source["exclusion_reasons"].items():
            info["exclusion_reasons"][domain + "/" + key] = count
    info["metadata"] = pd.concat(metadata, ignore_index=True)
    return pd.concat(features, ignore_index=True), pd.concat(labels, ignore_index=True), info
