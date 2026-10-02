"""Deterministic, non-research raw fixtures; never copy or mutate user datasets."""
from pathlib import Path
import numpy as np
import pandas as pd


def ton_rows(n=400):
    i = np.arange(n)
    return pd.DataFrame({"duration": i + .25, "src_bytes": 100 + i * 7,
        "dst_bytes": 20 + i * 3, "src_pkts": 1 + i % 10, "dst_pkts": 1 + i % 5,
        "src_ip_bytes": 140 + i * 7, "dst_ip_bytes": 60 + i * 3,
        "proto": "tcp", "conn_state": "SF", "label": i % 2,
        "ts": 1700000000 + i, "src_ip": "192.168.1.2", "src_port": 10000 + i % 1000,
        "dst_ip": "192.168.1.3", "dst_port": 80})


def bot_rows(n=400):
    df = ton_rows(n).rename(columns={"duration": "dur", "src_bytes": "sbytes", "dst_bytes": "dbytes",
        "src_pkts": "spkts", "dst_pkts": "dpkts", "label": "attack", "conn_state": "state",
        "src_ip_bytes": "TnBPSrcIP", "dst_ip_bytes": "TnBPDstIP", "src_ip": "saddr", "src_port": "sport",
        "dst_ip": "daddr", "dst_port": "dport", "ts": "stime"})
    df["state"] = "CON"; df["pkSeqID"] = np.arange(n)
    return df


def cic_rows(n=400):
    df = ton_rows(n).rename(columns={"duration": "Flow Duration", "src_bytes": "Total Length of Fwd Packets",
        "dst_bytes": "Total Length of Bwd Packets", "src_pkts": "Total Fwd Packets",
        "dst_pkts": "Total Backward Packets", "label": "Label", "src_ip": "Source IP",
        "src_port": "Source Port", "dst_ip": "Destination IP", "dst_port": "Destination Port",
        "ts": "Timestamp", "proto": "Protocol"})
    df["Flow Duration"] *= 1e6; df["Protocol"] = 6
    df["Label"] = np.where(df.Label == 0, "BENIGN", "DoS")
    return df


def write_datasets(root, n=400):
    root = Path(root)
    for domain, data, filename in (
        ("ton_iot", ton_rows(n), "Network_dataset_1.csv"),
        ("bot_iot", bot_rows(n), "UNSW_2018_IoT_Botnet_Full5pc_1.csv"),
        ("cic_ids2017", cic_rows(n), "Monday_fixture.csv"),
    ):
        (root / domain).mkdir(parents=True, exist_ok=True)
        data.to_csv(root / domain / filename, index=False)
    return root
