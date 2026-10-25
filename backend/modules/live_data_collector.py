import os
import time
import pandas as pd
from pathlib import Path
from backend.config import DATA_DIR
from backend.modules.module1_process import collect_process_telemetry
from backend.modules.module2_file import collect_file_telemetry
from backend.modules.module3_network import collect_network_telemetry
from backend.modules.module4_feature_extraction import extract_feature_vector, FEATURE_NAMES

LIVE_DATASET_PATH = DATA_DIR / "real_host_telemetry_live.csv"

def record_live_telemetry_sample(label: str = "Normal") -> dict:
    """
    Samples real-time host telemetry from the local operating system
    and appends the 10-feature vector to real_host_telemetry_live.csv.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    
    proc_data = collect_process_telemetry()
    file_data = collect_file_telemetry()
    net_data = collect_network_telemetry()
    
    feat_out = extract_feature_vector(proc_data, file_data, net_data)
    feat_dict = feat_out["feature_dict"]
    
    row = {name: feat_dict.get(name, 0.0) for name in FEATURE_NAMES}
    row["label"] = label
    row["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    df_new = pd.DataFrame([row])
    
    if not LIVE_DATASET_PATH.exists():
        df_new.to_csv(LIVE_DATASET_PATH, index=False)
    else:
        df_new.to_csv(LIVE_DATASET_PATH, mode="a", header=False, index=False)
        
    return row

def collect_live_dataset_batch(num_samples: int = 50, interval_sec: float = 0.5, label: str = "Normal") -> dict:
    """
    Collects a batch of real-time machine telemetry samples at specified intervals.
    """
    collected = []
    for _ in range(num_samples):
        sample = record_live_telemetry_sample(label=label)
        collected.append(sample)
        time.sleep(interval_sec)
        
    return {
        "status": "SUCCESS",
        "samples_collected": len(collected),
        "target_file": str(LIVE_DATASET_PATH),
        "sample_preview": collected[0] if collected else {}
    }

def get_live_dataset_stats() -> dict:
    """Returns statistics and record count of the live telemetry dataset."""
    if not LIVE_DATASET_PATH.exists():
        return {
            "exists": False,
            "total_records": 0,
            "path": str(LIVE_DATASET_PATH),
            "labels": {}
        }
    try:
        df = pd.read_csv(LIVE_DATASET_PATH)
        return {
            "exists": True,
            "total_records": len(df),
            "path": str(LIVE_DATASET_PATH),
            "labels": df["label"].value_counts().to_dict(),
            "latest_record": df.iloc[-1].to_dict() if len(df) > 0 else {}
        }
    except Exception as e:
        return {"exists": False, "error": str(e)}
