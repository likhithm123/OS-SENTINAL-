import numpy as np

# Feature Column Names
FEATURE_NAMES = [
    "cpu_percent",
    "mem_percent",
    "is_tmp_execution",
    "file_mod_rate",
    "avg_file_entropy",
    "outbound_conn_count",
    "suspicious_port_flag",
    "data_exfil_kb_sec",
    "spawn_rate",
    "file_deletion_rate"
]

def extract_feature_vector(proc_telemetry: dict, file_telemetry: dict, net_telemetry: dict) -> dict:
    """Extracts a structured numerical feature dictionary and NumPy array from raw telemetry."""
    
    cpu_percent = float(proc_telemetry.get("total_cpu_percent", 0.0))
    mem_percent = float(proc_telemetry.get("avg_cpu_percent", 0.0)) # Memory or avg load
    is_tmp_execution = 1.0 if proc_telemetry.get("tmp_execution_count", 0) > 0 else 0.0
    
    file_mod_rate = float(file_telemetry.get("file_mod_rate", 0.0))
    avg_file_entropy = float(file_telemetry.get("avg_file_entropy", 0.0))
    file_deletion_rate = float(file_telemetry.get("file_deletion_rate", 0.0))
    
    outbound_conn_count = float(net_telemetry.get("outbound_conn_count", 0))
    suspicious_port_flag = float(net_telemetry.get("suspicious_port_flag", 0))
    restricted_ip_flag = float(net_telemetry.get("restricted_ip_flag", 0))
    data_exfil_kb_sec = float(net_telemetry.get("data_exfil_kb_sec", 0.0))
    
    spawn_rate = float(proc_telemetry.get("spawn_rate", 0.0))
    
    feature_dict = {
        "cpu_percent": cpu_percent,
        "mem_percent": mem_percent,
        "is_tmp_execution": is_tmp_execution,
        "file_mod_rate": file_mod_rate,
        "avg_file_entropy": avg_file_entropy,
        "outbound_conn_count": outbound_conn_count,
        "suspicious_port_flag": suspicious_port_flag,
        "restricted_ip_flag": restricted_ip_flag,
        "data_exfil_kb_sec": data_exfil_kb_sec,
        "spawn_rate": spawn_rate,
        "file_deletion_rate": file_deletion_rate,
        "browser_high_cpu_count": float(proc_telemetry.get("browser_high_cpu_count", 0)),
        "multiple_tabs_burst": 1.0 if proc_telemetry.get("multiple_tabs_burst") else 0.0,
        "new_tab_count": float(proc_telemetry.get("new_tab_count", 0)),
        "lineage_anomaly_count": float(proc_telemetry.get("lineage_anomaly_count", 0))
    }
    
    vector = np.array([feature_dict[name] for name in FEATURE_NAMES], dtype=np.float32)
    
    return {
        "feature_dict": feature_dict,
        "vector": vector,
        "feature_names": FEATURE_NAMES
    }
