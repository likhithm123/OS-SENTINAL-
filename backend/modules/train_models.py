import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from backend.config import DATA_DIR, MODELS_DIR
from backend.database import get_db, init_db
from backend.modules.module4_feature_extraction import FEATURE_NAMES

def generate_synthetic_telemetry(num_samples=2500):
    """Generates balanced synthetic dataset representing baseline system operations & cyber attack patterns."""
    np.random.seed(42)
    
    # 1. Normal System Activity (70% of dataset)
    n_normal = int(num_samples * 0.70)
    normal_data = {
        "cpu_percent": np.random.uniform(5.0, 45.0, n_normal),
        "mem_percent": np.random.uniform(2.0, 15.0, n_normal),
        "is_tmp_execution": np.random.choice([0.0, 1.0], p=[0.98, 0.02], size=n_normal),
        "file_mod_rate": np.random.uniform(0.1, 4.0, n_normal),
        "avg_file_entropy": np.random.uniform(3.2, 5.8, n_normal),
        "outbound_conn_count": np.random.randint(0, 10, size=n_normal),
        "suspicious_port_flag": np.zeros(n_normal),
        "data_exfil_kb_sec": np.random.uniform(0.0, 50.0, n_normal),
        "spawn_rate": np.random.uniform(0.0, 2.0, n_normal),
        "file_deletion_rate": np.random.uniform(0.0, 1.0, n_normal),
        "label": ["Normal"] * n_normal
    }
    
    # 2. Ransomware Attack Samples (7.5%)
    n_rans = int(num_samples * 0.075)
    rans_data = {
        "cpu_percent": np.random.uniform(40.0, 95.0, n_rans),
        "mem_percent": np.random.uniform(10.0, 30.0, n_rans),
        "is_tmp_execution": np.random.choice([0.0, 1.0], p=[0.3, 0.7], size=n_rans),
        "file_mod_rate": np.random.uniform(15.0, 120.0, n_rans),
        "avg_file_entropy": np.random.uniform(7.2, 7.98, n_rans),
        "outbound_conn_count": np.random.randint(1, 5, size=n_rans),
        "suspicious_port_flag": np.zeros(n_rans),
        "data_exfil_kb_sec": np.random.uniform(0.0, 20.0, n_rans),
        "spawn_rate": np.random.uniform(1.0, 5.0, n_rans),
        "file_deletion_rate": np.random.uniform(8.0, 45.0, n_rans),
        "label": ["Ransomware"] * n_rans
    }

    # 3. Reverse Shell C2 Samples (7.5%)
    n_c2 = int(num_samples * 0.075)
    c2_data = {
        "cpu_percent": np.random.uniform(2.0, 25.0, n_c2),
        "mem_percent": np.random.uniform(1.0, 10.0, n_c2),
        "is_tmp_execution": np.ones(n_c2),
        "file_mod_rate": np.random.uniform(0.0, 2.0, n_c2),
        "avg_file_entropy": np.random.uniform(3.5, 5.0, n_c2),
        "outbound_conn_count": np.random.randint(1, 4, size=n_c2),
        "suspicious_port_flag": np.ones(n_c2),
        "data_exfil_kb_sec": np.random.uniform(5.0, 150.0, n_c2),
        "spawn_rate": np.random.uniform(2.0, 8.0, n_c2),
        "file_deletion_rate": np.zeros(n_c2),
        "label": ["Reverse Shell C2"] * n_c2
    }

    # 4. Data Exfiltration Samples (7.5%)
    n_exfil = int(num_samples * 0.075)
    exfil_data = {
        "cpu_percent": np.random.uniform(15.0, 60.0, n_exfil),
        "mem_percent": np.random.uniform(5.0, 25.0, n_exfil),
        "is_tmp_execution": np.random.choice([0.0, 1.0], p=[0.5, 0.5], size=n_exfil),
        "file_mod_rate": np.random.uniform(2.0, 15.0, n_exfil),
        "avg_file_entropy": np.random.uniform(4.0, 6.5, n_exfil),
        "outbound_conn_count": np.random.randint(8, 25, size=n_exfil),
        "suspicious_port_flag": np.random.choice([0.0, 1.0], p=[0.4, 0.6], size=n_exfil),
        "data_exfil_kb_sec": np.random.uniform(1024.0, 15000.0, n_exfil),
        "spawn_rate": np.random.uniform(0.5, 3.0, n_exfil),
        "file_deletion_rate": np.zeros(n_exfil),
        "label": ["Data Exfiltration"] * n_exfil
    }

    # 5. CryptoMiner Samples (7.5%)
    n_miner = int(num_samples * 0.075)
    miner_data = {
        "cpu_percent": np.random.uniform(88.0, 100.0, n_miner),
        "mem_percent": np.random.uniform(20.0, 60.0, n_miner),
        "is_tmp_execution": np.random.choice([0.0, 1.0], p=[0.2, 0.8], size=n_miner),
        "file_mod_rate": np.random.uniform(0.0, 1.0, n_miner),
        "avg_file_entropy": np.random.uniform(3.0, 5.0, n_miner),
        "outbound_conn_count": np.random.randint(1, 6, size=n_miner),
        "suspicious_port_flag": np.random.choice([0.0, 1.0], p=[0.8, 0.2], size=n_miner),
        "data_exfil_kb_sec": np.random.uniform(1.0, 50.0, n_miner),
        "spawn_rate": np.random.uniform(5.0, 15.0, n_miner),
        "file_deletion_rate": np.zeros(n_miner),
        "label": ["CryptoMiner"] * n_miner
    }

    dfs = [pd.DataFrame(d) for d in [normal_data, rans_data, c2_data, exfil_data, miner_data]]
    dataset = pd.concat(dfs, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return dataset

def export_dataset_to_csv(filepath=None, num_samples=3000):
    """Exports generated 10-feature telemetry dataset to a CSV file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    target_path = Path(filepath) if filepath else (DATA_DIR / "osentinel_10d_telemetry_dataset.csv")
    df = generate_synthetic_telemetry(num_samples)
    df.to_csv(target_path, index=False)
    print(f"[OSentinel ML] Exported {len(df)} samples to {target_path}")
    return target_path

def train_and_save_models():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    init_db()
    
    print("[OSentinel ML] Generating synthetic security telemetry dataset...")
    df = generate_synthetic_telemetry(3000)
    
    # Save active dataset to CSV in data directory
    csv_path = DATA_DIR / "osentinel_10d_telemetry_dataset.csv"
    df.to_csv(csv_path, index=False)
    print(f"[OSentinel ML] Saved active 10-feature telemetry dataset to {csv_path}")
    
    X = df[FEATURE_NAMES]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    # 1. Train Unsupervised Isolation Forest (trained on Normal traffic samples)
    print("[OSentinel ML] Training Isolation Forest anomaly detector...")
    X_normal_train = X_train[y_train == "Normal"]
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso_forest.fit(X_normal_train)
    
    # 2. Train Supervised Random Forest Classifier
    print("[OSentinel ML] Training Random Forest multi-class threat classifier...")
    rf_classifier = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    rf_classifier.fit(X_train, y_train)
    
    # Evaluate Classifier
    y_pred = rf_classifier.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    
    print(f"[OSentinel ML] Model Evaluation Results:")
    print(f"  - Accuracy:  {acc*100:.2f}%")
    print(f"  - Precision: {prec*100:.2f}%")
    print(f"  - Recall:    {rec*100:.2f}%")
    print(f"  - F1-Score:  {f1*100:.2f}%")
    
    # Save Model Artifacts
    joblib.dump(iso_forest, MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(rf_classifier, MODELS_DIR / "random_forest.joblib")
    
    feature_importances = dict(zip(FEATURE_NAMES, rf_classifier.feature_importances_.round(4).tolist()))
    
    meta_info = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "feature_importances": feature_importances,
        "labels": list(rf_classifier.classes_)
    }
    
    joblib.dump(meta_info, MODELS_DIR / "model_metadata.joblib")
    
    # Log metrics to DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ml_metrics (accuracy, precision, recall, f1_score, model_version) VALUES (?, ?, ?, ?, ?)",
        (round(acc, 4), round(prec, 4), round(rec, 4), round(f1, 4), "1.0.0")
    )
    conn.commit()
    conn.close()
    
    print("[OSentinel ML] Model training & artifact export complete!")
    return meta_info

if __name__ == "__main__":
    train_and_save_models()
