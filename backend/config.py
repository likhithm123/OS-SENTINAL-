import os
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
MODELS_DIR = BASE_DIR / "models"
RULES_DIR = BASE_DIR / "rules"
DB_PATH = BASE_DIR / "osentinel.db"
SANDBOX_DIR = PROJECT_ROOT / "live_threat_sandbox"
DATA_DIR = PROJECT_ROOT / "data"

# Ensure directories exist
MODELS_DIR.mkdir(parents=True, exist_ok=True)
RULES_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Risk Assessment Thresholds
RISK_THRESHOLD_LOW = 40.0       # < 40 is LOW (Log only)
RISK_THRESHOLD_HIGH = 70.0      # >= 70 is HIGH (Incident & Containment), 40-69 is MEDIUM (Alert)

# Risk Score Weights: Risk = w_rule * RuleScore + w_anomaly * AnomalyScore + w_class * ClassifierConfidence
WEIGHT_RULE = 0.45
WEIGHT_ANOMALY = 0.35
WEIGHT_CLASSIFIER = 0.20

# Feature Normalization Bounds & Constants
ENTROPY_HIGH_THRESHOLD = 7.2     # Shannon entropy threshold (0.0 to 8.0)
WRITE_RATE_HIGH_THRESHOLD = 50   # Writes/sec threshold
SUSPICIOUS_PORTS = [4444, 1337, 6667, 31337, 8888, 5555, 9999, 4445]

def get_platform_suspicious_paths():
    """Returns cross-platform list of temporary and scratch directories."""
    paths = []
    # 1. Standard OS temp directory
    t = tempfile.gettempdir()
    if t:
        paths.append(t.lower().replace("\\", "/"))
        
    # 2. Windows specific environment paths
    if sys.platform.startswith("win"):
        for env_k in ["TEMP", "TMP", "LOCALAPPDATA", "APPDATA"]:
            val = os.environ.get(env_k)
            if val:
                paths.append(val.lower().replace("\\", "/"))
        paths.extend(["c:/temp", "c:/windows/temp"])
    # 3. macOS / Linux specific directories
    else:
        paths.extend(["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm"])
        
    # Deduplicate and normalize
    return list(set(p.rstrip("/") for p in paths if p))

SUSPICIOUS_PATHS = get_platform_suspicious_paths()

# System Data Polling Interval (seconds)
POLL_INTERVAL_SEC = 2.0
