import os
import time
import math
import secrets
from pathlib import Path
from collections import Counter
from backend.config import SANDBOX_DIR, ENTROPY_HIGH_THRESHOLD
from backend.modules.module2_file import calculate_shannon_entropy, set_simulated_file_activity

WORD_DOCUMENT_PATH = SANDBOX_DIR / "corporate_quarterly_report.txt"

SAMPLE_HUMAN_WORDS = """CONFIDENTIAL CORPORATE QUARTERLY OPERATING REPORT
Fiscal Year 2026 - Q3 Performance Summary

1. Executive Strategic Overview:
Total consolidated revenue increased by 18.4% quarter-over-quarter, driven by enterprise software subscriptions and cloud infrastructure adoption. Operating margins expanded across all operational sectors.

2. Financial Health & Balance Sheet:
Cash and short-term liquid investments totaled $42.5 million. The board of directors approved a strategic expansion budget dedicated to advanced cybersecurity defense infrastructure, automated threat containment systems, and host-based intrusion monitoring.

3. Host Telemetry & Risk Management Compliance:
All corporate endpoints maintain continuous host-level telemetry inspection. Shannon entropy watchdog monitoring is actively enforced across all local storage volumes and customer database records.

4. Approved Operational Signatures:
Reviewed and verified by Senior Management, Audit Committee, and Enterprise Security Operations.
"""

def create_word_document():
    """Creates a human-readable corporate document with standard dictionary words."""
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    with open(WORD_DOCUMENT_PATH, "w", encoding="utf-8") as f:
        f.write(SAMPLE_HUMAN_WORDS)
    
    with open(WORD_DOCUMENT_PATH, "rb") as f:
        data = f.read()
        
    ent = calculate_shannon_entropy(data)
    return {
        "status": "CREATED",
        "file_name": WORD_DOCUMENT_PATH.name,
        "path": str(WORD_DOCUMENT_PATH),
        "entropy": ent,
        "category": "PLAINTEXT / LOW",
        "is_encrypted": False,
        "size_bytes": len(data),
        "content_preview": SAMPLE_HUMAN_WORDS[:250] + "..."
    }

def simulate_rapid_word_writes(num_bursts=20):
    """
    Performs rapid file write operations using natural words (Benign Developer/Office burst).
    Tests whether OSentinel differentiates rapid text editing from ransomware encryption.
    """
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    start_time = time.time()
    
    for i in range(num_bursts):
        with open(WORD_DOCUMENT_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n[Audit Log Revision {i+1}: Updated operating balance metrics at {time.strftime('%H:%M:%S')}]")
        time.sleep(0.04) # Rapid burst ~25 writes/sec
        
    duration = max(0.1, time.time() - start_time)
    actual_rate = round(num_bursts / duration, 1)
    
    with open(WORD_DOCUMENT_PATH, "rb") as f:
        data = f.read()
    ent = calculate_shannon_entropy(data)
    
    # Inform file telemetry of elevated write rate with benign entropy
    set_simulated_file_activity(mod_rate=actual_rate, avg_entropy=ent, del_rate=0.0)
    
    return {
        "status": "RAPID_WRITES_COMPLETED",
        "writes_performed": num_bursts,
        "write_rate": actual_rate,
        "entropy": ent,
        "verdict": "BENIGN / NORMAL TEXT (NO ENCRYPTION DETECTED)",
        "content_preview": data.decode("utf-8", errors="ignore")[-200:]
    }

def simulate_ransomware_encryption():
    """
    Simulates real ransomware cryptographic encryption on the word document:
    Replaces natural word byte distributions with high-randomness cryptographic ciphertext bytes.
    Shannon entropy H(X) surges to ~7.98 / 8.0 bits/byte!
    """
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    
    # Generate cryptographic ciphertext bytes (AES-like uniform byte distribution)
    ciphertext_bytes = secrets.token_bytes(8192)
    with open(WORD_DOCUMENT_PATH, "wb") as f:
        f.write(ciphertext_bytes)
        
    ent = calculate_shannon_entropy(ciphertext_bytes)
    
    # Inject active ransomware breach metrics into telemetry watchdog
    set_simulated_file_activity(mod_rate=32.0, avg_entropy=ent, del_rate=2.0)
    
    hex_preview = " ".join(f"{b:02X}" for b in ciphertext_bytes[:48])
    
    return {
        "status": "ENCRYPTED_RANSOMWARE_ATTACK",
        "file_name": WORD_DOCUMENT_PATH.name,
        "entropy": ent,
        "is_encrypted": True,
        "category": "🚨 HIGH ENTROPY / CIPHERTEXT (ENCRYPTED)",
        "rule_triggered": "RULE-RANSOMWARE-01",
        "hex_preview": hex_preview,
        "write_rate": 32.0,
        "verdict": "CRITICAL THREAT: Ransomware Cryptographic Encryption Detected!"
    }

def get_word_document_preview():
    """Returns current content preview, entropy, and cryptographic status."""
    if not WORD_DOCUMENT_PATH.exists():
        return create_word_document()
        
    try:
        with open(WORD_DOCUMENT_PATH, "rb") as f:
            raw_bytes = f.read()
            
        ent = calculate_shannon_entropy(raw_bytes)
        is_enc = ent >= ENTROPY_HIGH_THRESHOLD
        
        try:
            text_preview = raw_bytes.decode("utf-8")[:300]
        except Exception:
            text_preview = "[Binary Ciphertext Payload - Cryptographically Encrypted]"
            
        hex_preview = " ".join(f"{b:02X}" for b in raw_bytes[:48])
        
        return {
            "status": "READY",
            "file_name": WORD_DOCUMENT_PATH.name,
            "entropy": ent,
            "is_encrypted": is_enc,
            "category": "🚨 HIGH ENTROPY / CIPHERTEXT" if is_enc else "PLAINTEXT / LOW",
            "size_bytes": len(raw_bytes),
            "text_preview": text_preview,
            "hex_preview": hex_preview
        }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}
