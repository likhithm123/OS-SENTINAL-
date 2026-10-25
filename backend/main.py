import os
import asyncio
import json
import time
import threading
import ipaddress
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import POLL_INTERVAL_SEC
from backend.database import (
    init_db,
    get_recent_events,
    get_incidents,
    get_alerts,
    update_incident_status,
    create_incident,
    get_restricted_networks,
    add_restricted_network,
    delete_restricted_network,
    toggle_restricted_network
)
from backend.modules.module1_process import collect_process_telemetry
from backend.modules.module2_file import collect_file_telemetry
from backend.modules.module3_network import collect_network_telemetry
from backend.modules.module4_feature_extraction import extract_feature_vector
from backend.modules.module5_rule_engine import evaluate_rules
from backend.modules.module6_ml_engine import run_ml_inference, get_ml_metrics, load_ml_models
from backend.modules.module7_risk_assessment import (
    calculate_risk_score,
    triage_and_respond,
    terminate_process_safe,
    quarantine_process_safe,
    resume_process_safe
)
from backend.modules.attack_simulator import trigger_attack_simulation, get_active_simulation
from backend.modules.train_models import train_and_save_models

app = FastAPI(
    title="OSentinel Security Framework API",
    description="Intelligent Host-Based Security Framework with 2-Stage ML & Real-Time SOC Telemetry",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State Container
current_telemetry_state = {
    "status": "ONLINE",
    "timestamp": time.time(),
    "process_telemetry": {},
    "file_telemetry": {},
    "network_telemetry": {},
    "feature_dict": {},
    "rule_result": {},
    "ml_result": {},
    "risk_assessment": {},
    "triage_result": {},
    "active_simulation": None
}

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def telemetry_polling_loop():
    """Background thread polling system telemetry and executing OSentinel detection pipeline."""
    global current_telemetry_state
    
    # Initialize DB & ML models
    init_db()
    load_ml_models()
    
    while True:
        try:
            # 1. Collect Telemetry
            proc_data = collect_process_telemetry()
            file_data = collect_file_telemetry()
            net_data = collect_network_telemetry()
            
            # 2. Extract Behavioral Feature Vector
            feat_out = extract_feature_vector(proc_data, file_data, net_data)
            feat_dict = feat_out["feature_dict"]
            feat_vec = feat_out["vector"]
            
            # 3. Rule Engine Evaluation
            rule_res = evaluate_rules(feat_dict)
            
            # 4. ML Engine Inference (Isolation Forest + Random Forest)
            ml_res = run_ml_inference(feat_vec, feat_dict)
            
            # 5. Risk Assessment (0-100 Score)
            risk_res = calculate_risk_score(rule_res, ml_res)
            
            # 6. Response Triage & Incident Engine
            triage_res = triage_and_respond(proc_data, file_data, net_data, rule_res, ml_res, risk_res)
            
            active_sim = get_active_simulation()
            
            # Periodically log real host telemetry sample (every ~10 seconds)
            if int(time.time()) % 10 < int(POLL_INTERVAL_SEC):
                try:
                    from backend.modules.live_data_collector import record_live_telemetry_sample
                    current_label = risk_res.get("threat_category", "Normal")
                    record_live_telemetry_sample(label=current_label if current_label else "Normal")
                except Exception:
                    pass
                    
            # Update Global Telemetry Cache
            current_telemetry_state = {
                "status": "ONLINE",
                "timestamp": time.time(),
                "process_telemetry": proc_data,
                "file_telemetry": file_data,
                "network_telemetry": net_data,
                "feature_dict": feat_dict,
                "rule_result": rule_res,
                "ml_result": ml_res,
                "risk_assessment": risk_res,
                "triage_result": triage_res,
                "active_simulation": active_sim
            }
            
        except Exception as e:
            print(f"[OSentinel Loop Error] {e}")
            
        time.sleep(POLL_INTERVAL_SEC)

# Start background monitoring loop thread on startup
@app.on_event("startup")
def startup_event():
    t = threading.Thread(target=telemetry_polling_loop, daemon=True)
    t.start()

# --- REST ENDPOINTS ---

@app.get("/api/status")
def get_system_status():
    return current_telemetry_state

@app.get("/api/processes")
def get_processes():
    return current_telemetry_state.get("process_telemetry", {})

@app.get("/api/incidents")
def fetch_incidents():
    return get_incidents(50)

@app.get("/api/alerts")
def fetch_alerts():
    return get_alerts(50)

@app.get("/api/events")
def fetch_events():
    return get_recent_events(50)

@app.get("/api/metrics")
def fetch_ml_metrics():
    return get_ml_metrics()

class AttackSimRequest(BaseModel):
    attack_type: str

@app.post("/api/simulate")
def simulate_attack(req: AttackSimRequest):
    res = trigger_attack_simulation(req.attack_type)
    return res

class ContainRequest(BaseModel):
    incident_id: int = 0
    pid: int
    process_name: str
    action: str  # "TERMINATE", "QUARANTINE", "RESUME", or "IGNORE"

@app.post("/api/contain")
def contain_incident(req: ContainRequest):
    act = req.action.upper()
    if act == "TERMINATE":
        res = terminate_process_safe(req.pid, req.process_name, force=True)
        if req.incident_id > 0:
            update_incident_status(req.incident_id, "RESOLVED", f"MANUAL_TERMINATE (PID {req.pid})")
        return {"success": res.get("success", True), "message": res["message"]}
    elif act == "QUARANTINE":
        res = quarantine_process_safe(req.pid, req.process_name, reason="Manual operator quarantine via SOC")
        if req.incident_id > 0:
            update_incident_status(req.incident_id, "QUARANTINED", f"QUARANTINED_SIGSTOP (PID {req.pid})")
        return {"success": res.get("success", True), "message": res["message"]}
    elif act == "RESUME":
        res = resume_process_safe(req.pid, req.process_name)
        if req.incident_id > 0:
            update_incident_status(req.incident_id, "INVESTIGATING", f"RESUMED_SIGCONT (PID {req.pid})")
        return {"success": res.get("success", True), "message": res["message"]}
    else:
        if req.incident_id > 0:
            update_incident_status(req.incident_id, "DISMISSED", "MANUAL_IGNORE")
        return {"success": True, "message": "Incident marked as dismissed."}

@app.post("/api/retrain")
def retrain_models(background_tasks: BackgroundTasks):
    background_tasks.add_task(train_and_save_models)
    return {"success": True, "message": "Model retraining job queued in background."}

# --- RESTRICTED NETWORKS & IP ACCESS CONTROL ENDPOINTS ---

class RestrictedNetworkRequest(BaseModel):
    network_cidr: str
    description: str = ""
    action: str = "BLOCK"

@app.get("/api/network/restricted")
def fetch_restricted_networks():
    return get_restricted_networks()

@app.post("/api/network/restricted")
def create_restricted_network(req: RestrictedNetworkRequest):
    cidr_clean = req.network_cidr.strip()
    if not cidr_clean:
        raise HTTPException(status_code=400, detail="Network IP or CIDR cannot be empty.")
    try:
        # Validate CIDR or IP (accepts e.g. 192.168.1.100 or 10.0.0.0/16)
        ipaddress.ip_network(cidr_clean, strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP address or CIDR notation: {e}")
        
    try:
        created = add_restricted_network(cidr_clean, req.description, req.action)
        return {"success": True, "network": created}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to add restricted network (may already exist): {e}")

@app.delete("/api/network/restricted/{network_id}")
def remove_restricted_network(network_id: int):
    ok = delete_restricted_network(network_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Restricted network entry not found.")
    return {"success": True, "message": f"Restricted network {network_id} deleted."}

@app.post("/api/network/restricted/{network_id}/toggle")
def toggle_network(network_id: int):
    updated = toggle_restricted_network(network_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Restricted network entry not found.")
    return {"success": True, "network": updated}

# --- DATASET MANAGEMENT & REAL-WORLD BENCHMARK ENDPOINTS ---
from backend.modules.dataset_manager import (
    get_all_datasets_summary,
    get_nsl_kdd_metrics,
    train_nsl_kdd_benchmark
)
from backend.modules.live_data_collector import (
    collect_live_dataset_batch,
    get_live_dataset_stats
)

@app.get("/api/datasets")
def fetch_datasets():
    """Returns metadata and statistics on all synthetic, benchmark, and live host datasets."""
    return get_all_datasets_summary()

@app.get("/api/datasets/benchmark-metrics")
def fetch_benchmark_metrics():
    """Returns evaluation metrics on the real-world NSL-KDD benchmark dataset."""
    return get_nsl_kdd_metrics()

@app.post("/api/datasets/record-live")
def record_live_samples(samples: int = 20, label: str = "Normal"):
    """Collects real-time host telemetry samples from the local machine into the live CSV dataset."""
    res = collect_live_dataset_batch(num_samples=min(100, max(1, samples)), interval_sec=0.2, label=label)
    return res

# --- FILE ENTROPY GENERATOR & VISUALIZER ENDPOINTS ---
from backend.modules.entropy_demo import (
    create_word_document,
    simulate_rapid_word_writes,
    simulate_ransomware_encryption,
    get_word_document_preview
)

@app.get("/api/entropy/preview")
def fetch_entropy_doc_preview():
    return get_word_document_preview()

@app.post("/api/entropy/create-doc")
def create_entropy_word_doc():
    return create_word_document()

@app.post("/api/entropy/rapid-writes")
def run_rapid_word_writes():
    return simulate_rapid_word_writes()

@app.post("/api/entropy/encrypt")
def run_ransomware_encryption():
    return simulate_ransomware_encryption()

@app.post("/api/entropy/restore")
def restore_entropy_doc():
    return create_word_document()

# --- WEBSOCKET ENDPOINT ---

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.send_json(current_telemetry_state)
            await asyncio.sleep(POLL_INTERVAL_SEC)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
# --- STATIC FRONTEND ASSETS FOR PRODUCTION DEPLOYMENT ---
from fastapi.staticfiles import StaticFiles
from backend.config import PROJECT_ROOT

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=False)
