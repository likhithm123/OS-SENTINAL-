import os
import sys
import psutil
import json
from backend.config import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_HIGH,
    WEIGHT_RULE,
    WEIGHT_ANOMALY,
    WEIGHT_CLASSIFIER
)
from backend.database import create_alert, create_incident, log_event, log_containment_action
from backend.modules.module1_process import is_browser_process, is_browser_tab, is_ide_process

def is_protected_system_process(pid: int, process_name: str) -> bool:
    """Prevents terminating operating system core kernel processes."""
    if pid <= 100:
        return True
    current_pid = os.getpid()
    parent_pid = os.getppid()
    if pid in (current_pid, parent_pid):
        return True
    name_clean = (process_name or "").lower()
    return name_clean in ["kernel_task", "launchd", "systemd", "windowserver"]

def calculate_risk_score(rule_result: dict, ml_result: dict) -> dict:
    rule_score = float(rule_result.get("rule_score", 0.0))
    anomaly_score = float(ml_result.get("anomaly_score", 0.0))
    
    threat_category = ml_result.get("predicted_category", "Normal")
    confidence = float(ml_result.get("confidence", 0.0))
    
    classifier_score = (confidence * 100.0) if threat_category != "Normal" else 0.0
    
    raw_risk = (WEIGHT_RULE * rule_score) + (WEIGHT_ANOMALY * anomaly_score) + (WEIGHT_CLASSIFIER * classifier_score)
    final_risk_score = min(100.0, max(0.0, raw_risk))
    
    # Prioritize specific rule categories if triggered
    triggered_rules = rule_result.get("triggered_rules", [])
    if any(r.get("id") == "RULE-NET-RESTRICTED-01" for r in triggered_rules):
        threat_category = "Restricted Network Access"
    elif any(r.get("id") in ["RULE-BROWSER-01", "RULE-BROWSER-TABS-01"] for r in triggered_rules):
        threat_category = "Browser Cryptojacking"
    elif any(r.get("id") == "RULE-LINEAGE-01" for r in triggered_rules):
        threat_category = "Process Injection / Web Shell"
    
    if final_risk_score >= RISK_THRESHOLD_HIGH:
        severity = "HIGH"
    elif final_risk_score >= RISK_THRESHOLD_LOW:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    return {
        "risk_score": round(final_risk_score, 1),
        "severity": severity,
        "threat_category": threat_category if final_risk_score >= RISK_THRESHOLD_LOW else "Normal",
        "score_breakdown": {
            "rule_component": round(WEIGHT_RULE * rule_score, 1),
            "anomaly_component": round(WEIGHT_ANOMALY * anomaly_score, 1),
            "classifier_component": round(WEIGHT_CLASSIFIER * classifier_score, 1)
        }
    }

_quarantined_pids = set()

def is_process_quarantined(pid: int) -> bool:
    return pid in _quarantined_pids

def get_quarantined_pids() -> list:
    return list(_quarantined_pids)

def quarantine_process_safe(
    pid: int,
    process_name: str,
    reason: str = "Behavioral anomaly detected"
) -> dict:
    """
    Reversible Containment: Freezes execution using POSIX SIGSTOP (or NtSuspendProcess on Windows).
    Preserves process memory and state for forensic investigation without allowing malicious execution.
    """
    if is_ide_process(process_name):
        return {
            "success": False,
            "message": f"AntiGravity IDE ({process_name}, PID {pid}) is exempted from quarantine."
        }
    if is_protected_system_process(pid, process_name):
        return {
            "success": False,
            "message": f"System core process {process_name} (PID {pid}) cannot be quarantined."
        }
    try:
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.suspend()
            _quarantined_pids.add(pid)
            log_containment_action(
                incident_id=0,
                target_pid=pid,
                target_name=process_name,
                action_taken="QUARANTINE_SIGSTOP",
                status="SUCCESS",
                details=f"Suspended execution using POSIX SIGSTOP. Reason: {reason}"
            )
            return {
                "success": True,
                "message": f"Successfully quarantined (frozen via SIGSTOP): {process_name} (PID {pid})"
            }
        else:
            return {"success": False, "message": f"Process PID {pid} no longer running."}
    except (psutil.AccessDenied, PermissionError):
        return {"success": False, "message": f"Permission denied suspending PID {pid}."}
    except Exception as e:
        return {"success": False, "message": str(e)}

def resume_process_safe(
    pid: int,
    process_name: str
) -> dict:
    """
    Reversible Containment: Resumes execution using POSIX SIGCONT (or NtResumeProcess on Windows).
    """
    try:
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.resume()
            _quarantined_pids.discard(pid)
            log_containment_action(
                incident_id=0,
                target_pid=pid,
                target_name=process_name,
                action_taken="RESUME_SIGCONT",
                status="SUCCESS",
                details=f"Resumed execution using POSIX SIGCONT."
            )
            return {
                "success": True,
                "message": f"Successfully resumed (unfrozen via SIGCONT): {process_name} (PID {pid})"
            }
        else:
            _quarantined_pids.discard(pid)
            return {"success": True, "message": f"Process PID {pid} already stopped."}
    except Exception as e:
        return {"success": False, "message": str(e)}

def terminate_process_safe(
    pid: int,
    process_name: str,
    is_tmp: bool = False,
    cpu_percent: float = 0.0,
    cmdline: str = "",
    force: bool = False
) -> dict:
    """
    Terminates rogue processes and runaway browser tabs with alerts.
    AntiGravity is the ONLY process protected from termination.
    """
    # 1. AntiGravity Exemption Check - NEVER terminate AntiGravity
    if is_ide_process(process_name, cmdline):
        return {
            "success": False,
            "message": f"AntiGravity IDE ({process_name}, PID {pid}) is exempted from termination (sole permitted exception)."
        }
        
    if is_protected_system_process(pid, process_name):
        return {
            "success": False,
            "message": f"System core process {process_name} (PID {pid}) cannot be terminated."
        }
        
    # 2. Execute process termination (supports browser tabs, rogue writers, and miners)
    try:
        _quarantined_pids.discard(pid)
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                p.kill() # Force kill if stubborn
            return {
                "success": True,
                "message": f"Successfully auto-terminated target process: {process_name} (PID {pid})"
            }
        else:
            return {"success": True, "message": f"Process PID {pid} already stopped."}
    except (psutil.AccessDenied, PermissionError):
        return {"success": False, "message": f"Permission denied terminating PID {pid}."}
    except Exception as e:
        return {"success": False, "message": str(e)}

def triage_and_respond(proc_telemetry: dict, file_telemetry: dict, net_telemetry: dict, rule_result: dict, ml_result: dict, risk_assessment: dict):
    risk_score = risk_assessment["risk_score"]
    severity = risk_assessment["severity"]
    threat_cat = risk_assessment["threat_category"]
    
    triggered_rules = rule_result.get("triggered_rules", [])
    processes = proc_telemetry.get("processes", [])
    
    terminated_processes = []
    seen_terminated_pids = set()
    
    # -------------------------------------------------------------------------
    # RULE A1: Auto-Termination for Runaway Browser Tabs / Processes (Safari/Chrome >= 70%)
    # -------------------------------------------------------------------------
    for p in processes:
        p_name = p.get("name", "")
        p_cmd = p.get("cmdline", "")
        p_exe = p.get("exe", "")
        p_cpu = p.get("cpu_percent", 0.0)
        p_pid = p.get("pid", 0)
        
        # If it's a browser tab/process exceeding 70% CPU, auto-terminate it immediately
        if is_browser_process(p_name, p_cmd, p_exe) and p_cpu >= 70.0 and not is_ide_process(p_name, p_cmd, p_exe):
            if p_pid not in seen_terminated_pids:
                kill_res = terminate_process_safe(p_pid, p_name, cpu_percent=p_cpu, cmdline=p_cmd, force=True)
                if kill_res["success"]:
                    seen_terminated_pids.add(p_pid)
                    terminated_processes.append(f"Browser Tab '{p_name}' (PID {p_pid}, CPU {p_cpu}%)")
                    create_alert(
                        severity="HIGH",
                        title=f"Runaway Browser Tab Auto-Terminated (PID {p_pid})",
                        description=f"Browser process '{p_name}' (PID {p_pid}) exceeded the 70% CPU threshold ({p_cpu}%). Auto-terminated to protect system performance.",
                        risk_score=75.0,
                        triggered_rules=["RULE-BROWSER-01"],
                        threat_category="Browser Cryptojacking"
                    )

    # -------------------------------------------------------------------------
    # RULE A2: Auto-Termination on Multiple Browser Tabs Opening Burst
    # -------------------------------------------------------------------------
    if proc_telemetry.get("multiple_tabs_burst"):
        new_tab_pids = proc_telemetry.get("new_tab_pids", [])
        for p_pid in new_tab_pids:
            if p_pid in seen_terminated_pids:
                continue
            # Find process info
            p_name = "browser_tab"
            p_cmd = ""
            for p in processes:
                if p.get("pid") == p_pid:
                    p_name = p.get("name", "browser_tab")
                    p_cmd = p.get("cmdline", "")
                    break
                    
            kill_res = terminate_process_safe(p_pid, p_name, cmdline=p_cmd, force=True)
            if kill_res["success"]:
                seen_terminated_pids.add(p_pid)
                terminated_processes.append(f"Runaway Tab '{p_name}' (PID {p_pid})")
                create_alert(
                    severity="HIGH",
                    title=f"Multiple Tabs Opening: Tab Auto-Terminated (PID {p_pid})",
                    description=f"Detected multiple browser tabs opening burst. Offending tab '{p_name}' (PID {p_pid}) was auto-terminated to prevent resource exhaustion.",
                    risk_score=70.0,
                    triggered_rules=["RULE-BROWSER-TABS-01"],
                    threat_category="Browser Runaway Tabs"
                )

    # -------------------------------------------------------------------------
    # RULE B: Rapid Multiple Edits on File Save (Ransomware / Malicious File Writers)
    # AntiGravity is the SOLE EXCEPTION permitted to perform multiple file edits.
    # -------------------------------------------------------------------------
    is_rapid_file_edits = (file_telemetry.get("file_mod_rate", 0) >= 15.0 or file_telemetry.get("high_entropy_alert", False))
    if is_rapid_file_edits:
        for p in processes:
            p_name = p.get("name", "")
            p_cmd = p.get("cmdline", "")
            p_exe = p.get("exe", "")
            p_pid = p.get("pid", 0)
            
            # If process is NOT AntiGravity and is active or tmp
            if not is_ide_process(p_name, p_cmd, p_exe) and (p.get("is_tmp") or p.get("cpu_percent", 0) > 10.0):
                if p_pid not in seen_terminated_pids:
                    kill_res = terminate_process_safe(p_pid, p_name, force=True)
                    if kill_res["success"]:
                        seen_terminated_pids.add(p_pid)
                        terminated_processes.append(f"Rogue File Writer (PID {p_pid})")
                        create_alert(
                            severity="HIGH",
                            title=f"Rogue Process Auto-Terminated: Rapid File Modification (PID {p_pid})",
                            description=f"Process '{p_name}' was actively modifying files at high velocity. AntiGravity is the only allowed exception. Process auto-terminated.",
                            risk_score=85.0,
                            triggered_rules=["RULE-RANSOMWARE-01"],
                            threat_category="Ransomware"
                        )
                    break

    # -------------------------------------------------------------------------
    # RULE C: Unwanted Dependencies & Rogue Background Workers
    # (Temporary path execution, unapproved miners, rogue sockets)
    # -------------------------------------------------------------------------
    for p in processes:
        p_name = p.get("name", "")
        p_cmd = p.get("cmdline", "")
        p_exe = p.get("exe", "")
        p_pid = p.get("pid", 0)
        p_cpu = p.get("cpu_percent", 0.0)
        
        if p.get("is_tmp") and not is_ide_process(p_name, p_cmd, p_exe):
            if p_pid not in seen_terminated_pids:
                kill_res = terminate_process_safe(p_pid, p_name, is_tmp=True, cpu_percent=p_cpu, cmdline=p_cmd, force=True)
                if kill_res["success"]:
                    seen_terminated_pids.add(p_pid)
                    terminated_processes.append(f"Rogue Worker '{p_name}' (PID {p_pid})")
                    create_alert(
                        severity="HIGH",
                        title=f"Unwanted Rogue Dependency Auto-Terminated (PID {p_pid})",
                        description=f"Process '{p_name}' launched from unauthorized scratch/temp directory. Auto-terminated immediately.",
                        risk_score=80.0,
                        triggered_rules=["RULE-EXEC-01"],
                        threat_category="Malicious Execution"
                    )

    # -------------------------------------------------------------------------
    # RULE D: Restricted Network / IP Access Interception & Immediate Containment
    # Terminates unauthorized socket sessions to/from configured restricted networks.
    # -------------------------------------------------------------------------
    restricted_conns = [c for c in net_telemetry.get("connections", []) if c.get("is_restricted")]
    if restricted_conns or net_telemetry.get("restricted_ip_flag", 0) > 0:
        for c in restricted_conns:
            p_pid = c.get("pid", 0)
            raddr = c.get("raddr", "Unknown")
            matched_net = c.get("matched_network", "Restricted Subnet")
            restr_reason = c.get("restricted_reason", "Restricted Network")
            
            if p_pid > 0 and p_pid not in seen_terminated_pids:
                p_name = "network_process"
                p_cmd = ""
                p_exe = ""
                for p in processes:
                    if p.get("pid") == p_pid:
                        p_name = p.get("name", "network_process")
                        p_cmd = p.get("cmdline", "")
                        p_exe = p.get("exe", "")
                if p_name == "network_process":
                    try:
                        p_obj = psutil.Process(p_pid)
                        p_name = p_obj.name()
                        p_cmd = " ".join(p_obj.cmdline())
                        p_exe = p_obj.exe()
                    except Exception:
                        pass
                        
                if not is_ide_process(p_name, p_cmd, p_exe):
                    kill_res = terminate_process_safe(p_pid, p_name, cmdline=p_cmd, force=True)
                    if kill_res["success"]:
                        seen_terminated_pids.add(p_pid)
                        terminated_processes.append(f"Restricted Network Socket on '{p_name}' (PID {p_pid} -> {raddr})")
                        create_alert(
                            severity="HIGH",
                            title=f"Restricted Network Connection Severed & Auto-Terminated (PID {p_pid})",
                            description=f"Process '{p_name}' (PID {p_pid}) attempted unauthorized communication with restricted network {matched_net} ({raddr} - {restr_reason}). Policy: AUTO-BLOCK. Connection severed and process terminated.",
                            risk_score=90.0,
                            triggered_rules=["RULE-NET-RESTRICTED-01"],
                            threat_category="Restricted Network Access"
                        )

    incident_id = None
    incident_code = None
    alert_id = None
    response_action = "LOG"
    
    if severity == "HIGH" or terminated_processes:
        response_action = "CONTAIN_AND_INCIDENT"
        contain_summary = f"AUTO-TERMINATED: {', '.join(terminated_processes)}" if terminated_processes else "ISOLATE_MONITOR"
        incident_id, incident_code = create_incident(
            severity="HIGH",
            risk_score=max(75.0, risk_score) if terminated_processes else risk_score,
            threat_category=threat_cat if threat_cat != "Normal" else "Runaway Process",
            pid=processes[0].get("pid", 0) if processes else 0,
            process_name=processes[0].get("name", "unknown") if processes else "unknown",
            evidence_dict={
                "score_breakdown": risk_assessment["score_breakdown"],
                "triggered_rules": triggered_rules,
                "ml_inference": ml_result,
                "terminated_processes": terminated_processes,
                "file_activity": file_telemetry,
                "network_activity": net_telemetry
            },
            status="CONTAINED" if terminated_processes else "OPEN",
            containment_action=contain_summary
        )
    elif severity == "MEDIUM":
        response_action = "ALERT"
        alert_id = create_alert(
            severity="MEDIUM",
            title=f"Elevated Activity Flagged ({threat_cat})",
            description=f"Elevated risk score ({risk_score}) detected. {len(triggered_rules)} rule(s) active.",
            risk_score=risk_score,
            triggered_rules=triggered_rules,
            threat_category=threat_cat
        )
        
    return {
        "risk_score": risk_score,
        "severity": severity,
        "threat_category": threat_cat,
        "response_action": response_action,
        "terminated_count": len(terminated_processes),
        "terminated_details": terminated_processes,
        "incident_id": incident_id,
        "incident_code": incident_code,
        "alert_id": alert_id
    }
