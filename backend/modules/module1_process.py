import psutil
import time
import os
import sys
import re
from backend.config import SUSPICIOUS_PATHS

_last_process_count = 0
_last_sample_time = time.time()
_last_proc_cpu_times = {} # {pid: (user_time, sys_time, timestamp)}
_known_browser_tab_pids = set()
_simulated_proc_activity = None
_simulated_browser_activity = None

BROWSER_KEYWORDS = [
    "safari", "webkit.webcontent", "webkit", "chrome", "google chrome",
    "google chrome helper", "firefox", "msedge", "microsoft edge", "brave", "opera", "edge"
]

TRUSTED_PREFIXES = ["/applications", "/usr", "/system", "/library", "c:/program files", "c:/windows/system32"]

def is_browser_process(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """Accurately detects web browser instances (Chrome, Safari, Firefox, Edge, Opera, Brave)."""
    name_clean = (process_name or "").lower()
    cmd_clean = (cmdline or "").lower()
    exe_clean = (exe or "").lower()
    text = f"{name_clean} {cmd_clean} {exe_clean}"
    
    # AntiGravity IDE is never a web browser
    if "antigravity" in text:
        return False
        
    if any(b in name_clean for b in ["chrome", "safari", "firefox", "msedge", "edge", "brave", "opera", "webkit"]):
        return True
    if any(b in exe_clean for b in ["google chrome", "safari.app", "firefox", "msedge", "brave", "opera", "webkit"]):
        return True
    return False

def is_browser_tab(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """Identifies individual browser tab renderer/worker processes that can be safely closed without crashing the browser."""
    if not is_browser_process(process_name, cmdline, exe):
        return False
    name_clean = (process_name or "").lower()
    cmd_clean = (cmdline or "").lower()
    
    # macOS Chrome Helper / Renderer
    if "renderer" in name_clean or "--type=renderer" in cmd_clean:
        return True
    # macOS Safari WebContent process (each tab runs in a WebContent process)
    if "webcontent" in name_clean or "com.apple.webkit.webcontent" in name_clean:
        return True
    # Firefox tab processes
    if "tab" in name_clean or "-contentproc" in cmd_clean or "plugin-container" in name_clean:
        return True
    # Chrome Helper processes
    if "chrome helper" in name_clean:
        return True
    return False

def is_ide_process(process_name: str, cmdline: str = "", exe: str = "") -> bool:
    """
    Identifies AntiGravity IDE - the SOLE PERMITTED EXCEPTION.
    Must NEVER falsely match standard web browsers (Chrome, Safari, Firefox, Edge).
    """
    name_clean = (process_name or "").lower()
    cmd_clean = (cmdline or "").lower()
    exe_clean = (exe or "").lower()
    text = f"{name_clean} {cmd_clean} {exe_clean}"
    
    # Standard web browsers are NEVER the IDE
    if any(b in text for b in [
        "google chrome.app", "safari.app", "com.apple.webkit",
        "google chrome helper", "firefox.app", "msedge.app"
    ]):
        return False
        
    # AntiGravity IDE is the sole permitted exception
    if "antigravity" in text:
        return True
        
    # Core workspace developer processes and OSentinel daemon
    if any(d in text for d in ["antigravity", "backend.main", "uvicorn", "vite", "language_server"]):
        return True
    if any(d in name_clean for d in ["electron", "vscode", "cursor"]):
        return True
    if re.search(r'\b(code|vscode|electron|cursor|language_server)\b', name_clean):
        return True
        
    return False

def set_simulated_process_activity(total_cpu: float = 98.4, spawn_rate: float = 12.0, is_tmp: bool = True):
    """Allows safe injection of elevated CPU spikes (>95%) and spawn velocity for threat simulations."""
    global _simulated_proc_activity
    _simulated_proc_activity = {
        "total_cpu": total_cpu,
        "spawn_rate": spawn_rate,
        "is_tmp": is_tmp,
        "expire_time": time.time() + 4.0
    }

def set_simulated_browser_activity(cpu: float = 78.5, tab_count: int = 4):
    """Allows safe simulation of runaway browser tabs (>=70% CPU) or multiple tabs burst."""
    global _simulated_browser_activity
    _simulated_browser_activity = {
        "cpu": cpu,
        "tab_count": tab_count,
        "expire_time": time.time() + 4.0
    }

def get_accurate_process_cpu(proc, pid: int, current_time: float) -> float:
    """Accurately calculates real-time CPU percentage by computing time deltas between samples."""
    global _last_proc_cpu_times
    try:
        t = proc.cpu_times()
        if pid in _last_proc_cpu_times:
            prev_u, prev_s, prev_t = _last_proc_cpu_times[pid]
            dt = max(0.1, current_time - prev_t)
            delta = (t.user - prev_u) + (t.system - prev_s)
            cpu_pct = round((delta / dt) * 100.0, 1)
        else:
            # If process was just spawned, estimate real CPU from process lifetime
            try:
                proc_age = max(0.1, current_time - proc.create_time())
                cpu_pct = round(((t.user + t.system) / proc_age) * 100.0, 1)
            except Exception:
                cpu_pct = 0.0
            
        _last_proc_cpu_times[pid] = (t.user, t.system, current_time)
        return max(0.0, cpu_pct)
    except Exception:
        return 0.0

def collect_process_telemetry():
    global _last_process_count, _last_sample_time, _simulated_proc_activity, _simulated_browser_activity, _last_proc_cpu_times, _known_browser_tab_pids
    
    processes = []
    tmp_execution_count = 0
    browser_high_cpu_count = 0
    lineage_anomaly_count = 0
    current_tab_pids = set()
    total_cpu = 0.0
    total_mem = 0.0
    
    current_time = time.time()
    dt = max(0.1, current_time - _last_sample_time)
    
    is_sim_active = bool(_simulated_proc_activity and current_time < _simulated_proc_activity["expire_time"])
    if not is_sim_active:
        _simulated_proc_activity = None

    is_browser_sim_active = bool(_simulated_browser_activity and current_time < _simulated_browser_activity["expire_time"])
    if not is_browser_sim_active:
        _simulated_browser_activity = None
    
    active_pids = set()
    
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'memory_percent', 'username']):
        try:
            info = proc.info
            pid = info['pid']
            active_pids.add(pid)
            name = info['name'] or f"proc_{pid}"
            exe = (info['exe'] or "").replace("\\", "/")
            mem = info['memory_percent'] or 0.0
            raw_cmdline = " ".join(info['cmdline']) if info['cmdline'] else name
            cmdline_normalized = raw_cmdline.replace("\\", "/").lower()
            
            # Accurate real-time CPU calculation
            cpu = get_accurate_process_cpu(proc, pid, current_time)
            
            is_browser = is_browser_process(name, raw_cmdline, exe)
            is_tab = is_browser_tab(name, raw_cmdline, exe) if is_browser else False
            is_ide = is_ide_process(name, raw_cmdline, exe)
            
            if is_tab:
                current_tab_pids.add(pid)
            
            # Auto-flag browsers exceeding 70% threshold
            if is_browser and cpu >= 70.0 and not is_ide:
                browser_high_cpu_count += 1
            
            # Accurate temp path execution check
            is_tmp = False
            is_trusted_exe = any(exe.lower().startswith(prefix) for prefix in TRUSTED_PREFIXES)
            
            if not is_ide and not is_trusted_exe:
                for sp in SUSPICIOUS_PATHS:
                    sp_norm = sp.replace("\\", "/").lower()
                    if exe.lower().startswith(sp_norm):
                        is_tmp = True
                        break
                    parts = raw_cmdline.split()
                    if len(parts) > 1 and parts[1].replace("\\", "/").lower().startswith(sp_norm):
                        is_tmp = True
                        break
                    elif parts and parts[0].replace("\\", "/").lower().startswith(sp_norm):
                        is_tmp = True
                        break
            
            if "osentinel_rogue" in cmdline_normalized or "xmrig" in cmdline_normalized or "nc_shell" in cmdline_normalized:
                is_tmp = True
                
            if is_tmp:
                tmp_execution_count += 1
                
            total_cpu += cpu
            total_mem += mem
            
            # Process state & quarantine tracking
            proc_status = "RUNNING"
            try:
                raw_st = proc.status()
                if raw_st in (psutil.STATUS_STOPPED, 'stopped'):
                    proc_status = "QUARANTINED"
                elif raw_st in (psutil.STATUS_ZOMBIE, 'zombie'):
                    proc_status = "ZOMBIE"
            except Exception:
                pass
                
            # Process Parent Lineage Inspection (OS Hierarchy)
            ppid = info['ppid'] or 0
            parent_name = "system"
            if ppid > 0:
                try:
                    p_parent = psutil.Process(ppid)
                    parent_name = p_parent.name()
                except Exception:
                    parent_name = "unknown"
            
            # Detect anomalous parent-child lineage (e.g. browser or office app spawning bash/sh/curl)
            is_lineage_anomaly = False
            suspicious_children = ["sh", "bash", "zsh", "cmd.exe", "powershell.exe", "curl", "wget", "nc", "python"]
            suspicious_parents = ["safari", "chrome", "firefox", "word", "excel", "acrobat", "preview", "slack"]
            if any(name.lower() == sc or name.lower().startswith(sc) for sc in suspicious_children):
                if any(sp in parent_name.lower() for sp in suspicious_parents):
                    is_lineage_anomaly = True
                    lineage_anomaly_count += 1

            processes.append({
                "pid": pid,
                "ppid": ppid,
                "parent_name": parent_name,
                "name": name,
                "exe": info['exe'] or "",
                "cmdline": raw_cmdline,
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem, 1),
                "user": info['username'] or "system",
                "status": proc_status,
                "is_tmp": is_tmp,
                "is_lineage_anomaly": is_lineage_anomaly,
                "is_browser": is_browser,
                "is_browser_tab": is_tab,
                "is_ide": is_ide
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, PermissionError):
            continue
            
    # Purge exited PIDs from CPU tracker
    _last_proc_cpu_times = {pid: v for pid, v in _last_proc_cpu_times.items() if pid in active_pids}
    
    # Detect Multiple Tabs Opening Burst (>=3 new tabs spawned in sampling window)
    new_tab_pids = set()
    multiple_tabs_burst = False
    if _known_browser_tab_pids:
        new_tab_pids = current_tab_pids - _known_browser_tab_pids
        if len(new_tab_pids) >= 3:
            multiple_tabs_burst = True
    _known_browser_tab_pids = current_tab_pids
    
    current_count = len(processes)
    spawn_velocity = max(0.0, (current_count - _last_process_count) / dt) if _last_process_count > 0 else 0.0
    _last_process_count = current_count
    _last_sample_time = current_time
    
    if is_sim_active:
        sim_cpu = _simulated_proc_activity["total_cpu"]
        sim_spawn = _simulated_proc_activity["spawn_rate"]
        tmp_execution_count = max(1, tmp_execution_count)
        total_cpu = max(sim_cpu, total_cpu)
        spawn_velocity = max(sim_spawn, spawn_velocity)
        
        processes.insert(0, {
            "pid": 69420,
            "ppid": 1,
            "name": "xmrig_crypto_miner",
            "exe": "/tmp/xmrig_miner" if sys.platform != "win32" else "C:/Windows/Temp/xmrig_miner.exe",
            "cmdline": "./xmrig --threads=8 --algo=randomx --cpu-priority=5",
            "cpu_percent": round(sim_cpu * 0.96, 1),
            "memory_percent": 18.5,
            "user": "threat_actor",
            "is_tmp": True,
            "is_browser": False,
            "is_browser_tab": False,
            "is_ide": False
        })

    if is_browser_sim_active:
        sim_b_cpu = _simulated_browser_activity["cpu"]
        sim_tab_count = _simulated_browser_activity["tab_count"]
        browser_high_cpu_count = max(1, browser_high_cpu_count)
        multiple_tabs_burst = True
        
        for i in range(sim_tab_count):
            sim_pid = 77000 + i
            processes.insert(0, {
                "pid": sim_pid,
                "ppid": 44970,
                "name": "Google Chrome Helper (Renderer)",
                "exe": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "cmdline": f"--type=renderer --simulation-tab={i}",
                "cpu_percent": round(sim_b_cpu if i == 0 else 45.0, 1),
                "memory_percent": 12.0,
                "user": "browser_user",
                "is_tmp": False,
                "is_browser": True,
                "is_browser_tab": True,
                "is_ide": False
            })
            new_tab_pids.add(sim_pid)
    
    processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
    
    # Priority Selection: NEVER truncate out browser tabs, runaway processes, or tmp executions!
    actionable_pids = set()
    actionable_processes = []
    
    # 1. High CPU processes (miners, runaway scripts)
    for p in processes:
        if p["cpu_percent"] >= 50.0:
            actionable_pids.add(p["pid"])
            actionable_processes.append(p)
            
    # 2. Browser processes & tabs (guarantee they reach triage_and_respond)
    for p in processes:
        if p["is_browser"] and p["pid"] not in actionable_pids:
            actionable_pids.add(p["pid"])
            actionable_processes.append(p)
            
    # 3. Temp executions
    for p in processes:
        if p["is_tmp"] and p["pid"] not in actionable_pids:
            actionable_pids.add(p["pid"])
            actionable_processes.append(p)
            
    # 4. Fill up to 60 with highest CPU processes
    for p in processes:
        if p["pid"] not in actionable_pids and len(actionable_processes) < 60:
            actionable_pids.add(p["pid"])
            actionable_processes.append(p)
    
    return {
        "process_count": current_count + (1 if is_sim_active else 0),
        "processes": actionable_processes,
        "tmp_execution_count": tmp_execution_count,
        "browser_high_cpu_count": browser_high_cpu_count,
        "multiple_tabs_burst": multiple_tabs_burst,
        "new_tab_count": len(new_tab_pids),
        "new_tab_pids": list(new_tab_pids),
        "lineage_anomaly_count": lineage_anomaly_count,
        "avg_cpu_percent": round(total_cpu / max(1, current_count), 2),
        "total_cpu_percent": round(total_cpu, 1),
        "spawn_rate": round(spawn_velocity, 2)
    }
