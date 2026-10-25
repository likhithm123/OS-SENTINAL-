import psutil
import time
import ipaddress
from backend.config import SUSPICIOUS_PORTS
from backend.database import get_restricted_networks

_simulated_net_activity = None
_last_net_bytes = None
_last_net_time = time.time()

LOOPBACK_NAMES = ["lo", "lo0", "loopback", "127.0.0.1"]

def extract_ip_address(addr_str: str) -> str:
    """Extracts raw IP address without port or interface identifier."""
    if not addr_str:
        return ""
    if ":" in addr_str:
        if addr_str.startswith("[") and "]:" in addr_str:
            return addr_str[1:].split("]:")[0]
        parts = addr_str.split(":")
        if len(parts) == 2:
            return parts[0]
        return addr_str
    return addr_str

def match_restricted_ip(ip_str: str, restricted_list: list) -> tuple:
    """
    Checks if an IP address belongs to any configured restricted network or IP.
    Returns (is_restricted: bool, matched_cidr: str, description: str, action: str)
    """
    clean_ip = extract_ip_address(ip_str)
    if not clean_ip:
        return False, "", "", ""
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, "", "", ""
        
    for item in restricted_list:
        if not item.get("is_active", 1):
            continue
        cidr = item.get("network_cidr", "").strip()
        if not cidr:
            continue
        try:
            net_obj = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in net_obj:
                return True, cidr, item.get("description", ""), item.get("action", "BLOCK")
        except ValueError:
            continue
            
    return False, "", "", ""

def set_simulated_network_activity(
    outbound_conns: int,
    suspicious_port_flag: int,
    data_exfil_kb_sec: float,
    restricted_ip_flag: int = 0,
    simulated_raddr: str = None
):
    global _simulated_net_activity
    _simulated_net_activity = {
        "outbound_conns": outbound_conns,
        "suspicious_port_flag": suspicious_port_flag,
        "data_exfil_kb_sec": data_exfil_kb_sec,
        "restricted_ip_flag": restricted_ip_flag,
        "simulated_raddr": simulated_raddr,
        "expire_time": time.time() + 4.0
    }

def get_real_external_network_io_rate() -> float:
    """Calculates real network outbound upload rate in KB/sec excluding localhost loopback."""
    global _last_net_bytes, _last_net_time
    now = time.time()
    dt = max(0.2, now - _last_net_time)
    
    try:
        per_nic = psutil.net_io_counters(pernic=True)
        # Sum only real external network interfaces (exclude lo0, loopback)
        total_external_sent = 0
        for nic_name, stats in per_nic.items():
            if not any(lb in nic_name.lower() for lb in LOOPBACK_NAMES):
                total_external_sent += stats.bytes_sent
                
        if _last_net_bytes is None:
            _last_net_bytes = total_external_sent
            _last_net_time = now
            return 2.5
        
        bytes_sent_delta = max(0, total_external_sent - _last_net_bytes)
        kb_sec = (bytes_sent_delta / 1024.0) / dt
        _last_net_bytes = total_external_sent
        _last_net_time = now
        return round(kb_sec, 1)
    except Exception:
        return 2.5

def collect_network_telemetry():
    global _simulated_net_activity
    
    current_time = time.time()
    restricted_list = []
    try:
        restricted_list = get_restricted_networks()
    except Exception:
        restricted_list = []
    
    active_restricted_count = len([r for r in restricted_list if r.get("is_active", 1)])
    
    # Check if UI web simulation is active
    if _simulated_net_activity and current_time < _simulated_net_activity["expire_time"]:
        sim_restricted = bool(_simulated_net_activity.get("restricted_ip_flag", 0))
        sim_raddr = _simulated_net_activity.get("simulated_raddr") or ("198.51.100.45:8080" if sim_restricted else ("127.0.0.1:4444" if _simulated_net_activity["suspicious_port_flag"] else "93.184.216.34:443"))
        
        sim_conn = {
            "fd": 12, "family": "IPv4", "type": "TCP",
            "laddr": "127.0.0.1:49210",
            "raddr": sim_raddr,
            "status": "ESTABLISHED",
            "pid": 9821,
            "is_suspicious": bool(_simulated_net_activity["suspicious_port_flag"]),
            "is_restricted": sim_restricted,
            "matched_network": "198.51.100.0/24" if sim_restricted else "",
            "restricted_reason": "RFC 5737 Test-Net-2 (Restricted External Subnet)" if sim_restricted else "",
            "restriction_action": "BLOCK" if sim_restricted else ""
        }
        
        return {
            "outbound_conn_count": _simulated_net_activity["outbound_conns"],
            "suspicious_port_flag": _simulated_net_activity["suspicious_port_flag"],
            "restricted_ip_flag": 1 if sim_restricted else 0,
            "restricted_conns_count": 1 if sim_restricted else 0,
            "data_exfil_kb_sec": _simulated_net_activity["data_exfil_kb_sec"],
            "connections": [sim_conn],
            "restricted_networks_count": active_restricted_count
        }
    else:
        _simulated_net_activity = None

    connections = []
    outbound_count = 0
    suspicious_flag = 0
    restricted_flag = 0
    restricted_count = 0
    real_exfil_rate = get_real_external_network_io_rate()
    
    try:
        net_conns = psutil.net_connections(kind='inet')
        for conn in net_conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            
            is_susp = 0
            if conn.raddr:
                outbound_count += 1
                if conn.raddr.port in SUSPICIOUS_PORTS:
                    is_susp = 1
                    suspicious_flag = 1
            
            # Check restricted IP networks
            is_restr, restr_cidr, restr_desc, restr_act = match_restricted_ip(conn.raddr.ip if conn.raddr else "", restricted_list)
            if not is_restr and conn.laddr:
                is_restr, restr_cidr, restr_desc, restr_act = match_restricted_ip(conn.laddr.ip, restricted_list)
                
            if is_restr:
                restricted_flag = 1
                restricted_count += 1
                    
            if conn.status in ["ESTABLISHED", "LISTEN", "SYN_SENT"]:
                connections.append({
                    "fd": conn.fd if hasattr(conn, 'fd') else 0,
                    "family": "IPv4" if conn.family == 2 else "IPv6",
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": conn.status,
                    "pid": conn.pid or 0,
                    "is_suspicious": bool(is_susp),
                    "is_restricted": is_restr,
                    "matched_network": restr_cidr if is_restr else "",
                    "restricted_reason": restr_desc if is_restr else "",
                    "restriction_action": restr_act if is_restr else ""
                })
    except (psutil.AccessDenied, PermissionError):
        # Fallback for non-root systems on macOS / Ubuntu / Windows:
        priority_conns = []
        normal_conns = []
        try:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    for c in p.connections(kind='inet'):
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                        is_susp = 0
                        if c.raddr:
                            outbound_count += 1
                            if c.raddr.port in SUSPICIOUS_PORTS:
                                is_susp = 1
                                suspicious_flag = 1
                                
                        is_restr, restr_cidr, restr_desc, restr_act = match_restricted_ip(c.raddr.ip if c.raddr else "", restricted_list)
                        if not is_restr and c.laddr:
                            is_restr, restr_cidr, restr_desc, restr_act = match_restricted_ip(c.laddr.ip, restricted_list)
                            
                        if is_restr:
                            restricted_flag = 1
                            restricted_count += 1

                        if c.status in ["ESTABLISHED", "LISTEN", "SYN_SENT", "TIME_WAIT"]:
                            conn_entry = {
                                "fd": 0,
                                "family": "IPv4",
                                "type": "TCP",
                                "laddr": laddr,
                                "raddr": raddr,
                                "status": c.status,
                                "pid": p.pid,
                                "is_suspicious": bool(is_susp),
                                "is_restricted": is_restr,
                                "matched_network": restr_cidr if is_restr else "",
                                "restricted_reason": restr_desc if is_restr else "",
                                "restriction_action": restr_act if is_restr else ""
                            }
                            if is_restr or is_susp:
                                priority_conns.append(conn_entry)
                            elif len(normal_conns) < 35:
                                normal_conns.append(conn_entry)
                except Exception:
                    continue
            connections = priority_conns + normal_conns
        except Exception:
            pass
    except Exception:
        pass
        
    # Sort connections so restricted and suspicious are always at the top
    connections.sort(key=lambda x: (not x.get("is_restricted"), not x.get("is_suspicious")))
        
    return {
        "outbound_conn_count": max(outbound_count, len(connections)),
        "suspicious_port_flag": suspicious_flag,
        "restricted_ip_flag": restricted_flag,
        "restricted_conns_count": restricted_count,
        "data_exfil_kb_sec": max(real_exfil_rate, 2.5),
        "connections": connections[:50],
        "restricted_networks_count": active_restricted_count
    }
