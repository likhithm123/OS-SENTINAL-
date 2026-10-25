const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
const wsProtocol = isHttps ? 'wss:' : 'ws:';
const hostname = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
const host = typeof window !== 'undefined' ? window.location.host : 'localhost:8000';

const API_BASE = typeof window !== 'undefined' && window.location.port === '5173'
  ? `http://${hostname}:8000/api`
  : `/api`;

const WS_URL = typeof window !== 'undefined' && window.location.port === '5173'
  ? `ws://${hostname}:8000/ws/live`
  : `${wsProtocol}//${host}/ws/live`;

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) throw new Error("Failed to fetch system status");
  return res.json();
}

export async function fetchIncidents() {
  const res = await fetch(`${API_BASE}/incidents`);
  if (!res.ok) throw new Error("Failed to fetch incidents");
  return res.json();
}

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function fetchMLMetrics() {
  const res = await fetch(`${API_BASE}/metrics`);
  if (!res.ok) throw new Error("Failed to fetch ML metrics");
  return res.json();
}

export async function simulateAttack(attackType) {
  const res = await fetch(`${API_BASE}/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_type: attackType })
  });
  if (!res.ok) throw new Error("Failed to trigger attack simulation");
  return res.json();
}

export async function containIncident(incidentId, pid, processName, action = "TERMINATE") {
  const res = await fetch(`${API_BASE}/contain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      incident_id: incidentId,
      pid: pid,
      process_name: processName,
      action: action
    })
  });
  if (!res.ok) throw new Error("Failed to execute containment action");
  return res.json();
}

export async function retrainMLModels() {
  const res = await fetch(`${API_BASE}/retrain`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to trigger model retraining");
  return res.json();
}

export async function fetchRestrictedNetworks() {
  const res = await fetch(`${API_BASE}/network/restricted`);
  if (!res.ok) throw new Error("Failed to fetch restricted networks");
  return res.json();
}

export async function addRestrictedNetwork(networkCidr, description, action = "BLOCK") {
  const res = await fetch(`${API_BASE}/network/restricted`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      network_cidr: networkCidr,
      description: description,
      action: action
    })
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Failed to add restricted network");
  }
  return res.json();
}

export async function deleteRestrictedNetwork(networkId) {
  const res = await fetch(`${API_BASE}/network/restricted/${networkId}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error("Failed to delete restricted network");
  return res.json();
}

export async function toggleRestrictedNetwork(networkId) {
  const res = await fetch(`${API_BASE}/network/restricted/${networkId}/toggle`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to toggle restricted network");
  return res.json();
}

export async function fetchDatasets() {
  const res = await fetch(`${API_BASE}/datasets`);
  if (!res.ok) throw new Error("Failed to fetch datasets");
  return res.json();
}

export async function fetchBenchmarkMetrics() {
  const res = await fetch(`${API_BASE}/datasets/benchmark-metrics`);
  if (!res.ok) throw new Error("Failed to fetch benchmark metrics");
  return res.json();
}

export async function recordLiveSamples(samples = 20, label = "Normal") {
  const res = await fetch(`${API_BASE}/datasets/record-live?samples=${samples}&label=${encodeURIComponent(label)}`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to record live samples");
  return res.json();
}

export async function fetchEntropyDocPreview() {
  const res = await fetch(`${API_BASE}/entropy/preview`);
  if (!res.ok) throw new Error("Failed to fetch entropy document preview");
  return res.json();
}

export async function createEntropyWordDoc() {
  const res = await fetch(`${API_BASE}/entropy/create-doc`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to create entropy word document");
  return res.json();
}

export async function runRapidWordWrites() {
  const res = await fetch(`${API_BASE}/entropy/rapid-writes`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to run rapid word writes");
  return res.json();
}

export async function runRansomwareEncryption() {
  const res = await fetch(`${API_BASE}/entropy/encrypt`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to run ransomware encryption");
  return res.json();
}

export async function restoreEntropyDoc() {
  const res = await fetch(`${API_BASE}/entropy/restore`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to restore entropy document");
  return res.json();
}

export function connectWebSocket(onMessage, onError, onClose) {
  const socket = new WebSocket(WS_URL);

  socket.onopen = () => {
    console.log("[OSentinel WS] Connected to live telemetry stream.");
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error("[OSentinel WS] JSON Parse error:", e);
    }
  };

  socket.onerror = (err) => {
    if (onError) onError(err);
  };

  socket.onclose = () => {
    console.log("[OSentinel WS] Telemetry stream disconnected. Reconnecting in 3s...");
    if (onClose) onClose();
  };

  return socket;
}
