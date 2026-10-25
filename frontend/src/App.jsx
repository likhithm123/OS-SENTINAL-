import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Navigation from './components/Navigation';
import RiskOverviewGauge from './components/RiskOverviewGauge';
import ProcessMonitor from './components/ProcessMonitor';
import FileMonitor from './components/FileMonitor';
import NetworkMonitor from './components/NetworkMonitor';
import IncidentsList from './components/IncidentsList';
import AttackSimulator from './components/AttackSimulator';
import MLModelMetrics from './components/MLModelMetrics';
import { connectWebSocket, fetchIncidents, simulateAttack, containIncident } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [statusData, setStatusData] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [incidents, setIncidents] = useState([]);

  // Fetch initial incidents and manage WebSocket connection
  useEffect(() => {
    fetchIncidents().then(data => setIncidents(data)).catch(console.error);

    const socket = connectWebSocket(
      (data) => {
        setStatusData(data);
        setIsConnected(true);
        // Refresh incidents if high risk triggered
        if (data?.risk_assessment?.severity === 'HIGH') {
          fetchIncidents().then(d => setIncidents(d)).catch(console.error);
        }
      },
      () => setIsConnected(false),
      () => setIsConnected(false)
    );

    return () => {
      socket.close();
    };
  }, []);

  const handleTerminateProcess = async (pid, processName) => {
    try {
      await containIncident(0, pid, processName, 'TERMINATE');
      const updated = await fetchIncidents();
      setIncidents(updated);
    } catch (e) {
      alert(`Error terminating process: ${e.message}`);
    }
  };

  const handleQuarantineProcess = async (pid, processName) => {
    try {
      await containIncident(0, pid, processName, 'QUARANTINE');
      const updated = await fetchIncidents();
      setIncidents(updated);
    } catch (e) {
      alert(`Error quarantining process: ${e.message}`);
    }
  };

  const handleResumeProcess = async (pid, processName) => {
    try {
      await containIncident(0, pid, processName, 'RESUME');
      const updated = await fetchIncidents();
      setIncidents(updated);
    } catch (e) {
      alert(`Error resuming process: ${e.message}`);
    }
  };

  const handleSimulateAttack = async (attackType) => {
    const res = await simulateAttack(attackType);
    setTimeout(() => {
      fetchIncidents().then(d => setIncidents(d)).catch(console.error);
    }, 1500);
    return res;
  };

  const handleContainIncident = async (incidentId, pid, processName, action) => {
    await containIncident(incidentId, pid, processName, action);
    const updated = await fetchIncidents();
    setIncidents(updated);
  };

  const openIncidentsCount = incidents.filter(i => i.status === 'OPEN').length;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 p-4 md:p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header Bar */}
        <Header statusData={statusData} isConnected={isConnected} />

        {/* Tab Navigation */}
        <Navigation
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          openIncidentsCount={openIncidentsCount}
        />

        {/* Dynamic Tab Views */}
        <main className="transition-all duration-300">
          {activeTab === 'overview' && (
            <RiskOverviewGauge statusData={statusData} />
          )}

          {activeTab === 'processes' && (
            <ProcessMonitor
              procTelemetry={statusData?.process_telemetry || {}}
              onTerminateProcess={handleTerminateProcess}
              onQuarantineProcess={handleQuarantineProcess}
              onResumeProcess={handleResumeProcess}
            />
          )}

          {activeTab === 'files' && (
            <FileMonitor fileTelemetry={statusData?.file_telemetry || {}} />
          )}

          {activeTab === 'network' && (
            <NetworkMonitor netTelemetry={statusData?.network_telemetry || {}} />
          )}

          {activeTab === 'incidents' && (
            <IncidentsList
              incidents={incidents}
              onContainIncident={handleContainIncident}
            />
          )}

          {activeTab === 'simulator' && (
            <AttackSimulator
              onSimulateAttack={handleSimulateAttack}
              activeSim={statusData?.active_simulation}
            />
          )}

          {activeTab === 'ml_metrics' && (
            <MLModelMetrics />
          )}
        </main>

        {/* Footer */}
        <footer className="mt-12 pt-6 border-t border-slate-200 text-center font-mono text-xs text-slate-500">
          OSentinel Host-Based Threat Defense • 2-Stage ML Pipeline • Built for Ubuntu Linux & Extensible Systems
        </footer>
      </div>
    </div>
  );
}
