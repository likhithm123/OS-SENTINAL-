import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, ChevronRight, Trash2, X } from 'lucide-react';

export default function IncidentsList({ incidents, onContainIncident }) {
  const [selectedIncident, setSelectedIncident] = useState(null);

  return (
    <div className="space-y-6">
      <div className="card-panel p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
              <AlertTriangle className="w-5 h-5 text-red-600" />
              <span>Security Incidents & Automated Containment Triage</span>
            </h3>
            <p className="text-xs text-slate-500 mt-1 m-0 font-medium">
              High-risk threats (Risk Score &ge; 70) logged for forensic investigation and operator containment
            </p>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="data-table-container">
          <table className="clean-table">
            <thead>
              <tr>
                <th>Incident Code</th>
                <th>Threat Category</th>
                <th>Risk Score</th>
                <th>Target Process</th>
                <th>Containment Action</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
                    <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
                    <p className="text-sm font-bold text-slate-800 m-0">No active security incidents</p>
                    <p className="text-xs text-slate-500 m-0 mt-1">All telemetry is within baseline operating parameters.</p>
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  return (
                    <tr key={inc.id}>
                      <td className="font-mono font-bold text-slate-900">{inc.incident_code}</td>
                      <td>
                        <span className="badge-clean badge-rose font-mono">
                          {inc.threat_category}
                        </span>
                      </td>
                      <td className="font-mono font-extrabold text-red-600 text-sm">
                        {inc.risk_score} / 100
                      </td>
                      <td>
                        <strong className="text-slate-900 font-bold block">{inc.process_name}</strong>
                        <span className="text-slate-500 text-[11px] font-mono">PID: {inc.pid}</span>
                      </td>
                      <td className="text-slate-700 font-mono text-xs">
                        {inc.containment_action}
                      </td>
                      <td>
                        <span className={`badge-clean ${
                          inc.status === 'OPEN' ? 'badge-rose' :
                          inc.status === 'RESOLVED' ? 'badge-emerald' :
                          'badge-neutral'
                        }`}>
                          {inc.status}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="btn-bold-secondary"
                          style={{ padding: '6px 12px', fontSize: '11px' }}
                        >
                          <span>INSPECT EVIDENCE</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Evidence Modal View */}
      {selectedIncident && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div>
                <h3 className="text-base font-extrabold font-mono text-slate-900 flex items-center space-x-2 m-0">
                  <ShieldAlert className="w-5 h-5 text-red-600" />
                  <span>Forensic Audit: {selectedIncident.incident_code}</span>
                </h3>
                <p className="text-xs text-slate-500 font-mono m-0 mt-1">Logged Timestamp: {selectedIncident.timestamp}</p>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1.5 rounded-md hover:bg-slate-100 text-slate-500 cursor-pointer border-0 bg-transparent"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono my-4">
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                <span className="text-slate-500 block mb-0.5">Threat Category</span>
                <span className="text-red-700 font-extrabold text-sm">{selectedIncident.threat_category}</span>
              </div>
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                <span className="text-slate-500 block mb-0.5">Assigned Risk Score</span>
                <span className="text-red-700 font-extrabold text-sm">{selectedIncident.risk_score} / 100</span>
              </div>
            </div>

            {/* Containment Override Action Bar */}
            {(selectedIncident.status === 'OPEN' || selectedIncident.status === 'QUARANTINED') && (
              <div className="p-4 rounded-lg bg-red-50 border border-red-200 flex flex-col sm:flex-row items-center justify-between gap-3 mb-4">
                <div>
                  <h4 className="font-extrabold text-xs text-red-900 uppercase font-mono m-0">Operator Containment Actions</h4>
                  <p className="text-xs text-slate-600 font-mono m-0 mt-0.5">Control process execution state for PID {selectedIncident.pid} ({selectedIncident.process_name})</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedIncident.status === 'QUARANTINED' ? (
                    <button
                      onClick={() => {
                        onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "RESUME");
                        setSelectedIncident(null);
                      }}
                      className="btn-bold-secondary"
                      style={{ padding: '6px 12px', fontSize: '11px', color: '#047857', borderColor: '#a7f3d0', backgroundColor: '#ecfdf5' }}
                    >
                      <span>RESUME (SIGCONT)</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => {
                        onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "QUARANTINE");
                        setSelectedIncident(null);
                      }}
                      className="btn-bold-secondary"
                      style={{ padding: '6px 12px', fontSize: '11px', color: '#b45309', borderColor: '#fde68a', backgroundColor: '#fffbeb' }}
                    >
                      <span>FREEZE (SIGSTOP)</span>
                    </button>
                  )}
                  <button
                    onClick={() => {
                      onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "TERMINATE");
                      setSelectedIncident(null);
                    }}
                    className="btn-bold-danger"
                    style={{ padding: '6px 12px', fontSize: '11px' }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>TERMINATE</span>
                  </button>
                  <button
                    onClick={() => {
                      onContainIncident(selectedIncident.id, selectedIncident.pid, selectedIncident.process_name, "IGNORE");
                      setSelectedIncident(null);
                    }}
                    className="btn-bold-secondary"
                    style={{ padding: '6px 12px', fontSize: '11px' }}
                  >
                    DISMISS
                  </button>
                </div>
              </div>
            )}

            {/* Evidence Payload */}
            <div className="space-y-2 font-mono text-xs">
              <h4 className="text-xs font-extrabold text-slate-800 uppercase m-0">Evidence Telemetry Dump:</h4>
              <pre className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-slate-800 overflow-x-auto text-[11px] leading-relaxed">
                {JSON.stringify(JSON.parse(selectedIncident.evidence || '{}'), null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
