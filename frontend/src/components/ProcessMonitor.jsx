import React, { useState } from 'react';
import { Cpu, Search, AlertTriangle, Trash2, CheckCircle2 } from 'lucide-react';

export default function ProcessMonitor({ procTelemetry, onTerminateProcess, onQuarantineProcess, onResumeProcess }) {
  const [search, setSearch] = useState('');
  const processes = procTelemetry.processes || [];

  const filtered = processes.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.pid.toString().includes(search) ||
    (p.cmdline && p.cmdline.toLowerCase().includes(search.toLowerCase())) ||
    (p.parent_name && p.parent_name.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="card-panel p-6 space-y-4">
      {/* Table Header & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
            <Cpu className="w-5 h-5 text-slate-800" />
            <span>Process Monitor, Lineage & Reversible Containment</span>
          </h3>
          <p className="text-xs text-slate-500 m-0 mt-1 font-medium">
            Active processes: <strong className="text-slate-900">{procTelemetry.process_count ?? 0}</strong> • Spawn rate: <strong className="text-slate-900">{procTelemetry.spawn_rate ?? 0}/s</strong>
            {procTelemetry.lineage_anomaly_count > 0 && (
              <span className="ml-2 text-red-600 font-bold">• Lineage Anomalies: {procTelemetry.lineage_anomaly_count}</span>
            )}
          </p>
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
          <Search className="w-4 h-4 text-slate-400" style={{ position: 'absolute', left: '10px', top: '10px' }} />
          <input
            type="text"
            placeholder="Search PID, parent, name, cmd..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              paddingLeft: '32px',
              paddingRight: '12px',
              paddingTop: '8px',
              paddingBottom: '8px',
              backgroundColor: '#ffffff',
              border: '1.5px solid #cbd5e1',
              borderRadius: '6px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              color: '#0f172a',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {/* Process Table */}
      <div className="data-table-container">
        <table className="clean-table">
          <thead>
            <tr>
              <th>PID / Ancestry</th>
              <th>Process Name</th>
              <th>CPU %</th>
              <th>RAM %</th>
              <th>State & Lineage</th>
              <th style={{ textAlign: 'right' }}>OS Containment Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b' }}>
                  No matching processes found.
                </td>
              </tr>
            ) : (
              filtered.slice(0, 50).map((proc) => {
                const isQuarantined = proc.status === 'QUARANTINED';
                return (
                  <tr key={proc.pid} className={isQuarantined ? "bg-amber-50/50" : ""}>
                    <td className="font-mono font-bold text-slate-900">
                      <div>{proc.pid} <span className="text-slate-400 font-normal">({proc.ppid})</span></div>
                      <div className="text-[10px] text-slate-500 font-normal truncate max-w-[130px]">
                        Parent: <span className="text-slate-700 font-medium">{proc.parent_name || "init"}</span>
                      </div>
                    </td>
                    <td>
                      <strong className="text-slate-900 font-bold block">{proc.name}</strong>
                      <span className="text-[11px] font-mono text-slate-500 truncate block" style={{ maxWidth: '240px' }}>
                        {proc.cmdline}
                      </span>
                    </td>
                    <td className="font-mono">
                      <span className={proc.cpu_percent > 50 ? "text-red-700 font-extrabold" : "text-slate-700 font-bold"}>
                        {proc.cpu_percent}%
                      </span>
                    </td>
                    <td className="font-mono text-slate-700 font-bold">
                      {proc.memory_percent}%
                    </td>
                    <td>
                      <div className="flex flex-col gap-1 items-start">
                        {isQuarantined ? (
                          <span className="badge-clean badge-amber font-mono text-[10px] bg-amber-100 text-amber-900 border-amber-300">
                            ⏸ QUARANTINED (SIGSTOP)
                          </span>
                        ) : (
                          <span className="badge-clean badge-emerald font-mono text-[10px]">
                            ▶ RUNNING
                          </span>
                        )}

                        {proc.is_lineage_anomaly && (
                          <span className="badge-clean badge-rose font-mono text-[10px]">
                            <AlertTriangle className="w-2.5 h-2.5" />
                            LINEAGE ANOMALY
                          </span>
                        )}

                        {proc.is_tmp && (
                          <span className="badge-clean badge-rose font-mono text-[10px]">
                            SPAWNED FROM /TMP
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div className="flex items-center justify-end gap-1.5">
                        {isQuarantined ? (
                          <button
                            onClick={() => onResumeProcess && onResumeProcess(proc.pid, proc.name)}
                            className="btn-bold-secondary"
                            style={{ padding: '4px 8px', fontSize: '11px', color: '#047857', borderColor: '#a7f3d0', backgroundColor: '#ecfdf5' }}
                            title="Resume process execution using POSIX SIGCONT"
                          >
                            <span>RESUME (CONT)</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => onQuarantineProcess && onQuarantineProcess(proc.pid, proc.name)}
                            className="btn-bold-secondary"
                            style={{ padding: '4px 8px', fontSize: '11px', color: '#b45309', borderColor: '#fde68a', backgroundColor: '#fffbeb' }}
                            title="Suspend process execution using POSIX SIGSTOP (Reversible Quarantine)"
                          >
                            <span>FREEZE (STOP)</span>
                          </button>
                        )}
                        <button
                          onClick={() => onTerminateProcess(proc.pid, proc.name)}
                          className="btn-bold-danger"
                          style={{ padding: '4px 8px', fontSize: '11px' }}
                          title="Terminate Process permanently"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>KILL</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
