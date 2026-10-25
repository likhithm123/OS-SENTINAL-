import React, { useState, useEffect } from 'react';
import { HardDrive, AlertTriangle, ShieldCheck, FileText, Lock, Play, RefreshCw, Zap, CheckCircle2, ArrowRight } from 'lucide-react';
import {
  fetchEntropyDocPreview,
  createEntropyWordDoc,
  runRapidWordWrites,
  runRansomwareEncryption,
  restoreEntropyDoc
} from '../services/api';

export default function FileMonitor({ fileTelemetry }) {
  const avgEntropy = fileTelemetry.avg_file_entropy ?? 0.0;
  const modRate = fileTelemetry.file_mod_rate ?? 0.0;
  const delRate = fileTelemetry.file_deletion_rate ?? 0.0;
  const isHighEntropy = fileTelemetry.high_entropy_alert;
  const sampleFiles = fileTelemetry.sample_files || [];

  // Live Word Document & Entropy Generator State
  const [docPreview, setDocPreview] = useState(null);
  const [loadingAction, setLoadingAction] = useState(false);
  const [lastActionResult, setLastActionResult] = useState(null);

  useEffect(() => {
    loadDocPreview();
  }, []);

  const loadDocPreview = () => {
    fetchEntropyDocPreview()
      .then(data => setDocPreview(data))
      .catch(err => console.error(err));
  };

  const handleCreateDoc = async () => {
    setLoadingAction(true);
    try {
      const res = await createEntropyWordDoc();
      setDocPreview(res);
      setLastActionResult({
        type: 'NORMAL',
        message: 'Normal word document generated: Plaintext human words, low entropy (H ≈ 4.6 bits/byte).'
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleRapidWrites = async () => {
    setLoadingAction(true);
    try {
      const res = await runRapidWordWrites();
      loadDocPreview();
      setLastActionResult({
        type: 'RAPID_BENIGN',
        message: `Rapid write burst executed: ${res.writes_performed} writes at ${res.write_rate} writes/sec. Entropy remained normal (${res.entropy} bits/byte). Verdict: Benign text operations, no false ransomware alarm!`
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleEncryptRansomware = async () => {
    setLoadingAction(true);
    try {
      const res = await runRansomwareEncryption();
      loadDocPreview();
      setLastActionResult({
        type: 'RANSOMWARE_ENCRYPTED',
        message: `🚨 RANSOMWARE ENCRYPTION DETECTED! Document encrypted with uniform random ciphertext. Shannon Entropy surged to ${res.entropy} / 8.0 bits/byte! Triggered: RULE-RANSOMWARE-01.`
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleRestoreDoc = async () => {
    setLoadingAction(true);
    try {
      const res = await restoreEntropyDoc();
      setDocPreview(res);
      setLastActionResult({
        type: 'RESTORED',
        message: 'Document restored to clean, human-readable corporate words. Entropy normalized.'
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAction(false);
    }
  };

  const currentEntropy = docPreview?.entropy ?? avgEntropy;
  const isDocEncrypted = docPreview?.is_encrypted || currentEntropy >= 7.2;

  return (
    <div className="space-y-6">
      {/* Entropy Alert Banner if High */}
      {(isHighEntropy || isDocEncrypted) && (
        <div className="card-panel p-4 bg-red-50 border-red-300 flex items-center space-x-3 text-red-900 animate-pulse">
          <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0" />
          <div>
            <h4 className="font-extrabold font-mono text-sm uppercase m-0 text-red-800">
              🚨 Ransomware Cryptographic Entropy Alert Triggered!
            </h4>
            <p className="text-xs text-red-700 font-mono m-0 mt-0.5">
              Shannon Entropy reached critical threshold ({currentEntropy} / 8.0 bits/byte). Uniform byte randomization detected consistent with AES / RSA ransomware payload encryption!
            </p>
          </div>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">SHANNON ENTROPY H(X)</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono ${currentEntropy >= 7.2 ? 'text-red-600' : 'text-slate-900'}`}>
              {currentEntropy}
            </span>
            <span className="text-xs text-slate-400 font-mono font-medium">/ 8.0 bits/byte</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Encrypted content threshold: &ge; 7.2 bits/byte
          </p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">FILE MODIFICATION RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-900">{modRate}</span>
            <span className="text-xs text-slate-400 font-mono font-medium">writes / sec</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Rapid encryption velocity threshold: &ge; 15 writes/sec
          </p>
        </div>

        <div className="card-panel p-5">
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider font-mono m-0">DELETION BURST RATE</p>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-900">{delRate}</span>
            <span className="text-xs text-slate-400 font-mono font-medium">deletions / sec</span>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono m-0">
            Mass deletion threshold: &ge; 10 deletes/sec
          </p>
        </div>
      </div>

      {/* INTERACTIVE GENERATOR & ENTROPY VISUALIZER */}
      <div className="card-panel p-6 space-y-6 border-slate-300 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
          <div>
            <h3 className="text-base font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center gap-2 m-0">
              <FileText className="w-5 h-5 text-blue-600" />
              <span>Word Document & Shannon Entropy Interactive Generator</span>
            </h3>
            <p className="text-xs text-slate-500 font-medium m-0 mt-1">
              Generate real word documents, test fast read/write velocity, and visualize how OSentinel detects ransomware encryption vs normal text.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={handleCreateDoc}
              disabled={loadingAction}
              className="px-3 py-2 text-xs font-mono font-bold rounded bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 transition-colors flex items-center gap-1.5"
            >
              <FileText className="w-3.5 h-3.5 text-slate-600" />
              <span>1. OPEN NORMAL WORD DOC</span>
            </button>

            <button
              onClick={handleRapidWrites}
              disabled={loadingAction}
              className="px-3 py-2 text-xs font-mono font-bold rounded bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 transition-colors flex items-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5 text-amber-600" />
              <span>2. FAST READ/WRITE BURST</span>
            </button>

            <button
              onClick={handleEncryptRansomware}
              disabled={loadingAction}
              className="px-3 py-2 text-xs font-mono font-bold rounded shadow-sm transition-colors flex items-center gap-1.5"
              style={{ backgroundColor: '#dc2626', color: '#ffffff', border: '1px solid #b91c1c' }}
            >
              <Lock className="w-3.5 h-3.5" style={{ color: '#ffffff' }} />
              <span style={{ color: '#ffffff' }}>3. SIMULATE RANSOMWARE ENCRYPT</span>
            </button>

            <button
              onClick={handleRestoreDoc}
              disabled={loadingAction}
              className="px-3 py-2 text-xs font-mono font-bold rounded transition-colors flex items-center gap-1.5"
              style={{ backgroundColor: '#0f172a', color: '#ffffff', border: '1px solid #0f172a' }}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAction ? 'animate-spin' : ''}`} style={{ color: '#ffffff' }} />
              <span style={{ color: '#ffffff' }}>RESTORE WORDS</span>
            </button>
          </div>
        </div>

        {/* Action Result Notification Banner */}
        {lastActionResult && (
          <div className={`p-3 rounded-lg border font-mono text-xs flex items-center gap-2 ${
            lastActionResult.type === 'RANSOMWARE_ENCRYPTED'
              ? 'bg-red-50 text-red-900 border-red-300'
              : lastActionResult.type === 'RAPID_BENIGN'
              ? 'bg-amber-50 text-amber-900 border-amber-300'
              : 'bg-emerald-50 text-emerald-900 border-emerald-300'
          }`}>
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>{lastActionResult.message}</span>
          </div>
        )}

        {/* Real-time Entropy Gauge & Visualizer Card */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Shannon Entropy Spectrum Meter (4 Cols) */}
          <div className="lg:col-span-4 p-5 bg-slate-50 rounded-lg border border-slate-200 font-mono space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-slate-700 uppercase">SHANNON ENTROPY METER</span>
              <span className={`badge-clean font-mono text-[10px] ${isDocEncrypted ? 'badge-rose' : 'badge-emerald'}`}>
                {isDocEncrypted ? 'CRITICAL THREAT' : 'NORMAL / PLAINTEXT'}
              </span>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-2xl font-extrabold text-slate-900">
                <span>{currentEntropy}</span>
                <span className="text-xs text-slate-400 self-end">8.0 MAX</span>
              </div>

              {/* Multi-zone entropy bar */}
              <div className="w-full h-3 bg-slate-200 rounded-full overflow-hidden flex">
                <div style={{ width: '62.5%' }} className="bg-emerald-500 h-full" title="Plaintext Zone (0 - 5.0)" />
                <div style={{ width: '27.5%' }} className="bg-amber-400 h-full" title="Compressed Zone (5.0 - 7.2)" />
                <div style={{ width: '10%' }} className="bg-red-600 h-full" title="Ciphertext Threat Zone (7.2 - 8.0)" />
              </div>

              {/* Marker pin */}
              <div className="w-full relative h-3">
                <div
                  style={{
                    left: `${Math.min(100, (currentEntropy / 8.0) * 100)}%`,
                    transition: 'left 0.5s ease-out'
                  }}
                  className="absolute -top-1 w-2.5 h-2.5 bg-slate-900 rotate-45 transform -translate-x-1/2"
                />
              </div>

              <div className="flex justify-between text-[10px] text-slate-500 pt-1 font-bold">
                <span>0.0 (Uniform)</span>
                <span>5.0 (Words)</span>
                <span className="text-red-600 font-extrabold">7.2 (Alert)</span>
                <span>8.0</span>
              </div>
            </div>

            <div className="p-3 bg-white rounded border border-slate-200 text-[11px] text-slate-600 space-y-1.5">
              <div className="font-bold text-slate-800">Detection Formula:</div>
              <div className="font-mono bg-slate-50 p-1.5 rounded text-[10px] text-slate-700">
                H(X) = -∑ P(x) · log₂(P(x))
              </div>
              <div className="text-[10px] text-slate-500">
                • <strong>Normal Words</strong>: Letter frequencies are non-uniform (e.g. 'e', 't', spaces are frequent) → H ≈ 4.6<br/>
                • <strong>Ransomware</strong>: AES encryption spreads bytes uniformly across all 256 values → H ≈ 7.98
              </div>
            </div>
          </div>

          {/* Document Content & Hex Byte Stream Viewer (8 Cols) */}
          <div
            className="lg:col-span-8 p-5 rounded-lg font-mono space-y-4"
            style={{ backgroundColor: '#0f172a', color: '#f8fafc', border: '1px solid #1e293b' }}
          >
            <div className="flex justify-between items-center flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
                <span className="text-xs font-bold tracking-wide" style={{ color: '#f8fafc' }}>
                  FILE INSPECTION: {docPreview?.file_name || 'corporate_quarterly_report.txt'}
                </span>
              </div>
              <span
                className="px-2.5 py-1 rounded text-[11px] font-extrabold uppercase font-mono"
                style={{
                  backgroundColor: isDocEncrypted ? '#450a0a' : '#022c22',
                  color: isDocEncrypted ? '#fca5a5' : '#6ee7b7',
                  border: isDocEncrypted ? '1px solid #b91c1c' : '1px solid #059669'
                }}
              >
                {docPreview?.category || 'PLAINTEXT / LOW'}
              </span>
            </div>

            {/* Document Text / Word Preview */}
            <div className="space-y-1.5">
              <div className="text-[11px] uppercase font-bold tracking-wider font-mono" style={{ color: '#94a3b8' }}>
                DOCUMENT CONTENT PREVIEW:
              </div>
              <div
                className="p-3.5 rounded text-xs whitespace-pre-wrap max-h-36 overflow-y-auto leading-relaxed font-mono"
                style={{
                  backgroundColor: '#020617',
                  color: '#f8fafc',
                  border: '1px solid #334155',
                  boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.6)'
                }}
              >
                {docPreview?.text_preview || "Loading document words..."}
              </div>
            </div>

            {/* Raw Byte Hex Distribution */}
            <div className="space-y-1.5">
              <div className="text-[11px] uppercase font-bold tracking-wider font-mono" style={{ color: '#94a3b8' }}>
                BYTE STREAM SAMPLE (HEX DISTRIBUTION):
              </div>
              <div
                className="p-3 rounded text-[12px] font-mono break-all overflow-x-auto font-bold tracking-wider"
                style={{
                  backgroundColor: '#020617',
                  color: '#34d399',
                  border: '1px solid #334155',
                  boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.6)'
                }}
              >
                {docPreview?.hex_preview || "00 00 00 00"}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sample Monitored Files Table */}
      <div className="card-panel p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-extrabold text-slate-900 font-mono uppercase tracking-wider flex items-center space-x-2 m-0">
            <HardDrive className="w-5 h-5 text-slate-800" />
            <span>Monitored File System Watchdog & Entropy Inspector</span>
          </h3>
          <span className="badge-clean badge-neutral font-mono">
            {sampleFiles.length} FILES TRACKED
          </span>
        </div>

        <div className="data-table-container">
          <table className="clean-table">
            <thead>
              <tr>
                <th>Monitored File Path</th>
                <th>Entropy Score H(X)</th>
                <th>Entropy Category</th>
                <th style={{ textAlign: 'right' }}>Security Status</th>
              </tr>
            </thead>
            <tbody>
              {sampleFiles.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b' }}>
                    No file system write events intercepted in active window.
                  </td>
                </tr>
              ) : (
                sampleFiles.map((file, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-xs font-semibold text-slate-800">
                      {file.path}
                    </td>
                    <td className="font-mono font-bold text-slate-900">
                      {file.entropy} bits/byte
                    </td>
                    <td>
                      {file.entropy >= 7.2 ? (
                        <span className="badge-clean badge-rose font-mono">ENCRYPTED / HIGH ENTROPY</span>
                      ) : file.entropy >= 5.0 ? (
                        <span className="badge-clean badge-amber font-mono">COMPRESSED / NORMAL</span>
                      ) : (
                        <span className="badge-clean badge-emerald font-mono">PLAINTEXT / LOW</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <span className={`badge-clean ${file.status === 'SUSPICIOUS' || file.status === 'ENCRYPTED' ? 'badge-rose' : 'badge-emerald'}`}>
                        {file.status || 'NORMAL'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
