import React, { useState, useEffect, useCallback } from 'react';
import { 
  Zap, 
  ShieldCheck, 
  ShieldAlert,
  Lock, 
  UserX, 
  AlertTriangle, 
  RefreshCw, 
  ArrowRight,
  FileText,
  Filter,
  Eye,
  History,
  CheckCircle,
  ExternalLink,
  Shield
} from 'lucide-react';
import { api } from '../api/client';

const levelClasses = {
  LOW: 'bg-emerald-950/60 border-emerald-800 text-emerald-300',
  MEDIUM: 'bg-blue-950/60 border-blue-800 text-blue-300',
  HIGH: 'bg-amber-950/60 border-amber-800 text-amber-300',
  CRITICAL: 'bg-red-950/70 border-red-700 text-red-300'
};

function RiskBadge({ level }) {
  const value = String(level || 'LOW').toUpperCase();
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${levelClasses[value] || levelClasses.LOW}`}>
      {value}
    </span>
  );
}

export default function ResponseAudit({ onNavigate }) {
  const [enforcements, setEnforcements] = useState([]);
  const [policySummary, setPolicySummary] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionFilter, setActionFilter] = useState('');

  // Modals
  const [selectedUserForOverride, setSelectedUserForOverride] = useState(null);
  const [overrideAction, setOverrideAction] = useState('RESTORE');
  const [overrideReason, setOverrideReason] = useState('Analyst verified legitimate activity');
  const [overrideLoading, setOverrideLoading] = useState(false);

  const [selectedUserHistory, setSelectedUserHistory] = useState(null);
  const [selectedAuditPayload, setSelectedAuditPayload] = useState(null);

  const loadAllData = useCallback(async () => {
    try {
      setRefreshing(true);
      const [enfList, summary, logs] = await Promise.all([
        api.listEnforcements().catch(() => []),
        api.getPolicySummary().catch(() => null),
        api.listAuditLogs(actionFilter || null, 150).catch(() => []),
      ]);
      setEnforcements(Array.isArray(enfList) ? enfList : []);
      setPolicySummary(summary);
      setAuditLogs(Array.isArray(logs) ? logs : []);
    } catch (err) {
      console.error('Failed to load response and audit data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [actionFilter]);

  useEffect(() => {
    loadAllData();
  }, [loadAllData]);

  const handleExecuteOverride = async () => {
    if (!selectedUserForOverride) return;
    try {
      setOverrideLoading(true);
      await api.overrideEnforcement(
        selectedUserForOverride.cloud_user_id,
        overrideAction,
        overrideReason
      );
      setSelectedUserForOverride(null);
      await loadAllData();
    } catch (err) {
      alert(`Override failed: ${err.message}`);
    } finally {
      setOverrideLoading(false);
    }
  };

  // Helper to extract identity from audit log
  const getAuditUser = (log) => {
    if (log.resource && log.resource.startsWith('cloud_user/')) {
      return log.resource.replace('cloud_user/', '');
    }
    if (log.detail?.cloud_user_id) {
      return log.detail.cloud_user_id;
    }
    if (log.detail?.username) {
      return log.detail.username;
    }
    return log.resource || 'System';
  };

  const formatUtcTimestamp = (ts) => {
    if (!ts) return 'N/A';
    try {
      const date = new Date(ts);
      return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return String(ts);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 uppercase tracking-widest font-mono mb-1">
            <Zap className="w-3.5 h-3.5" />
            Autonomous Protection & Compliance
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Response & Audit</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Risk-adaptive automated protection policies, active enforcement registry, and immutable compliance audit trail.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadAllData}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-xs text-slate-300 flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh Workspace</span>
          </button>
        </div>
      </div>

      {/* KPI Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>MONITORED IDENTITIES</span>
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white mt-2">
            {policySummary?.total_monitored_users ?? enforcements.length}
          </div>
          <div className="text-xs text-slate-500 mt-1 font-mono">
            Active continuous assessment
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>ACTIVE / MONITORING</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-emerald-400 mt-2">
            {policySummary?.active_users ?? enforcements.filter(e => e.status === 'ACTIVE').length}
          </div>
          <div className="text-xs text-emerald-500/80 mt-1 font-mono">
            Normal operational baseline
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>AUTOMATICALLY RESTRICTED</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-amber-400 mt-2">
            {policySummary?.restricted_users ?? enforcements.filter(e => e.status === 'RESTRICTED').length}
          </div>
          <div className="text-xs text-amber-500/80 mt-1 font-mono">
            Privilege & IAM quarantine
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>AUTOMATICALLY BLOCKED</span>
            <UserX className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-3xl font-bold text-red-400 mt-2">
            {policySummary?.blocked_users ?? enforcements.filter(e => e.status === 'BLOCKED').length}
          </div>
          <div className="text-xs text-red-500/80 mt-1 font-mono">
            Revoked sessions & lockouts
          </div>
        </div>
      </div>

      {/* 1. Current Response Policy Matrix */}
      <section className="bg-[#090e1a] border border-slate-800/90 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Current Response Policy Matrix
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Autonomous, risk-driven mitigation policies mapped dynamically to user risk progression.
            </p>
          </div>
          <span className="text-[11px] font-mono text-cyan-400 font-semibold px-2.5 py-1 rounded-lg bg-cyan-950/50 border border-cyan-800/50 self-start sm:self-auto">
            Mode: Real-Time Auto-Enforce
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* LOW */}
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-emerald-400">LOW (0–24)</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <span>Low</span>
              <ArrowRight className="w-3 h-3 text-slate-500" />
              <span className="text-emerald-300">Monitor</span>
            </p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Standard continuous user behavior monitoring. No access restrictions applied.
            </p>
            <div className="pt-1 text-[10px] font-mono text-emerald-400/70">
              Policy Action: Monitor
            </div>
          </div>

          {/* MEDIUM */}
          <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-blue-400">MEDIUM (25–49)</span>
              <AlertTriangle className="w-4 h-4 text-blue-400" />
            </div>
            <p className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <span>Medium</span>
              <ArrowRight className="w-3 h-3 text-slate-500" />
              <span className="text-blue-300">Alert + Monitor</span>
            </p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Generates operational alerts in SOC console and escalates telemetry sampling frequency.
            </p>
            <div className="pt-1 text-[10px] font-mono text-blue-400/70">
              Policy Action: Alert + Monitor
            </div>
          </div>

          {/* HIGH */}
          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-amber-400">HIGH (50–74)</span>
              <Lock className="w-4 h-4 text-amber-400" />
            </div>
            <p className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <span>High</span>
              <ArrowRight className="w-3 h-3 text-slate-500" />
              <span className="text-amber-300">Automatically Restrict</span>
            </p>
            <p className="text-[11px] text-amber-200/80 leading-relaxed">
              Quarantines high-privilege IAM/KMS actions, isolates credential manipulation, logs automated restriction.
            </p>
            <div className="pt-1 text-[10px] font-mono text-amber-400/70">
              Policy Action: Automatically Restrict
            </div>
          </div>

          {/* CRITICAL */}
          <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-red-400">CRITICAL (75+)</span>
              <UserX className="w-4 h-4 text-red-400" />
            </div>
            <p className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <span>Critical</span>
              <ArrowRight className="w-3 h-3 text-slate-500" />
              <span className="text-red-300">Automatically Block</span>
            </p>
            <p className="text-[11px] text-red-200/80 leading-relaxed">
              Revokes active session tokens, blocks API access, creates critical incident, and triggers lockdown.
            </p>
            <div className="pt-1 text-[10px] font-mono text-red-400/70">
              Policy Action: Automatically Block
            </div>
          </div>
        </div>
      </section>

      {/* 2. Current Enforcement Status Registry */}
      <section className="bg-[#090e1a] border border-slate-800/90 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Current Enforcement Status ({enforcements.length})
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Active security status, session state, and policy actions applied to evaluated cloud identities.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-500">
            Backed by PostgreSQL <code className="text-cyan-400">cloud_user_enforcements</code>
          </div>
        </div>

        {loading ? (
          <div className="py-16 text-center text-cyan-400 font-mono text-sm">
            Loading active enforcements...
          </div>
        ) : enforcements.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No identity enforcements recorded. Run threat detection inference to evaluate user risks.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="text-[11px] font-mono uppercase bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Cloud Identity</th>
                  <th className="p-3.5">Evaluated Risk</th>
                  <th className="p-3.5">Session State</th>
                  <th className="p-3.5">Enforcement Reason</th>
                  <th className="p-3.5">Last Evaluated</th>
                  <th className="p-3.5 text-center">History</th>
                  <th className="p-3.5 text-right">Analyst Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {enforcements.map((enf) => {
                  const isBlocked = enf.status === 'BLOCKED';
                  const isRestricted = enf.status === 'RESTRICTED';
                  const historyCount = Array.isArray(enf.history) ? enf.history.length : 0;

                  return (
                    <tr key={enf.id || enf.cloud_user_id} className="hover:bg-slate-800/40">
                      <td className="p-3.5">
                        <span className={`px-2.5 py-1 rounded-md font-bold text-[10px] ${
                          isBlocked ? 'bg-red-950 text-red-300 border border-red-800' :
                          isRestricted ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                        }`}>
                          {enf.status}
                        </span>
                      </td>

                      <td className="p-3.5">
                        <button
                          onClick={() => onNavigate && onNavigate('investigation', { userId: enf.cloud_user_id })}
                          className="font-bold text-white text-xs hover:text-cyan-400 flex items-center gap-1.5 group transition-colors"
                          title="Click to investigate this identity in Investigation Workspace"
                        >
                          <span>{enf.cloud_user_id}</span>
                          <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-cyan-400" />
                        </button>
                      </td>

                      <td className="p-3.5">
                        <div className="flex items-center gap-2">
                          <span className={`font-bold ${
                            enf.risk_score >= 75 ? 'text-red-400' :
                            enf.risk_score >= 50 ? 'text-amber-400' : 'text-slate-300'
                          }`}>
                            {Number(enf.risk_score || 0).toFixed(1)}
                          </span>
                          <RiskBadge level={enf.risk_level} />
                        </div>
                      </td>

                      <td className="p-3.5">
                        {enf.session_revoked ? (
                          <span className="text-red-400 font-bold flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                            REVOKED
                          </span>
                        ) : (
                          <span className="text-emerald-400 flex items-center gap-1">
                            <CheckCircle className="w-3 h-3 text-emerald-500" />
                            Active
                          </span>
                        )}
                      </td>

                      <td className="p-3.5 font-sans text-slate-300 max-w-xs truncate" title={enf.blocking_reason || enf.restriction_reason || 'Standard observation baseline'}>
                        {enf.blocking_reason || enf.restriction_reason || 'Standard observation baseline'}
                      </td>

                      <td className="p-3.5 text-slate-400">
                        {enf.last_evaluated_at 
                          ? new Date(enf.last_evaluated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                          : 'N/A'}
                      </td>

                      <td className="p-3.5 text-center">
                        <button
                          onClick={() => setSelectedUserHistory(enf)}
                          className={`px-2 py-1 rounded text-[10px] font-mono border transition-all ${
                            historyCount > 0 
                              ? 'bg-slate-800 hover:bg-slate-700 text-cyan-300 border-slate-700' 
                              : 'bg-slate-900/50 text-slate-500 border-slate-800'
                          }`}
                        >
                          <History className="w-3 h-3 inline mr-1" />
                          {historyCount} action{historyCount !== 1 ? 's' : ''}
                        </button>
                      </td>

                      <td className="p-3.5 text-right">
                        <button
                          onClick={() => {
                            setSelectedUserForOverride(enf);
                            setOverrideAction(isBlocked || isRestricted ? 'RESTORE' : 'RESTRICT');
                            setOverrideReason(`Manual analyst mitigation for ${enf.cloud_user_id}`);
                          }}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-300 font-sans text-[11px] font-medium transition-colors"
                        >
                          Manual Action
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* 3. Audit Trail */}
      <section className="bg-[#090e1a] border border-slate-800/90 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Security Response & Compliance Audit Trail ({auditLogs.length})
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Chronological, immutable audit records detailing user, risk score, applied mitigation, reason, and status.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-slate-500" />
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">All Audit Actions</option>
                <option value="AUTOMATED_RESTRICTION">Automated Restriction</option>
                <option value="AUTOMATED_BLOCK">Automated Block</option>
                <option value="MANUAL">Manual Overrides</option>
                <option value="login">Authentication Events</option>
              </select>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="py-16 text-center text-cyan-400 font-mono text-sm">
            Retrieving immutable audit records...
          </div>
        ) : auditLogs.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No audit records found matching query filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="text-[11px] font-mono uppercase bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3.5">Timestamp (UTC)</th>
                  <th className="p-3.5">User / Target</th>
                  <th className="p-3.5">Risk Assessment</th>
                  <th className="p-3.5">Action Taken</th>
                  <th className="p-3.5">Reason / Justification</th>
                  <th className="p-3.5">Enforcement Status</th>
                  <th className="p-3.5 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {auditLogs.map((log) => {
                  const targetUser = getAuditUser(log);
                  const riskScore = log.detail?.risk_score;
                  const riskLevel = log.detail?.risk_level;
                  const isBlock = log.action.includes('BLOCK');
                  const isRestrict = log.action.includes('RESTRICT');
                  const isManual = log.action.includes('MANUAL');

                  // Status derived from action/detail
                  const statusLabel = log.detail?.new_status 
                    ? log.detail.new_status 
                    : isBlock ? 'BLOCKED' 
                    : isRestrict ? 'RESTRICTED' 
                    : 'COMMITTED';

                  return (
                    <tr key={log.id} className="hover:bg-slate-800/40">
                      <td className="p-3.5 text-slate-400 whitespace-nowrap">
                        {formatUtcTimestamp(log.timestamp)}
                      </td>

                      <td className="p-3.5">
                        {targetUser && targetUser !== 'System' ? (
                          <button
                            onClick={() => onNavigate && onNavigate('investigation', { userId: targetUser })}
                            className="font-bold text-white hover:text-cyan-400 transition-colors flex items-center gap-1"
                          >
                            <span>{targetUser}</span>
                            <ExternalLink className="w-2.5 h-2.5 text-slate-500" />
                          </button>
                        ) : (
                          <span className="text-slate-400 font-bold">{targetUser}</span>
                        )}
                      </td>

                      <td className="p-3.5">
                        {riskScore !== undefined && riskScore !== null ? (
                          <div className="flex items-center gap-1.5">
                            <span className={`font-bold ${
                              Number(riskScore) >= 75 ? 'text-red-400' :
                              Number(riskScore) >= 50 ? 'text-amber-400' : 'text-slate-300'
                            }`}>
                              {Number(riskScore).toFixed(1)}
                            </span>
                            {riskLevel && <RiskBadge level={riskLevel} />}
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          isBlock ? 'bg-red-950 text-red-300 border border-red-800' :
                          isRestrict ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          isManual ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                          'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}>
                          {log.action}
                        </span>
                      </td>

                      <td className="p-3.5 font-sans text-slate-300 max-w-sm truncate" title={log.detail?.reason || log.detail?.note || log.action}>
                        {log.detail?.reason || log.detail?.note || log.action}
                      </td>

                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          statusLabel === 'BLOCKED' ? 'bg-red-950/60 text-red-400 border-red-900/60' :
                          statusLabel === 'RESTRICTED' ? 'bg-amber-950/60 text-amber-400 border-amber-900/60' :
                          statusLabel === 'ACTIVE' ? 'bg-emerald-950/60 text-emerald-400 border-emerald-900/60' :
                          'bg-slate-800/80 text-cyan-400 border-slate-700'
                        }`}>
                          {statusLabel}
                        </span>
                      </td>

                      <td className="p-3.5 text-right">
                        <button
                          onClick={() => setSelectedAuditPayload(log)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] inline-flex items-center gap-1 transition-colors"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Modal: Response History */}
      {selectedUserHistory && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#090e1a] border border-slate-700 p-6 rounded-2xl max-w-lg w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-400" />
                Response History — <span className="font-mono text-cyan-300">{selectedUserHistory.cloud_user_id}</span>
              </h3>
              <RiskBadge level={selectedUserHistory.risk_level} />
            </div>

            <p className="text-xs text-slate-400">
              Chronological mitigation and policy enforcement history recorded in the database.
            </p>

            {(!selectedUserHistory.history || selectedUserHistory.history.length === 0) ? (
              <div className="py-8 text-center text-slate-500 text-xs font-mono">
                No past mitigation events recorded for this user. Identity remains under baseline tracking.
              </div>
            ) : (
              <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                {selectedUserHistory.history.map((hist, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        hist.action?.includes('BLOCK') ? 'bg-red-950 text-red-300 border border-red-800' :
                        hist.action?.includes('RESTRICT') ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {hist.action}
                      </span>
                      <span className="text-slate-500 text-[10px]">
                        {formatUtcTimestamp(hist.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 font-sans mt-1">
                      {hist.reason || 'Automated policy enforcement transition'}
                    </p>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedUserHistory(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Manual Override */}
      {selectedUserForOverride && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#090e1a] border border-slate-700 p-6 rounded-2xl max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Manual Enforcement Override</h3>
            <p className="text-xs text-slate-400">
              Apply administrative enforcement override for identity: <span className="text-cyan-400 font-mono font-bold">{selectedUserForOverride.cloud_user_id}</span>
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1 font-mono">Target Action:</label>
                <select
                  value={overrideAction}
                  onChange={(e) => setOverrideAction(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-mono"
                >
                  <option value="RESTORE">RESTORE (Active / Remove Restrictions)</option>
                  <option value="RESTRICT">RESTRICT (Quarantine Sensitive IAM/KMS)</option>
                  <option value="BLOCK">BLOCK (Revoke Sessions & Lockout)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1 font-mono">Analyst Justification / Reason:</label>
                <textarea
                  rows={2}
                  value={overrideReason}
                  onChange={(e) => setOverrideReason(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-sans"
                  placeholder="Enter justification for this manual security action..."
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedUserForOverride(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteOverride}
                disabled={overrideLoading}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold"
              >
                {overrideLoading ? 'Applying...' : 'Confirm Override'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Audit Payload Inspection */}
      {selectedAuditPayload && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#090e1a] border border-slate-700 p-6 rounded-2xl max-w-lg w-full space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Audit Log Record #{selectedAuditPayload.id}
            </h3>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Action:</span>
                <span className="text-white font-bold">{selectedAuditPayload.action}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Resource:</span>
                <span className="text-cyan-400">{selectedAuditPayload.resource || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Timestamp:</span>
                <span className="text-slate-300">{formatUtcTimestamp(selectedAuditPayload.timestamp)}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-mono text-slate-400 block mb-1">Payload Detail JSON:</span>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-48">
                {JSON.stringify(selectedAuditPayload.detail, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedAuditPayload(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
