import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search
} from 'lucide-react';
import { api } from '../api/client';

export default function ThreatDetection({ onNavigate }) {
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');

  useEffect(() => {
    loadThreats();
  }, []);

  const loadThreats = async () => {
    try {
      setLoading(true);
      const res = await api.listAnomalies();
      setAnomalies(Array.isArray(res) ? res : []);
    } catch (err) {
      console.error('Failed to load threats:', err);
      setAnomalies([]);
    } finally {
      setLoading(false);
    }
  };

  const getThreatCategory = (anomaly) => {
    const text = (anomaly.explanation?.summary || '').toLowerCase();
    const findings = anomaly.explanation?.findings || [];

    if (
      text.includes('privilege') ||
      findings.some((f) => f.category?.includes('iam'))
    ) {
      return 'Privilege Escalation';
    }

    if (
      text.includes('exfiltration') ||
      text.includes('s3') ||
      text.includes('download')
    ) {
      return 'Data Exfiltration';
    }

    if (
      text.includes('burst') ||
      text.includes('velocity')
    ) {
      return 'Abnormal API Burst';
    }

    if (
      text.includes('unusual service') ||
      text.includes('reconnaissance')
    ) {
      return 'Cloud Reconnaissance';
    }

    return 'Behavioral Deviation';
  };

  const filteredAnomalies = anomalies.filter((a) => {
    const userId = String(a.cloud_user_id || '');

    const matchesSearch =
      !searchQuery ||
      userId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      getThreatCategory(a)
        .toLowerCase()
        .includes(searchQuery.toLowerCase());

    const isHighOrCritical =
      a.anomaly_score >= 0.5 || a.is_anomaly;

    if (
      selectedSeverity === 'HIGH_CRITICAL' &&
      !isHighOrCritical
    ) {
      return false;
    }

    if (
      selectedSeverity === 'ANOMALIES_ONLY' &&
      !a.is_anomaly
    ) {
      return false;
    }

    return matchesSearch;
  });

  // Open the central Investigation workspace for the selected user.
  const openInvestigation = (cloudUserId) => {
    if (!cloudUserId) return;

    onNavigate('investigation', {
      userId: cloudUserId
    });
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">

        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-red-400 uppercase tracking-widest font-mono mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            Threat Intelligence Engine
          </div>

          <h1 className="text-2xl font-bold text-white tracking-tight">
            Threat Detection
          </h1>

          <p className="text-sm text-slate-400 mt-0.5">
            Individual and coordinated security anomalies identified by GNN multi-hop models.
          </p>
        </div>

        {/* Search & Severity Filter */}
        <div className="flex flex-wrap items-center gap-3">

          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />

            <input
              type="text"
              placeholder="Search user or threat..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700/80 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48 sm:w-60"
            />
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">
              All Scores
            </option>

            <option value="ANOMALIES_ONLY">
              Flagged Anomalies Only
            </option>

            <option value="HIGH_CRITICAL">
              Score ≥ 0.50
            </option>
          </select>

        </div>
      </div>

      {/* Main Threat Table */}
      <div className="bg-[#090e1a] border border-slate-800/90 rounded-2xl overflow-hidden">

        <div className="p-4 border-b border-slate-800 flex items-center justify-between">

          <h3 className="text-sm font-semibold text-white">
            Detected Anomalies ({filteredAnomalies.length})
          </h3>

          <span className="text-[11px] font-mono text-slate-400">
            Select a threat to open the full investigation workspace
          </span>

        </div>

        {loading ? (

          <div className="py-20 text-center text-cyan-400 font-mono text-sm">
            Evaluating GNN anomaly scores...
          </div>

        ) : filteredAnomalies.length === 0 ? (

          <div className="py-16 text-center text-slate-500 text-xs">
            No security anomalies matched your criteria.
            Ingest a dataset to evaluate threats.
          </div>

        ) : (

          <div className="overflow-x-auto">

            <table className="w-full text-xs text-left">

              <thead className="text-[11px] font-mono uppercase bg-slate-900/80 text-slate-400 border-b border-slate-800">

                <tr>
                  <th className="p-3.5">
                    Threat Status
                  </th>

                  <th className="p-3.5">
                    Identity (cloud_user_id)
                  </th>

                  <th className="p-3.5">
                    Threat Category
                  </th>

                  <th className="p-3.5">
                    Anomaly Score
                  </th>

                  <th className="p-3.5">
                    Confidence
                  </th>

                  <th className="p-3.5">
                    Window / Detected
                  </th>

                  <th className="p-3.5 text-right">
                    Investigation
                  </th>
                </tr>

              </thead>

              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">

                {filteredAnomalies.map((anom) => {

                  const category = getThreatCategory(anom);

                  const isFlagged =
                    anom.is_anomaly ||
                    anom.anomaly_score >= 0.5;

                  const score = Number(anom.anomaly_score || 0);

                  return (

                    <tr
                      key={anom.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >

                      {/* Threat Status */}
                      <td className="p-3.5">

                        <span
                          className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                            isFlagged
                              ? 'bg-red-950/80 border border-red-800 text-red-300'
                              : 'bg-emerald-950/40 border border-emerald-800/50 text-emerald-400'
                          }`}
                        >
                          {isFlagged
                            ? '🚨 ANOMALOUS'
                            : '✓ NORMAL'}
                        </span>

                      </td>

                      {/* User */}
                      <td className="p-3.5">

                        <span className="font-bold text-white text-xs block">
                          {anom.cloud_user_id}
                        </span>

                        {anom.explanation?.summary && (

                          <span className="text-[10px] text-slate-400 truncate max-w-xs block font-sans mt-0.5">
                            {anom.explanation.summary}
                          </span>

                        )}

                      </td>

                      {/* Category */}
                      <td className="p-3.5 font-sans">

                        <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 text-[11px] font-medium">
                          {category}
                        </span>

                      </td>

                      {/* Anomaly Score */}
                      <td className="p-3.5">

                        <div className="flex items-center gap-2">

                          <span
                            className={`font-bold text-xs ${
                              isFlagged
                                ? 'text-red-400'
                                : 'text-slate-200'
                            }`}
                          >
                            {(score * 100).toFixed(1)}%
                          </span>

                          <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">

                            <div
                              className={`h-full ${
                                isFlagged
                                  ? 'bg-red-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{
                                width: `${Math.min(
                                  100,
                                  score * 100
                                )}%`
                              }}
                            />

                          </div>

                        </div>

                      </td>

                      {/* Confidence */}
                      <td className="p-3.5 text-slate-300 font-bold">

                        {(
                          (anom.confidence ?? 0.88) * 100
                        ).toFixed(0)}%

                      </td>

                      {/* Window */}
                      <td className="p-3.5 text-slate-400 font-sans text-[11px]">

                        Window #{anom.graph_window_id}

                      </td>

                      {/* Investigation */}
                      <td className="p-3.5 text-right">

                        <button
                          onClick={() =>
                            openInvestigation(
                              anom.cloud_user_id
                            )
                          }
                          className="px-3 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-700/70 text-cyan-300 font-sans text-[11px] font-medium transition-colors"
                        >
                          Investigate
                        </button>

                      </td>

                    </tr>

                  );

                })}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </div>
  );
}