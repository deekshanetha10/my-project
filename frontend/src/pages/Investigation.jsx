import React, { useEffect, useMemo, useState, useRef } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  Activity,
  User,
  Network,
  Clock,
  AlertTriangle,
  Ban,
  Lock,
  MessageSquare,
  RefreshCw,
  ChevronRight,
  Sliders,
  ArrowRight
} from 'lucide-react';
import { api } from '../api/client';

const levelClasses = {
  LOW: 'bg-emerald-950/60 border-emerald-800 text-emerald-300',
  MEDIUM: 'bg-amber-950/60 border-amber-800 text-amber-300',
  HIGH: 'bg-orange-950/60 border-orange-800 text-orange-300',
  CRITICAL: 'bg-red-950/70 border-red-700 text-red-300'
};

function RiskBadge({ level }) {
  const value = String(level || 'LOW').toUpperCase();

  return (
    <span
      className={`inline-flex items-center px-2.5 py-1 rounded-lg border text-[11px] font-bold font-mono ${
        levelClasses[value] || levelClasses.LOW
      }`}
    >
      {value}
    </span>
  );
}

function Section({ title, icon: Icon, children, className = '', id, sectionRef }) {
  return (
    <section
      ref={sectionRef}
      id={id}
      className={`rounded-2xl border border-slate-800 bg-[#090e1a] overflow-hidden ${className}`}
    >
      <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4 text-cyan-400" />}
        <h2 className="text-sm font-semibold text-slate-100">
          {title}
        </h2>
      </div>

      <div className="p-5">
        {children}
      </div>
    </section>
  );
}

function Value({ value, fallback = 'N/A' }) {
  if (value === null || value === undefined || value === '') {
    return <span className="text-slate-500">{fallback}</span>;
  }

  if (typeof value === 'object') {
    return (
      <span className="text-slate-300 break-all">
        {JSON.stringify(value)}
      </span>
    );
  }

  return <span className="text-slate-200">{String(value)}</span>;
}

export default function Investigation({ onNavigate, initialUserId, scrollTo }) {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(initialUserId || '');
  const [details, setDetails] = useState(null);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [error, setError] = useState('');
  const [copilotQuery, setCopilotQuery] = useState('');
  const [copilotAnswer, setCopilotAnswer] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);

  const simulatorRef = useRef(null);

  const [simToggles, setSimToggles] = useState({
    unusual_login: false,
    new_ip_location: false,
    privilege_escalation: false,
    abnormal_api_activity: false,
    sensitive_resource_access: false,
    multiple_failed_logins: false,
    coordinated_behavior: false,
    temporal_anomaly: false,
  });
  const [simResult, setSimResult] = useState(null);
  const [simLoading, setSimLoading] = useState(false);

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    if (initialUserId) {
      setSelectedUser(initialUserId);
    }
  }, [initialUserId]);

  useEffect(() => {
    if (selectedUser) {
      loadDetails(selectedUser);
    }
  }, [selectedUser]);

  useEffect(() => {
    if (scrollTo === 'simulator' && !loadingDetails && details && simulatorRef.current) {
      const timer = setTimeout(() => {
        simulatorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 150);
      return () => clearTimeout(timer);
    }
  }, [scrollTo, loadingDetails, details]);

  const loadUsers = async () => {
    try {
      setLoadingUsers(true);
      setError('');

      const result = await api.listInvestigationUsers();

      const list = Array.isArray(result) ? result : [];
      setUsers(list);

      if (!selectedUser && list.length > 0) {
        setSelectedUser(list[0].cloud_user_id);
      }
    } catch (err) {
      console.error(err);
      setError(err.message || 'Unable to load investigation users.');
    } finally {
      setLoadingUsers(false);
    }
  };

  const loadDetails = async (userId) => {
    try {
      setLoadingDetails(true);
      setError('');

      const result = await api.getInvestigationDetails(userId);
      setDetails(result);
    } catch (err) {
      console.error(err);
      setDetails(null);
      setError(err.message || 'Unable to load investigation details.');
    } finally {
      setLoadingDetails(false);
    }
  };

  const summary = details?.summary || {};
  const currentRisk = details?.current_risk || {};
  const uba = details?.uba_profile || {};

  const evolution = Array.isArray(details?.risk_evolution)
    ? details.risk_evolution
    : [];

  const evidence = Array.isArray(details?.evidence_timeline)
    ? details.evidence_timeline
    : [];

  const suspiciousEvents = Array.isArray(details?.suspicious_events)
    ? details.suspicious_events
    : [];

  const riskContributors = Array.isArray(details?.risk_contributors)
    ? details.risk_contributors
    : [];

  const selectedUserSummary = useMemo(
    () =>
      users.find(
        (u) => u.cloud_user_id === selectedUser
      ),
    [users, selectedUser]
  );

  const runCopilot = async () => {
    if (!copilotQuery.trim() || !selectedUser) return;

    try {
      setCopilotLoading(true);
      setCopilotAnswer('');

      const result = await api.queryCopilot(
        copilotQuery,
        selectedUser
      );

      setCopilotAnswer(
        result?.answer ||
        result?.response ||
        result?.message ||
        JSON.stringify(result, null, 2)
      );
    } catch (err) {
      setCopilotAnswer(
        `Unable to query Security Copilot: ${err.message}`
      );
    } finally {
      setCopilotLoading(false);
    }
  };

  const runSimulation = async (toggleStates) => {
    if (!selectedUser) return;
    try {
      setSimLoading(true);
      const res = await api.simulateRisk({
        cloud_user_id: selectedUser,
        ...toggleStates,
      });
      setSimResult(res);
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setSimLoading(false);
    }
  };

  const handleSimToggle = (key) => {
    const updated = { ...simToggles, [key]: !simToggles[key] };
    setSimToggles(updated);
    runSimulation(updated);
  };

  const resetSimulation = () => {
    const cleared = {
      unusual_login: false,
      new_ip_location: false,
      privilege_escalation: false,
      abnormal_api_activity: false,
      sensitive_resource_access: false,
      multiple_failed_logins: false,
      coordinated_behavior: false,
      temporal_anomaly: false,
    };
    setSimToggles(cleared);
    setSimResult(null);
  };

  const formatTime = (item) => {
    return (
      item?.time ||
      item?.timestamp ||
      item?.created_at ||
      item?.event_time ||
      'N/A'
    );
  };

  const getEvolutionScore = (item) => {
    const value =
      item?.risk_score ??
      item?.score ??
      item?.risk ??
      item?.value;

    if (value === undefined || value === null) return null;

    return Number(value);
  };

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="border-b border-slate-800/80 pb-5">

        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-4">

          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 uppercase tracking-widest font-mono mb-1">
              <Search className="w-3.5 h-3.5" />
              Security Investigation Center
            </div>

            <h1 className="text-2xl font-bold text-white">
              Investigation Workspace
            </h1>

            <p className="text-sm text-slate-400 mt-1">
              Continuous user-risk analysis, behavioral evidence,
              attack-path investigation, and adaptive security decisions.
            </p>
          </div>

          <button
            onClick={() => selectedUser && loadDetails(selectedUser)}
            disabled={loadingDetails || !selectedUser}
            className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-slate-300 hover:border-cyan-700 hover:text-cyan-300 disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${
                loadingDetails ? 'animate-spin' : ''
              }`}
            />
            Refresh Investigation
          </button>

        </div>
      </div>

      {/* User selector */}
      <Section title="Select Identity" icon={User}>

        <div className="flex flex-col md:flex-row gap-4 md:items-center">

          <div className="flex-1">

            <label className="block text-[11px] uppercase tracking-wider text-slate-500 font-mono mb-2">
              Monitored Cloud User
            </label>

            <select
              value={selectedUser}
              onChange={(e) => setSelectedUser(e.target.value)}
              disabled={loadingUsers}
              className="w-full px-3 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {loadingUsers ? (
                <option>Loading users...</option>
              ) : users.length === 0 ? (
                <option value="">
                  No monitored users available
                </option>
              ) : (
                users.map((user) => (
                  <option
                    key={user.cloud_user_id}
                    value={user.cloud_user_id}
                  >
                    {user.cloud_user_id}
                    {user.risk_level
                      ? ` — ${user.risk_level}`
                      : ''}
                  </option>
                ))
              )}
            </select>

          </div>

          {selectedUserSummary && (
            <div className="md:w-72 p-3 rounded-xl bg-slate-950 border border-slate-800">

              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">
                Selected Identity
              </div>

              <div className="text-sm font-bold text-white mt-1">
                {selectedUserSummary.cloud_user_id}
              </div>

              <div className="flex items-center gap-2 mt-2">
                <RiskBadge
                  level={
                    selectedUserSummary.risk_level ||
                    selectedUserSummary.current_risk_level
                  }
                />

                {selectedUserSummary.threat_category && (
                  <span className="text-[10px] text-slate-400">
                    {selectedUserSummary.threat_category}
                  </span>
                )}
              </div>

            </div>
          )}

        </div>
      </Section>

      {error && (
        <div className="rounded-xl border border-red-800/70 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {loadingDetails && (
        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-12 text-center text-cyan-400 font-mono text-sm">
          Loading investigation evidence...
        </div>
      )}

      {!loadingDetails && details && (
        <>
          {/* Current risk summary */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">

            <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                CURRENT RISK
              </div>

              <div className="text-3xl font-bold text-white mt-3">
                {Number(
                  currentRisk.score ??
                  summary.risk_score ??
                  0
                ).toFixed(1)}
              </div>

              <div className="mt-2">
                <RiskBadge
                  level={
                    currentRisk.level ||
                    summary.risk_level
                  }
                />
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Activity className="w-4 h-4 text-cyan-400" />
                BEHAVIOR DEVIATION
              </div>

              <div className="text-3xl font-bold text-white mt-3">
                {Number(
                  uba.deviation_score || 0
                ).toFixed(1)}
              </div>

              <div className="text-xs text-slate-500 mt-2">
                Compared with established user baseline
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Network className="w-4 h-4 text-purple-400" />
                EVENTS MONITORED
              </div>

              <div className="text-3xl font-bold text-white mt-3">
                {summary.total_events ?? 0}
              </div>

              <div className="text-xs text-slate-500 mt-2">
                First seen: {summary.first_seen || 'N/A'}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-5">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                {String(
                  currentRisk.level ||
                  summary.risk_level ||
                  ''
                ).toUpperCase() === 'CRITICAL' ? (
                  <Ban className="w-4 h-4 text-red-400" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                )}
                ADAPTIVE RESPONSE
              </div>

              <div className="text-lg font-bold text-white mt-3">
                {currentRisk.policy_action ||
                  summary.policy_action ||
                  'Monitor'}
              </div>

              <div className="text-xs text-slate-500 mt-2">
                Status: {summary.status || 'ACTIVE'}
              </div>
            </div>

          </div>

          {/* Risk evolution */}
          <Section title="Continuous Risk Evolution" icon={Activity}>

            {evolution.length === 0 ? (

              <div className="py-8 text-center text-slate-500 text-sm">
                No risk evolution history is available for this user.
              </div>

            ) : (

              <div className="space-y-3">

                {evolution.map((item, index) => {

                  const score = getEvolutionScore(item);

                  return (
                    <div
                      key={index}
                      className="flex items-center gap-4"
                    >

                      <div className="w-28 shrink-0 text-[11px] text-slate-500 font-mono">
                        {formatTime(item)}
                      </div>

                      <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">

                        <div
                          className="h-full bg-cyan-500 rounded-full"
                          style={{
                            width: `${Math.min(
                              100,
                              Math.max(0, Number(score || 0))
                            )}%`
                          }}
                        />

                      </div>

                      <div className="w-16 text-right font-bold text-slate-200">
                        {score === null
                          ? 'N/A'
                          : Number(score).toFixed(1)}
                      </div>

                      <RiskBadge
                        level={
                          item?.risk_level ||
                          item?.level ||
                          'LOW'
                        }
                      />

                    </div>
                  );

                })}

              </div>

            )}

          </Section>

          {/* Normal vs current */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

            <Section title="Normal Behavior Baseline" icon={ShieldCheck}>

              {Object.keys(uba.baseline || {}).length === 0 ? (

                <p className="text-sm text-slate-500">
                  No baseline behavior information available.
                </p>

              ) : (

                <div className="space-y-3">

                  {Object.entries(uba.baseline).map(
                    ([key, value]) => (
                      <div
                        key={key}
                        className="flex justify-between gap-4 py-2 border-b border-slate-800/70"
                      >
                        <span className="text-xs text-slate-500 capitalize">
                          {key.replaceAll('_', ' ')}
                        </span>

                        <Value value={value} />
                      </div>
                    )
                  )}

                </div>

              )}

            </Section>

            <Section title="Current Behavior" icon={Activity}>

              {Object.keys(uba.current_behavior || {}).length === 0 ? (

                <p className="text-sm text-slate-500">
                  No current behavior information available.
                </p>

              ) : (

                <div className="space-y-3">

                  {Object.entries(
                    uba.current_behavior
                  ).map(([key, value]) => (
                    <div
                      key={key}
                      className="flex justify-between gap-4 py-2 border-b border-slate-800/70"
                    >
                      <span className="text-xs text-slate-500 capitalize">
                        {key.replaceAll('_', ' ')}
                      </span>

                      <Value value={value} />
                    </div>
                  ))}

                </div>

              )}

            </Section>

          </div>

          {/* Why suspicious */}
          <Section
            title="Why Suspicious?"
            icon={AlertTriangle}
          >

            <div className="rounded-xl bg-red-950/20 border border-red-900/50 p-4">

              <p className="text-sm leading-6 text-slate-300">
                {details.why_suspicious ||
                  'No suspicious explanation available.'}
              </p>

            </div>

            {uba.suspicious_indicators?.length > 0 && (

              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">

                {uba.suspicious_indicators.map(
                  (indicator, index) => (
                    <div
                      key={index}
                      className="rounded-xl border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300"
                    >
                      {typeof indicator === 'object'
                        ? JSON.stringify(indicator)
                        : indicator}
                    </div>
                  )
                )}

              </div>

            )}

          </Section>

          {/* Evidence timeline */}
          <Section
            title="Evidence Timeline"
            icon={Clock}
          >

            {evidence.length === 0 ? (

              <div className="py-8 text-center text-slate-500 text-sm">
                No evidence events available.
              </div>

            ) : (

              <div className="relative space-y-3">

                {evidence.map((event, index) => (

                  <div
                    key={index}
                    className="flex gap-4 p-3 rounded-xl bg-slate-950 border border-slate-800"
                  >

                    <div className="w-24 shrink-0 text-[10px] text-cyan-400 font-mono">
                      {formatTime(event)}
                    </div>

                    <div className="flex-1">

                      <div className="text-xs font-semibold text-slate-200">
                        {event.action ||
                          event.event ||
                          event.api ||
                          event.event_name ||
                          'Security Event'}
                      </div>

                      <div className="text-[11px] text-slate-500 mt-1 break-all">
                        {event.service ||
                          event.resource ||
                          event.ip ||
                          event.source_ip ||
                          event.description ||
                          ''}
                      </div>

                    </div>

                  </div>

                ))}

              </div>

            )}

          </Section>

          {/* Suspicious events */}
          {suspiciousEvents.length > 0 && (

            <Section
              title="Suspicious Activities"
              icon={ShieldAlert}
            >

              <div className="space-y-2">

                {suspiciousEvents.map((event, index) => (

                  <div
                    key={index}
                    className="flex items-start gap-3 p-3 rounded-xl bg-red-950/20 border border-red-900/40"
                  >

                    <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />

                    <div className="text-xs text-slate-300 break-all">
                      {typeof event === 'object'
                        ? JSON.stringify(event)
                        : event}
                    </div>

                  </div>

                ))}

              </div>

            </Section>

          )}

          {/* Attack path */}
          <Section
            title="Multi-Hop Attack Path"
            icon={Network}
          >
            {!details.attack_path ? (
              <div className="py-8 text-center text-slate-500 text-sm">
                No attack path has been associated with this identity.
              </div>
            ) : (
              <div className="space-y-4">
                {/* Header info */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-950 border border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <RiskBadge level={details.attack_path.severity || 'HIGH'} />
                      <span className="text-xs font-mono text-slate-400">
                        {details.attack_path.path_id}
                      </span>
                    </div>
                    <div className="text-xs text-slate-300">
                      Target: <span className="font-mono text-cyan-300 break-all">{details.attack_path.target_resource}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Path Risk Score</span>
                    <span className="text-xl font-bold text-red-400 font-mono">
                      {Number(details.attack_path.path_risk_score || 0).toFixed(1)}/100
                    </span>
                  </div>
                </div>

                {/* 5-Hop Visual Breadcrumb Chain: User -> IP -> Action -> Service -> Resource */}
                {Array.isArray(details.attack_path.chain) && details.attack_path.chain.length > 0 && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                    <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">
                      Multi-Hop Attack Traversal Chain
                    </div>
                    <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                      {details.attack_path.chain.map((hop, idx) => {
                        const colors = {
                          USER: 'bg-cyan-950/70 border-cyan-700 text-cyan-300',
                          IP_ADDRESS: 'bg-amber-950/70 border-amber-700 text-amber-300',
                          ACTION: 'bg-emerald-950/70 border-emerald-700 text-emerald-300',
                          SERVICE: 'bg-blue-950/70 border-blue-700 text-blue-300',
                          RESOURCE: 'bg-purple-950/70 border-purple-700 text-purple-300',
                        };
                        return (
                          <React.Fragment key={idx}>
                            <div className={`px-2.5 py-1.5 rounded-lg border flex flex-col ${colors[hop.type] || 'bg-slate-900 border-slate-700 text-slate-200'}`}>
                              <span className="text-[9px] uppercase tracking-wider text-slate-400 font-sans">{hop.type}</span>
                              <span className="font-bold font-mono break-all">{hop.label}</span>
                            </div>
                            {idx < details.attack_path.chain.length - 1 && (
                              <ArrowRight className="w-4 h-4 text-slate-500 shrink-0" />
                            )}
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Summary */}
                {details.attack_path.summary && (
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed">
                    {details.attack_path.summary}
                  </div>
                )}

                {/* Sequential Progression Steps */}
                {Array.isArray(details.attack_path.steps) && details.attack_path.steps.length > 0 && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                    <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">
                      Sequential Entity Transitions ({details.attack_path.steps.length} Steps)
                    </div>
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                      {details.attack_path.steps.map((st) => (
                        <div
                          key={st.step_number}
                          className={`p-2.5 rounded-lg border text-xs flex flex-col md:flex-row md:items-center justify-between gap-2 ${
                            st.is_suspicious ? 'bg-red-950/20 border-red-900/50 text-red-200' : 'bg-slate-900/40 border-slate-800 text-slate-300'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono font-bold text-cyan-400">
                              STEP {st.step_number}
                            </span>
                            <span className="font-medium text-white">{st.action}</span>
                            <span className="text-[11px] font-mono text-slate-400">
                              ({st.source_type}: {st.source_entity} → {st.target_type}: {st.target_entity})
                            </span>
                          </div>
                          <span className="text-[10px] font-mono text-slate-500 shrink-0">{st.timestamp}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </Section>

          {/* Risk contributors */}
          <Section
            title="Risk Evidence Fusion"
            icon={AlertTriangle}
          >

            {riskContributors.length === 0 ? (

              <div className="text-sm text-slate-500">
                No individual risk contributors are available.
              </div>

            ) : (

              <div className="space-y-2">

                {riskContributors.map((factor, index) => (

                  <div
                    key={index}
                    className="flex items-center justify-between gap-4 p-3 rounded-xl bg-slate-950 border border-slate-800"
                  >

                    <div className="text-xs text-slate-300 break-all">
                      {typeof factor === 'object'
                        ? factor.factor ||
                          factor.name ||
                          factor.reason ||
                          JSON.stringify(factor)
                        : factor}
                    </div>

                    {typeof factor === 'object' &&
                      (factor.contribution !== undefined ||
                        factor.score !== undefined) && (
                        <span className="text-xs font-bold text-cyan-300">
                          {factor.contribution ??
                            factor.score}
                        </span>
                      )}

                  </div>

                ))}

              </div>

            )}

          </Section>

          {/* ── What-If Risk Simulator ── */}
          <Section title="What-If Risk Simulator" icon={Sliders} sectionRef={simulatorRef} id="what-if-risk-simulator">
            <div className="mb-4 px-3 py-2 rounded-lg bg-violet-950/40 border border-violet-700/40 text-[11px] text-violet-300 font-mono">
              SIMULATED / WHAT-IF — changes here do <strong>NOT</strong> affect actual risk scores,
              enforcement status, or audit records.
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              {[
                { key: 'unusual_login',            label: 'Unusual Login' },
                { key: 'new_ip_location',          label: 'New IP Location' },
                { key: 'privilege_escalation',     label: 'Privilege Escalation' },
                { key: 'abnormal_api_activity',    label: 'Abnormal API Activity' },
                { key: 'sensitive_resource_access',label: 'Sensitive Resource Access' },
                { key: 'multiple_failed_logins',   label: 'Multiple Failed Logins' },
                { key: 'coordinated_behavior',     label: 'Coordinated Behavior' },
                { key: 'temporal_anomaly',         label: 'Temporal Anomaly' },
              ].map(({ key, label }) => {
                const active = simToggles[key];
                return (
                  <button
                    key={key}
                    onClick={() => handleSimToggle(key)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-semibold transition-all ${
                      active
                        ? 'bg-violet-900/60 border-violet-500 text-violet-200'
                        : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className={`w-3 h-3 rounded-full flex-shrink-0 ${active ? 'bg-violet-400' : 'bg-slate-600'}`} />
                    {label}
                  </button>
                );
              })}
            </div>

            <button
              onClick={resetSimulation}
              className="mb-5 text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 transition-colors"
            >
              <RefreshCw className="w-3 h-3" /> Reset all toggles
            </button>

            {simLoading && (
              <div className="text-xs text-violet-300 font-mono animate-pulse">
                Running simulation…
              </div>
            )}

            {!simLoading && simResult && (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded-lg bg-violet-800/60 border border-violet-500 text-[11px] font-bold text-violet-200 font-mono">
                    SIMULATED / WHAT-IF
                  </span>
                  {simResult.risk_level_changed && (
                    <span className="px-2 py-1 rounded-lg bg-red-900/60 border border-red-600 text-[11px] font-bold text-red-300 font-mono">
                      RISK LEVEL CHANGED
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 font-mono mb-1">Current Score</div>
                    <div className="text-xl font-bold text-cyan-300">{simResult.current_risk_score?.toFixed(1)}</div>
                    <div className="text-[10px] text-slate-400 mt-1">{simResult.current_risk_level}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-violet-950/40 border border-violet-700">
                    <div className="text-[10px] uppercase text-slate-500 font-mono mb-1">Simulated Score</div>
                    <div className="text-xl font-bold text-violet-300">{simResult.simulated_risk_score?.toFixed(1)}</div>
                    <div className="text-[10px] text-slate-400 mt-1">{simResult.simulated_risk_level}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 font-mono mb-1">Delta</div>
                    <div className={`text-xl font-bold ${simResult.delta > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {simResult.delta > 0 ? '+' : ''}{simResult.delta?.toFixed(1)}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 font-mono mb-1">Predicted Action</div>
                    <div className="text-sm font-bold text-orange-300 leading-tight">{simResult.predicted_action}</div>
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="text-[10px] uppercase text-slate-500 font-mono">Top Contributor</div>
                  <div className="text-sm font-semibold text-white">{simResult.top_contributor}</div>
                  {simResult.explanation && (
                    <div className="text-xs text-slate-400 leading-relaxed">{simResult.explanation}</div>
                  )}
                </div>

                {Array.isArray(simResult.factor_contributions) && simResult.factor_contributions.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase text-slate-500 font-mono mb-2">Factor Contributions</div>
                    <div className="space-y-1.5">
                      {simResult.factor_contributions.map((fc, i) => {
                        const name = fc.factor || fc.name || String(i);
                        const val = fc.contribution ?? fc.score ?? fc.value ?? 0;
                        const pct = Math.min(100, Math.abs(Number(val)));
                        return (
                          <div key={i} className="flex items-center gap-3">
                            <div className="text-xs text-slate-400 w-44 shrink-0 truncate">{name}</div>
                            <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                              <div
                                className="h-full rounded-full bg-violet-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <div className="text-xs font-mono text-violet-300 w-10 text-right">{Number(val).toFixed(1)}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {!simLoading && !simResult && (
              <div className="text-xs text-slate-500 font-mono">
                Enable one or more hypothetical behaviors above to run a simulation.
              </div>
            )}
          </Section>

          {/* Automated response */}
          <Section
            title="Automated Response Decision"
            icon={Lock}
          >

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">

                <div className="text-[10px] uppercase text-slate-500 font-mono">
                  Policy Decision
                </div>

                <div className="text-lg font-bold text-cyan-300 mt-2">
                  {details.automated_response?.policy_action ||
                    summary.policy_action ||
                    'Monitor'}
                </div>

              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">

                <div className="text-[10px] uppercase text-slate-500 font-mono">
                  Enforcement Status
                </div>

                <div className="text-lg font-bold text-white mt-2">
                  {details.automated_response?.status ||
                    summary.status ||
                    'ACTIVE'}
                </div>

              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">

                <div className="text-[10px] uppercase text-slate-500 font-mono">
                  Session Revoked
                </div>

                <div className="text-lg font-bold text-white mt-2">
                  {details.automated_response?.session_revoked
                    ? 'YES'
                    : 'NO'}
                </div>

              </div>

            </div>

          </Section>

          {/* AI Copilot */}
          <Section
            title="AI Security Investigation Copilot"
            icon={MessageSquare}
          >

            <div className="text-xs text-slate-500 mb-4">
              Ask questions about the selected identity using the
              investigation data available to the backend.
            </div>

            <div className="flex gap-2">

              <input
                value={copilotQuery}
                onChange={(e) =>
                  setCopilotQuery(e.target.value)
                }
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    runCopilot();
                  }
                }}
                placeholder="Why was this user flagged?"
                className="flex-1 px-3 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />

              <button
                onClick={runCopilot}
                disabled={
                  copilotLoading ||
                  !copilotQuery.trim()
                }
                className="px-4 py-2 rounded-xl bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold disabled:opacity-50"
              >
                {copilotLoading
                  ? 'Analyzing...'
                  : 'Ask Copilot'}
              </button>

            </div>

            {copilotAnswer && (

              <div className="mt-4 rounded-xl bg-slate-950 border border-cyan-900/60 p-4">

                <div className="text-[10px] uppercase tracking-wider text-cyan-500 font-mono mb-2">
                  Investigation Result
                </div>

                <pre className="whitespace-pre-wrap text-sm text-slate-300 font-sans leading-6">
                  {copilotAnswer}
                </pre>

              </div>

            )}

            <div className="flex flex-wrap gap-2 mt-4">

              {[
                'Why was this user flagged?',
                'Show suspicious activities',
                'Why did risk become critical?',
                'What happened before the response?',
                'Which IP caused the risk increase?'
              ].map((question) => (

                <button
                  key={question}
                  onClick={() => {
                    setCopilotQuery(question);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800 text-[11px] text-slate-400 hover:text-cyan-300"
                >
                  {question}
                </button>

              ))}

            </div>

          </Section>
        </>
      )}

      {!loadingDetails && !details && !error && (
        <div className="rounded-2xl border border-slate-800 bg-[#090e1a] p-12 text-center">
          <Search className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-400">
            Select a monitored identity to begin investigation.
          </p>
        </div>
      )}

    </div>
  );
}