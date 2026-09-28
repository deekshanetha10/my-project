import React from 'react';
import { 
  Database,
  LayoutDashboard, 
  Share2, 
  ShieldAlert, 
  UserCheck, 
  Search,
  ShieldCheck
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'datasets', label: '1. Data & Pipeline', icon: Database },
  { id: 'overview', label: '2. Security Overview', icon: LayoutDashboard },
  { id: 'graph', label: '3. Security Graph', icon: Share2 },
  { id: 'threats', label: '4. Threat Detection', icon: ShieldAlert },
  { id: 'uba', label: '5. User Behavior', icon: UserCheck },
  { id: 'investigation', label: '6. Investigation', icon: Search },
  { id: 'response_audit', label: '7. Response & Audit', icon: ShieldCheck },
];

export default function Sidebar({ activeTab, onSelectTab }) {
  return (
    <aside className="w-64 bg-[#090d16] border-r border-slate-800/80 flex flex-col p-4 shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-3">
        SOC Intelligence Center
      </div>
      <nav className="space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-950/80 to-blue-950/50 text-cyan-300 border border-cyan-800/50 shadow-md shadow-cyan-950/40 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="mt-auto pt-4 border-t border-slate-800/80">
        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-400">
          <div className="font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            Adaptive Response Engine
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed font-mono">
            LOW ➔ Monitor<br />
            MEDIUM ➔ Alert + Monitor<br />
            HIGH ➔ Auto-Restrict<br />
            CRITICAL ➔ Auto-Block
          </p>
          <div className="mt-2 text-[10px] text-slate-600 border-t border-slate-800/60 pt-1">
            * App-level & simulated enforcement
          </div>
        </div>
      </div>
    </aside>
  );
}
