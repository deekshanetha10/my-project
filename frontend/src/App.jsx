import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';

import Overview from './pages/Overview';
import DynamicGraph from './pages/DynamicGraph';
import ThreatDetection from './pages/ThreatDetection';
import UserBehaviorAnalytics from './pages/UserBehaviorAnalytics';
import Datasets from './pages/Datasets';
import Investigation from './pages/Investigation';
import ResponseAudit from './pages/ResponseAudit';

import { api } from './api/client';

function AppContent() {
  const { isAuthenticated, loading } = useAuth();

  // Final 7-section navigation
  const [activeTab, setActiveTab] = useState('datasets');
  const [navParams, setNavParams] = useState({});
  const [alertsCount, setAlertsCount] = useState(0);

  useEffect(() => {
    if (isAuthenticated) {
      api.listAlerts(true)
        .then((alerts) => setAlertsCount(alerts.length))
        .catch(() => {});
    }
  }, [isAuthenticated, activeTab]);

  const handleNavigate = (tabId, params = {}) => {
    setActiveTab(tabId);
    setNavParams(params);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#07090e] flex items-center justify-center text-cyan-400 font-mono text-xs">
        Initializing CloudIntelliGuard Enterprise SOC Console...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  const renderContent = () => {
    switch (activeTab) {

      // 1. DATA & PIPELINE
      case 'datasets':
        return (
          <Datasets
            onNavigate={handleNavigate}
          />
        );

      // 2. SECURITY OVERVIEW
      case 'overview':
        return (
          <Overview
            onNavigate={handleNavigate}
          />
        );

      // 3. SECURITY GRAPH
      case 'graph':
        return (
          <DynamicGraph
            onNavigate={handleNavigate}
            initialUserId={navParams.userId}
          />
        );

      // 4. THREAT DETECTION
      case 'threats':
        return (
          <ThreatDetection
            onNavigate={handleNavigate}
          />
        );

      // 5. USER BEHAVIOR
      case 'uba':
        return (
          <UserBehaviorAnalytics
            onNavigate={handleNavigate}
            initialUserId={navParams.userId}
          />
        );

      // 6. INVESTIGATION
      case 'investigation':
        return (
          <Investigation
            onNavigate={handleNavigate}
            initialUserId={navParams.userId}
            scrollTo={navParams.scrollTo}
          />
        );

      // 7. RESPONSE & AUDIT
      case 'response_audit':
        return (
          <ResponseAudit
            onNavigate={handleNavigate}
          />
        );

      default:
        return (
          <Datasets
            onNavigate={handleNavigate}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans">

      <Navbar
        activeAlertsCount={alertsCount}
        onNavigate={handleNavigate}
      />

      <div className="flex flex-1">

        <Sidebar
          activeTab={activeTab}
          onSelectTab={(tab) => handleNavigate(tab)}
        />

        <main className="flex-1 p-6 md:p-8 overflow-y-auto max-w-7xl mx-auto w-full">
          {renderContent()}
        </main>

      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}