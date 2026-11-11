import React from 'react';
import { Layers, CheckCircle2 } from 'lucide-react';

export default function MetricsOverview({ stats }) {
  const typeCounts = stats?.type_counts || { auth: 0, network: 0, api: 0 };
  const statusCounts = stats?.status_counts || {};
  const total = (stats?.total_generated || 0) || 1;

  const authPct = Math.round(((typeCounts.auth || 0) / total) * 100);
  const netPct = Math.round(((typeCounts.network || 0) / total) * 100);
  const apiPct = Math.round(((typeCounts.api || 0) / total) * 100);

  const okCount = (statusCounts.ok || 0) + (statusCounts.success || 0);
  const invalidCount = (statusCounts.invalid || 0) + (statusCounts.fail || 0) + (statusCounts.denied || 0);

  const okPct = total > 0 ? Math.round((okCount / total) * 100) : 0;
  const invalidPct = total > 0 ? Math.round((invalidCount / total) * 100) : 0;


  return (
    <div className="metrics-row">
      {/* Event Source Breakdown */}
      <div className="metric-card">
        <div className="metric-card-top">
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Layers size={14} color="var(--accent-cyan)" />
            Source Types
          </span>
          <span>{total.toLocaleString()} Total</span>
        </div>
        <div className="metric-card-value">
          <span style={{ color: 'var(--type-auth)' }}>{typeCounts.auth || 0}</span>
          <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', margin: '0 0.4rem' }}>/</span>
          <span style={{ color: 'var(--type-network)' }}>{typeCounts.network || 0}</span>
          <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', margin: '0 0.4rem' }}>/</span>
          <span style={{ color: 'var(--type-api)' }}>{typeCounts.api || 0}</span>
        </div>
        <div className="metric-bars">
          <div className="bar-segment" style={{ width: `${authPct}%`, background: 'var(--type-auth)' }} title={`Auth: ${authPct}%`} />
          <div className="bar-segment" style={{ width: `${netPct}%`, background: 'var(--type-network)' }} title={`Network: ${netPct}%`} />
          <div className="bar-segment" style={{ width: `${apiPct}%`, background: 'var(--type-api)' }} title={`API: ${apiPct}%`} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
          <span>AUTHORISATION: {authPct}%</span>
          <span>NET: {netPct}%</span>
          <span>API: {apiPct}%</span>
        </div>
      </div>

      {/* Status Ratios (Only 2 Outcomes: OK & INVALID) */}
      <div className="metric-card">
        <div className="metric-card-top">
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <CheckCircle2 size={14} color="var(--status-success)" />
            Status Distribution
          </span>
          <span>Integrity</span>
        </div>
        <div className="metric-card-value">
          <span style={{ color: 'var(--status-success)' }}>{okCount}</span>
          <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', margin: '0 0.4rem' }}>/</span>
          <span style={{ color: 'var(--status-denied)' }}>{invalidCount}</span>
        </div>
        <div className="metric-bars">
          <div className="bar-segment" style={{ width: `${okPct}%`, background: 'var(--status-success)' }} title={`OK: ${okPct}%`} />
          <div className="bar-segment" style={{ width: `${invalidPct}%`, background: 'var(--status-denied)' }} title={`Invalid: ${invalidPct}%`} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
          <span style={{ color: 'var(--status-success)', fontWeight: '700' }}>OK: {okPct}%</span>
          <span style={{ color: 'var(--status-denied)', fontWeight: '700' }}>INVALID: {invalidPct}%</span>
        </div>
      </div>
    </div>
  );
}
