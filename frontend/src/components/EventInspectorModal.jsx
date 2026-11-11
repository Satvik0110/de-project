import React, { useState } from 'react';
import { X, Copy, Check, Database, FileText } from 'lucide-react';

export default function EventInspectorModal({ event, onClose }) {
  const [copied, setCopied] = useState(false);
  if (!event) return null;

  const jsonString = JSON.stringify(event, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const isMalicious = event.raw_payload?.threat_flag === 'malicious';
  const eventDate = event.event_time ? event.event_time.slice(0, 10) : '2026-09-08';
  const eventHour = event.event_time ? event.event_time.slice(11, 13) : '04';

  return (
    <div className="inspector-overlay" onClick={onClose}>
      <div className="inspector-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            <FileText size={18} color="var(--accent-cyan)" />
            <span>Raw Event Inspector</span>
            <span className={`badge-type ${event.source_type}`} style={{ marginLeft: '0.5rem' }}>
              {event.source_type === 'auth' ? 'Authorisation' : event.source_type}
            </span>
            <span className={`badge-status ${event.status === 'ok' || event.status === 'success' ? 'ok' : 'invalid'}`}>
              {event.status === 'ok' || event.status === 'success' ? 'OK' : 'INVALID'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={handleCopy}
              className="filter-btn"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem' }}
            >
              {copied ? <Check size={14} color="var(--status-success)" /> : <Copy size={14} />}
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
            <button onClick={onClose} className="filter-btn" style={{ padding: '0.35rem 0.6rem' }}>
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="modal-body">
          {/* Pipeline Destination Info matching Figure 2 of Project Document */}
          <div className="pipeline-mapping-box">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: '700', color: 'var(--accent-cyan)' }}>
              <Database size={15} />
              Project Data Lake & Warehouse Mapping (Section 4 & Figure 2):
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>
              • <b>Data Lake (Parquet)</b>: Stored 1:1 in partition:{' '}
              <code style={{ color: '#38bdf8' }}>
                raw_events/event_type={event.source_type}/dt={eventDate}/hour={eventHour}/part-*.parquet
              </code>
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>
              • <b>Data Warehouse (PostgreSQL)</b>:{' '}
              {isMalicious ? (
                <span style={{ color: 'var(--status-denied)' }}>
                  Triggers detection rule → Written to <code>alerts(alert_id, event_time, rule_name, severity, src_ip, user, window_start, count)</code>
                </span>
              ) : (
                <span style={{ color: 'var(--status-success)' }}>
                  Aggregated over event-time window → Written to <code>aggregates(window_start, window_end, source_type, event_count, unique_ips)</code>
                </span>
              )}
            </div>
          </div>

          {/* Raw JSON viewer */}
          <div className="json-codeblock">
            {jsonString}
          </div>
        </div>
      </div>
    </div>
  );
}
