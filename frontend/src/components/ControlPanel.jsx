import React from 'react';
import { Crosshair, User, Link } from 'lucide-react';

export default function ControlPanel({ config, onUpdateConfig }) {
  const handleChange = (key, value) => {
    onUpdateConfig({ ...config, [key]: value });
  };

  return (
    <div className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Crosshair size={16} color="var(--status-denied)" />
          Target Definition &amp; Attack Parameters
        </div>
      </div>

      <div className="panel-body">
        {/* Target Base URL */}
        <div className="control-group">
          <div className="control-label">
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-primary)', fontWeight: '700' }}>
              <Link size={14} color="var(--status-denied)" />
              Target Server URL
            </span>
            <span className="slider-val-badge font-mono" style={{ color: 'var(--status-denied)', borderColor: 'rgba(244,63,94,0.4)' }}>
              VICTIM HOST
            </span>
          </div>
          <input
            type="text"
            className="soc-input font-mono"
            value={config.target_base_url || 'http://localhost:8002'}
            onChange={(e) => handleChange('target_base_url', e.target.value)}
            placeholder="http://localhost:8002"
          />
        </div>

        {/* Target User */}
        <div className="control-group">
          <div className="control-label">
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <User size={13} color="var(--text-muted)" />
              Target User Account
            </span>
          </div>
          <input
            type="text"
            className="soc-input font-mono"
            value={config.target_user || 'admin'}
            onChange={(e) => handleChange('target_user', e.target.value)}
            placeholder="e.g. root, admin, sysadmin"
          />
        </div>

        {/* Generation Rate (EPS) */}
        <div className="control-group">
          <div className="control-label">
            <span>Attack Generation Rate (EPS)</span>
            <span className="slider-val-badge">{config.events_per_second || 10} EPS</span>
          </div>
          <input
            type="range"
            min="1"
            max="150"
            step="1"
            className="soc-slider"
            value={config.events_per_second || 10}
            onChange={(e) => handleChange('events_per_second', parseFloat(e.target.value))}
          />
        </div>

        {/* Traffic Generation Mode */}
        <div className="control-group">
          <div className="control-label">
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              Traffic Generation Mode
            </span>
            <span className="slider-val-badge" style={{ color: config.only_attacks ? 'var(--status-denied)' : 'var(--accent-cyan)' }}>
              {config.only_attacks ? '100% Selected Attacks' : 'Mixed Baseline'}
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', marginTop: '0.2rem' }}>
            <button
              type="button"
              className={`filter-btn ${config.only_attacks ? 'active' : ''}`}
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.72rem', justifyContent: 'center' }}
              onClick={() => onUpdateConfig({ ...config, only_attacks: true, attack_ratio: 1.0 })}
            >
              Only Selected Attacks
            </button>
            <button
              type="button"
              className={`filter-btn ${!config.only_attacks ? 'active' : ''}`}
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.72rem', justifyContent: 'center' }}
              onClick={() => onUpdateConfig({ ...config, only_attacks: false, attack_ratio: 0.5 })}
            >
              Mix with Normal Traffic
            </button>
          </div>
        </div>

        {/* Multiple Choice Attack Selection */}
        <div className="control-group">
          <div className="control-label">
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-primary)', fontWeight: '700' }}>
              Continuous Attacks
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span className="slider-val-badge" style={{ color: 'var(--accent-cyan)' }}>
                {(config.selected_scenarios || [
                  'auth_brute_force', 'auth_password_spray',
                  'api_injection_probe', 'api_rate_limit',
                  'network_port_scan', 'network_connection_flood'
                ]).length} / 6 Active
              </span>
              <button
                type="button"
                onClick={() => handleChange('selected_scenarios', [
                  'auth_brute_force', 'auth_password_spray',
                  'api_injection_probe', 'api_rate_limit',
                  'network_port_scan', 'network_connection_flood'
                ])}
                style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', textDecoration: 'underline' }}
              >
                All
              </button>
              <span style={{ color: 'var(--text-muted)' }}>|</span>
              <button
                type="button"
                onClick={() => handleChange('selected_scenarios', [])}
                style={{ fontSize: '0.68rem', color: 'var(--status-denied)', textDecoration: 'underline' }}
              >
                Clear
              </button>
            </div>
          </div>

          <div className="multi-choice-box">
            {[
              {
                category: 'Authorisation',
                items: [
                  { id: 'auth_brute_force', label: 'Credential Brute Force' },
                  { id: 'auth_password_spray', label: 'Horizontal Password Spray' }
                ]
              },
              {
                category: 'API',
                items: [
                  { id: 'api_injection_probe', label: 'Diverse Injection Probes' },
                  { id: 'api_rate_limit', label: 'Rate Limit Exhaustion' }
                ]
              },
              {
                category: 'Network',
                items: [
                  { id: 'network_port_scan', label: 'Port Sweep Scan' },
                  { id: 'network_connection_flood', label: 'TCP Connection Flood' }
                ]
              }
            ].map((group) => {
              const currentSelected = config.selected_scenarios || [
                'auth_brute_force', 'auth_password_spray',
                'api_injection_probe', 'api_rate_limit',
                'network_port_scan', 'network_connection_flood'
              ];


              return (
                <div key={group.category} className="choice-category">
                  <div className="choice-category-heading">
                    <span>{group.category}</span>
                  </div>
                  <div className="choice-grid">
                    {group.items.map((item) => {
                      const isChecked = currentSelected.includes(item.id);
                      return (
                        <label
                          key={item.id}
                          className={`choice-item ${isChecked ? 'selected' : ''}`}
                          onClick={(e) => {
                            e.preventDefault();
                            let updated;
                            if (isChecked) {
                              updated = currentSelected.filter((s) => s !== item.id);
                            } else {
                              updated = [...currentSelected, item.id];
                            }
                            handleChange('selected_scenarios', updated);
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            readOnly
                          />
                          <span>{item.label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </div>
  );
}
