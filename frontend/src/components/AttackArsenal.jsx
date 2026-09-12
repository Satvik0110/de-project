import React, { useState } from 'react';
import { Zap, Crosshair } from 'lucide-react';

export default function AttackArsenal({ onTriggerAttack, targetBaseUrl = 'http://localhost:8002', targetUser = 'admin' }) {
  const [burstCount, setBurstCount] = useState(25);
  const [triggering, setTriggering] = useState(null);

  const handleLaunch = async (scenario) => {
    setTriggering(scenario);
    try {
      await onTriggerAttack(scenario, burstCount);
    } finally {
      setTimeout(() => setTriggering(null), 600);
    }
  };

  return (
    <div className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Zap size={16} color="var(--status-denied)" />
          Targeted Attack Arsenal
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          <span>Burst:</span>
          {[10, 25, 50, 100].map((num) => (
            <button
              key={num}
              onClick={() => setBurstCount(num)}
              className={`filter-btn ${burstCount === num ? 'active' : ''}`}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
            >
              {num}
            </button>
          ))}
        </div>
      </div>

      <div className="panel-body" style={{ gap: '0.85rem' }}>
        {/* Active Target Banner */}
        <div style={{
          background: 'rgba(244, 63, 94, 0.08)',
          border: '1px solid rgba(244, 63, 94, 0.3)',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <Crosshair size={14} color="var(--status-denied)" />
          <span>
            Active Target: <b style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{targetBaseUrl}</b>
            &nbsp;&bull;&nbsp;Target Identity: <b style={{ color: 'var(--text-primary)' }}>{targetUser}</b>
          </span>
        </div>

        {/* Authorisation Threats */}
        <div className="attack-category-title">
          Authorisation
        </div>
        <div className="attack-grid">
          <button
            className={`btn-attack ${triggering === 'auth_brute_force' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('auth_brute_force')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">Credential Brute Force</span>
            </div>
            <div className="attack-btn-desc">
              High-volume dictionary attack against authentication endpoints. Evaluates credential exhaustion resilience.
            </div>
          </button>

          <button
            className={`btn-attack ${triggering === 'auth_jwt_tampering' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('auth_jwt_tampering')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">JWT Token Tampering</span>
            </div>
            <div className="attack-btn-desc">
              Cryptographic signature stripping, algorithm none forgery, and privilege claim manipulation in Bearer tokens.
            </div>
          </button>
        </div>

        {/* API Threats */}
        <div className="attack-category-title">
          API
        </div>
        <div className="attack-grid">
          <button
            className={`btn-attack ${triggering === 'api_injection_probe' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('api_injection_probe')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">SQL and Command Injection Probe</span>
            </div>
            <div className="attack-btn-desc">
              Automated vulnerability probing for SQL injection, path traversal, NoSQL, and command injection patterns.
            </div>
          </button>

          <button
            className={`btn-attack ${triggering === 'api_rate_limit' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('api_rate_limit')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">Rate Limit Exhaustion</span>
            </div>
            <div className="attack-btn-desc">
              Rapid concurrent request flooding against compute-intensive endpoints to test rate limiting policies.
            </div>
          </button>
        </div>

        {/* Network Threats */}
        <div className="attack-category-title">
          Network
        </div>
        <div className="attack-grid">
          <button
            className={`btn-attack ${triggering === 'network_port_scan' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('network_port_scan')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">Horizontal and Vertical Port Sweep</span>
            </div>
            <div className="attack-btn-desc">
              Multi-port TCP SYN connection sweep probing common administration and service ports.
            </div>
          </button>

          <button
            className={`btn-attack ${triggering === 'network_slowloris' ? 'pulse' : ''}`}
            onClick={() => handleLaunch('network_slowloris')}
          >
            <div className="attack-btn-top">
              <span className="attack-btn-title">Slowloris Connection Starvation</span>
            </div>
            <div className="attack-btn-desc">
              Low-bandwidth attack transmitting fragmented HTTP headers to exhaust server connection slots.
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}


