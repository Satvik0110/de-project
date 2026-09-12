import React from 'react';
import { Shield, Play, Pause, Square, RotateCcw } from 'lucide-react';

export default function Header({
  stats,
  onStart,
  onPause,
  onStop,
  onReset
}) {
  const isRunning = stats?.running;

  return (
    <header className="soc-header">
      <div className="header-left">
        <div className="brand-badge">
          <div className="brand-icon-wrapper">
            <Shield size={22} />
          </div>
          <div>
            <div className="brand-title" style={{ fontSize: '1.05rem', fontWeight: '800', letterSpacing: '0.02em' }}>
              Real-Time Cybersecurity Event Analytics Platform
            </div>
          </div>
        </div>
      </div>



      <div className="header-right">
        {!isRunning ? (
          <button className="btn-master start" onClick={onStart}>
            <Play size={16} fill="currentColor" />
            START SIMULATION
          </button>
        ) : (
          <button className="btn-master pause" onClick={onPause}>
            <Pause size={16} fill="currentColor" />
            PAUSE
          </button>
        )}

        <button className="btn-master stop" onClick={onStop} title="Stop simulator">
          <Square size={16} fill="currentColor" />
          STOP
        </button>

        <button
          className="filter-btn"
          style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.55rem 0.85rem' }}
          onClick={onReset}
          title="Reset and clear all data"
        >
          <RotateCcw size={14} />
          RESET / REFRESH
        </button>
      </div>
    </header>
  );
}
