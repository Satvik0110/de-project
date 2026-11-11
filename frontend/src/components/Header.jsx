import { Crosshair } from 'lucide-react';

function Toggle({ label, hint, checked, danger, onChange }) {
  return (
    <label className="toggle-item">
      <span className="toggle-info">
        <span className="toggle-title">{label}</span>
        <span className="toggle-sub">{hint}</span>
      </span>
      <span className="switch">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span className={`slider-switch${danger ? ' danger' : ''}`} />
      </span>
    </label>
  );
}

export default function Header({ connected, background, chaos, onToggle }) {
  return (
    <header className="soc-header">
      <div className="brand-badge">
        <div className="brand-icon-wrapper">
          <Crosshair size={22} />
        </div>
        <h1 className="brand-title">Red Team — Attack Simulator</h1>
        <span className="telemetry-chip">
          <span className={`status-dot ${connected ? 'active' : 'error'}`} />
          {connected ? 'Live' : 'Reconnecting…'}
        </span>
      </div>
      <div className="header-right">
        <Toggle
          label="Background traffic"
          hint="normal employee activity"
          checked={background}
          onChange={(v) => onToggle('background', v)}
        />
        <Toggle
          label="Unreliable network"
          hint="log shippers duplicate & delay events — tests dedup/late handling"
          checked={chaos}
          danger
          onChange={(v) => onToggle('chaos', v)}
        />
      </div>
    </header>
  );
}
