import { Loader2, Swords } from 'lucide-react';

function ScenarioButton({ scenario, running, disabled, onLaunch }) {
  const multiStage = scenario.id === 'kill_chain';
  return (
    <button
      className={`btn-attack${multiStage ? ' multi-stage' : ''}${running ? ' running' : ''}`}
      disabled={disabled || running}
      onClick={() => onLaunch(scenario.id)}
    >
      <span className="attack-btn-top">
        <span className="attack-btn-title">{scenario.name}</span>
        {running && <Loader2 size={14} className="spin" />}
      </span>
      <span className="badge-row">
        {multiStage && <span className="attack-chip">Multi-stage</span>}
        <span className="tag">{scenario.tactic}</span>
        <span className="tag mono">{scenario.technique}</span>
      </span>
      <span className="attack-btn-desc">{scenario.description}</span>
      <span className="attack-btn-rules">
        expects: {scenario.expected_rules.join(', ')}
      </span>
    </button>
  );
}

export default function AttackLauncher({ scenarios, running, disabled, onLaunch }) {
  return (
    <section className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Swords size={16} /> Launch attack
        </div>
      </div>
      <div className="panel-body attack-list">
        {scenarios.map((s) => (
          <ScenarioButton
            key={s.id}
            scenario={s}
            running={running.has(s.id)}
            disabled={disabled}
            onLaunch={onLaunch}
          />
        ))}
      </div>
    </section>
  );
}
