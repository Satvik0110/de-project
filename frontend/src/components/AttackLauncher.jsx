import { Loader2, ShieldCheck, Swords } from 'lucide-react';

function ScenarioButton({ scenario, running, disabled, onLaunch }) {
  const multiStage = scenario.id === 'kill_chain';
  const benign = scenario.malicious === false;
  const duration = scenario.duration_s >= 60 ? `~${Math.round(scenario.duration_s / 60)} min` : null;
  return (
    <button
      className={`btn-attack${multiStage ? ' multi-stage' : ''}${benign ? ' benign' : ''}${running ? ' running' : ''}`}
      disabled={disabled || running}
      onClick={() => onLaunch(scenario.id)}
    >
      <span className="attack-btn-top">
        <span className="attack-btn-title">{scenario.name}</span>
        {running && <Loader2 size={14} className="spin" />}
      </span>
      <span className="badge-row">
        {multiStage && <span className="attack-chip">Multi-stage</span>}
        {benign && <span className="attack-chip benign">Benign</span>}
        <span className="tag">{scenario.tactic}</span>
        <span className="tag mono">{scenario.technique}</span>
        {duration && <span className="tag duration">{duration}</span>}
      </span>
      <span className="attack-btn-desc">{scenario.description}</span>
      <span className="attack-btn-rules">
        expects: {benign ? 'no alert' : (scenario.expected_rules ?? []).join(', ')}
      </span>
    </button>
  );
}

export default function AttackLauncher({ scenarios, running, disabled, onLaunch }) {
  const button = (s) => (
    <ScenarioButton
      key={s.id}
      scenario={s}
      running={running.has(s.id)}
      disabled={disabled}
      onLaunch={onLaunch}
    />
  );
  const benign = scenarios.filter((s) => s.malicious === false);
  return (
    <section className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Swords size={16} /> Launch attack
        </div>
      </div>
      <div className="panel-body attack-list">
        {scenarios.filter((s) => s.malicious !== false).map(button)}
        {benign.length > 0 && (
          <>
            <div className="group-title benign">
              <ShieldCheck size={14} /> Benign but suspicious — should NOT be treated as attacks
            </div>
            {benign.map(button)}
          </>
        )}
      </div>
    </section>
  );
}
