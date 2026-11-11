import { useCallback, useEffect, useState } from 'react'
import { getJSON, usePoll } from '../api.js'
import Panel, { Sev, Waiting } from './Panel.jsx'
import { fmtMs, fmtSpan, fmtTime } from '../format.js'

const Chain = ({ tactics }) => (
  <div className="chain">
    {tactics.map((t, i) => (
      <span key={`${t}-${i}`} className="chain-step">
        {i > 0 && <span className="arrow">→</span>}
        <span className="tactic">{t}</span>
      </span>
    ))}
  </div>
)

const SourceTag = ({ source }) =>
  source ? <span className={`src src-${source}`}>{source === 'llm' ? 'AI' : 'template'}</span> : null

function IncidentDetail({ id, onClose }) {
  const [inc, setInc] = useState(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    getJSON(`/api/incidents/${encodeURIComponent(id)}`).then(setInc).catch(() => setFailed(true))
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [id, onClose])

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="close" onClick={onClose} aria-label="Close">×</button>
        {!inc ? (
          <Waiting text={failed ? 'Could not load incident.' : 'Loading…'} />
        ) : (
          <>
            <div className="inc-head">
              <Sev level={inc.severity} />
              <code className="entity big">{inc.entity}</code>
              {inc.multi_stage && <span className="badge-multi">MULTI-STAGE</span>}
            </div>
            <Chain tactics={inc.tactics ?? []} />
            {inc.summary && (
              <p className="summary">
                <SourceTag source={inc.summary_source} /> {inc.summary}
              </p>
            )}
            <h3>Alert timeline</h3>
            <table className="table">
              <thead>
                <tr>
                  <th>Detected</th><th>Severity</th><th>Rule</th><th>Tactic</th><th>Trigger</th><th>Count</th><th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {(inc.alerts ?? []).map((a) => (
                  <tr key={`${a.alert_id}:${a.trigger}`}>
                    <td>{fmtTime(a.detected_at)}</td>
                    <td><Sev level={a.severity} /></td>
                    <td className="rule">{a.rule_name}</td>
                    <td>{a.technique} · {a.tactic}</td>
                    <td><span className={`trigger trigger-${a.trigger}`}>{a.trigger}</span></td>
                    <td>{a.count} / {a.threshold}</td>
                    <td>{fmtMs(a.detection_latency_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}

export default function Incidents({ refreshKey }) {
  const incidents = usePoll('/api/incidents?limit=50', 5000, refreshKey)
  const [selected, setSelected] = useState(null)
  const close = useCallback(() => setSelected(null), [])

  return (
    <Panel title="Incidents" extra={<span className="muted">correlated by entity · click for timeline</span>} className="incidents">
      {!incidents?.length ? (
        <Waiting text={incidents ? 'No incidents yet.' : undefined} />
      ) : (
        <div className="inc-list">
          {incidents.map((i) => (
            <button key={i.incident_id} className={`inc-card sev-border-${i.severity}`} onClick={() => setSelected(i.incident_id)}>
              <div className="inc-head">
                <Sev level={i.severity} />
                <code className="entity">{i.entity}</code>
                {i.multi_stage && <span className="badge-multi">MULTI-STAGE</span>}
                <span className="inc-meta">
                  {i.alert_count} alerts · {fmtSpan(i.first_seen, i.last_seen)} · {fmtTime(i.last_seen)}
                </span>
              </div>
              <Chain tactics={i.tactics ?? []} />
              <div className="rules">
                {(i.rules ?? []).map((r) => <span key={r} className="chip">{r}</span>)}
              </div>
              {i.summary && (
                <p className="summary">
                  <SourceTag source={i.summary_source} /> {i.summary}
                </p>
              )}
            </button>
          ))}
        </div>
      )}
      {selected && <IncidentDetail id={selected} onClose={close} />}
    </Panel>
  )
}
