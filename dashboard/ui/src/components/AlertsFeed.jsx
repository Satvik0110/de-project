import Panel, { Sev, Waiting } from './Panel.jsx'
import { fmtMs, fmtTime } from '../format.js'

export default function AlertsFeed({ alerts }) {
  return (
    <Panel title="Live alerts" extra={<span className="muted">{alerts.length} alerts · newest first</span>} className="feed">
      {alerts.length === 0 ? (
        <Waiting text="No alerts yet — launch an attack on the red-team console." />
      ) : (
        <ul className="alerts">
          {alerts.map((a) => (
            <li key={`${a.alert_id}:${a.trigger}`} className={`alert sev-border-${a.severity} ${a.live ? 'flash' : ''}`}>
              <div className="alert-top">
                <Sev level={a.severity} />
                <span className="rule">{a.rule_name}</span>
                <span className={`trigger trigger-${a.trigger}`}>{a.trigger}</span>
                <span className="attck">
                  {a.technique} · {a.tactic}
                </span>
                <span className="alert-time">{fmtTime(a.detected_at)}</span>
              </div>
              <div className="alert-bottom">
                <code className="entity">{a.entity}</code>
                <span>
                  count <b>{a.count}</b> / {a.threshold}
                </span>
                <span>
                  detected in <b className="latency">{fmtMs(a.detection_latency_ms)}</b>
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
