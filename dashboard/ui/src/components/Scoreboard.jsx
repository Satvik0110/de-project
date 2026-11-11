import { usePoll } from '../api.js'
import Panel, { Sev, Waiting } from './Panel.jsx'
import { fmtMs, fmtPct, fmtTime } from '../format.js'

const Headline = ({ label, value, sub }) => (
  <div className="headline">
    <div className="kpi-label">{label}</div>
    <div className="headline-value">{value}</div>
    {sub && <div className="muted small">{sub}</div>}
  </div>
)

export default function Scoreboard({ refreshKey }) {
  const sb = usePoll('/api/scoreboard', 5000, refreshKey)

  return (
    <Panel title="Detection scoreboard" extra={<span className="muted">ground truth from red-team campaigns</span>} className="score">
      {!sb ? (
        <Waiting />
      ) : (
        <>
          <div className="headlines">
            <Headline label="Recall" value={fmtPct(sb.recall)} sub="campaigns detected" />
            <Headline
              label="Precision"
              value={fmtPct(sb.precision)}
              sub={`${sb.true_positive_alerts ?? 0} TP · ${sb.false_positive_alerts ?? 0} FP`}
            />
            <Headline label="Median time-to-detect" value={fmtMs(sb.median_ttd_ms)} sub={`${sb.alerts_total ?? 0} alerts total`} />
          </div>

          <table className="table">
            <thead>
              <tr><th>Scenario</th><th>Campaigns</th><th>Detected</th><th>Rate</th><th>Median TTD</th></tr>
            </thead>
            <tbody>
              {(sb.by_scenario ?? []).map((s) => (
                <tr key={s.scenario}>
                  <td className="rule">{s.scenario}</td>
                  <td>{s.campaigns}</td>
                  <td>{s.detected}</td>
                  <td className={s.detection_rate >= 1 ? 'good' : s.detection_rate > 0 ? 'warn' : 'bad'}>{fmtPct(s.detection_rate)}</td>
                  <td>{fmtMs(s.median_ttd_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h3>Recent campaigns</h3>
          {!sb.campaigns?.length ? (
            <Waiting text="No campaigns yet." />
          ) : (
            <ul className="campaigns">
              {sb.campaigns.slice(0, 10).map((c) => (
                <li key={c.campaign_id}>
                  <span className={`verdict ${c.detected ? 'good' : 'bad'}`}>{c.detected ? '✓ DETECTED' : '✗ MISSED'}</span>
                  <span className="rule">{c.scenario}</span>
                  <span className="muted">{fmtTime(c.started_at)}</span>
                  <span>TTD <b>{fmtMs(c.ttd_ms)}</b></span>
                  <span className="rules">
                    {(c.detected_rules ?? []).map((r) => <span key={r} className="chip good">{r}</span>)}
                    {(c.missed_rules ?? []).map((r) => <span key={r} className="chip bad">{r}</span>)}
                  </span>
                </li>
              ))}
            </ul>
          )}

          <details className="fps">
            <summary>False-positive alerts ({sb.false_positives?.length ?? 0})</summary>
            <ul className="fp-list">
              {(sb.false_positives ?? []).map((a) => (
                <li key={`${a.alert_id}:${a.trigger}`}>
                  <Sev level={a.severity} />
                  <span className="rule">{a.rule_name}</span>
                  <code className="entity">{a.entity}</code>
                  <span className="muted">{fmtTime(a.detected_at)}</span>
                </li>
              ))}
            </ul>
          </details>
        </>
      )}
    </Panel>
  )
}
