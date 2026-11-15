import { usePoll } from '../api.js'
import Panel, { Sev, Waiting } from './Panel.jsx'
import { firstDetected, fmtMs, fmtNum, fmtPct, fmtSec, fmtTime } from '../format.js'

const Headline = ({ label, value, sub, className = '' }) => (
  <div className={`headline ${className}`}>
    <div className="kpi-label">{label}</div>
    <div className="headline-value">{value}</div>
    {sub && <div className="muted small">{sub}</div>}
  </div>
)

const Benign = () => <span className="badge-benign">BENIGN</span>

const FunnelStep = ({ value, label }) => (
  <span className="funnel-step">
    <b>{fmtNum(value)}</b>
    <span className="muted small">{label}</span>
  </span>
)

function Funnel({ f }) {
  return (
    <span className="funnel">
      <FunnelStep value={f.attack_events} label="events" />
      <span className="arrow">→</span>
      <FunnelStep value={f.alerts} label="alerts" />
      <span className="arrow">→</span>
      <FunnelStep value={f.incidents} label="incidents" />
    </span>
  )
}

const rateClass = (n, d) => (!d ? '' : n >= d ? 'good' : n > 0 ? 'warn' : 'bad')

function Verdict({ c }) {
  if (c.malicious === false) {
    return c.fp_alerts > 0 ? <span className="verdict warn">⚠ FALSE ALARM</span> : <span className="verdict good">✓ NO ALERT</span>
  }
  return <span className={`verdict ${c.detected ? 'good' : 'bad'}`}>{c.detected ? '✓ DETECTED' : '✗ MISSED'}</span>
}

function CampaignRow({ c }) {
  const benign = c.malicious === false
  const noteClass = benign ? 'warn' : !c.detected || c.missed_rules?.length ? 'bad' : 'muted'
  return (
    <li>
      <Verdict c={c} />
      <span className="rule">{c.scenario}</span>
      {benign && <Benign />}
      <span className="muted">{fmtTime(c.started_at)}</span>
      {!benign && (
        <>
          <span>TTD <b>{fmtMs(c.ttd_ms)}</b></span>
          {c.progress_at_detection != null && <span className="muted">seen {fmtPct(c.progress_at_detection)} before alert</span>}
        </>
      )}
      <span className="rules">
        {(c.detected_rules ?? []).map((r) => <span key={r} className={`chip ${benign ? 'warn' : 'good'}`}>{r}</span>)}
        {(c.missed_rules ?? []).map((r) => <span key={r} className="chip bad">{r}</span>)}
      </span>
      {c.note && <span className={`note small ${noteClass}`}>{c.note}</span>}
    </li>
  )
}

export default function Scoreboard({ refreshKey }) {
  const sb = usePoll('/api/scoreboard', 5000, refreshKey)
  const fpCount = sb?.false_positive_alerts

  return (
    <Panel title="Detection scoreboard" extra={<span className="muted">ground truth from red-team campaigns</span>} className="score">
      {!sb ? (
        <Waiting />
      ) : (
        <>
          <div className="headlines">
            <Headline label="MTTD" value={fmtMs(sb.mttd_ms ?? sb.median_ttd_ms)} sub="median time-to-detect" />
            <Headline
              label="Alert reduction"
              value={sb.funnel ? <Funnel f={sb.funnel} /> : '—'}
              sub={sb.funnel ? `attack events → alerts → incidents · ${fmtNum(sb.funnel.events_total)} events total` : null}
              className="wide"
            />
            <Headline
              label="Attacks detected"
              value={sb.malicious_campaigns == null ? '—' : `${fmtNum(sb.detected_campaigns)}/${fmtNum(sb.malicious_campaigns)}`}
              sub="malicious campaigns"
            />
            <Headline
              label="False positives"
              value={<span className={fpCount > 0 ? 'warn' : ''}>{fmtNum(fpCount)}</span>}
              sub={`of ${fmtNum(sb.alerts_total)} alerts`}
            />
          </div>
          <p className="muted small pr">
            recall {fmtPct(sb.recall)} · precision {fmtPct(sb.precision)}
          </p>

          <table className="table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Runs</th>
                <th>Detected</th>
                <th>Median TTD</th>
                <th title="median share of the attack's events seen before the first alert">Seen before alert</th>
                <th title="median seconds the alert fired before the detection window would have closed">Before window close</th>
                <th>FP alerts</th>
              </tr>
            </thead>
            <tbody>
              {(sb.by_scenario ?? []).map((s) => {
                const benign = s.malicious === false
                return (
                  <tr key={s.scenario}>
                    <td className="rule">{s.scenario} {benign && <Benign />}</td>
                    <td>{s.campaigns}</td>
                    <td className={benign ? 'muted' : rateClass(s.detected, s.campaigns)}>{benign ? '—' : s.detected}</td>
                    <td>{fmtMs(s.median_ttd_ms)}</td>
                    <td>{fmtPct(s.median_progress)}</td>
                    <td>{fmtSec(s.median_early_by_s)}</td>
                    <td className={benign && s.fp_alerts > 0 ? 'warn' : 'muted'}>{benign ? fmtNum(s.fp_alerts) : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          <h3>Recent campaigns</h3>
          {!sb.campaigns?.length ? (
            <Waiting text="No campaigns yet." />
          ) : (
            <ul className="campaigns">
              {sb.campaigns.slice(0, 10).map((c) => <CampaignRow key={c.campaign_id} c={c} />)}
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
                  {a.reason && <span className="warn small">{a.reason}</span>}
                  <span className="muted">{fmtTime(firstDetected(a))}</span>
                </li>
              ))}
            </ul>
          </details>
        </>
      )}
    </Panel>
  )
}
