import { fmtMs, fmtNum } from '../format.js'

function Kpi({ label, value, unit, tone }) {
  return (
    <div className={`kpi ${tone ?? ''}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">
        {value}
        {unit && value !== '—' && <span className="kpi-unit">{unit}</span>}
      </div>
    </div>
  )
}

export default function KpiRow({ metrics, summary }) {
  const m = metrics ?? {}
  const lat = m.detection_latency_ms ?? {}
  const totals = m.totals ?? {}
  const sevTotal = summary ? Object.values(summary.alerts_by_severity ?? {}).reduce((s, n) => s + n, 0) : null
  const inc = summary?.incidents

  return (
    <div className="kpis">
      <Kpi label="Events / s" value={fmtNum(m.events_per_s, 1)} tone="accent" />
      <Kpi label="Consumer lag" value={fmtNum(m.consumer_lag)} unit="msgs" />
      <Kpi label="Detect p50" value={fmtMs(lat.p50)} tone="accent" />
      <Kpi label="Detect p95" value={fmtMs(lat.p95)} />
      <Kpi label="Alerts" value={fmtNum(totals.alerts ?? sevTotal)} tone="alert" />
      <Kpi
        label="Multi-stage incidents"
        value={fmtNum(inc?.multi_stage)}
        unit={inc ? `of ${fmtNum(inc.total)}` : null}
        tone="alert"
      />
      <Kpi label="Duplicates dropped" value={fmtNum(totals.duplicate)} tone="dq" />
      <Kpi label="Late dropped" value={fmtNum(totals.late)} tone="dq" />
      <Kpi label="Invalid → DLQ" value={fmtNum(totals.invalid)} tone="dq" />
    </div>
  )
}
