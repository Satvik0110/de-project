import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import Panel, { Waiting } from './Panel.jsx'
import { fmtMs, fmtNum, fmtTime } from '../format.js'

const C1 = '#22d3ee'
const C2 = '#f59e0b'
const AXIS = { stroke: '#64748b', fontSize: 11, tickLine: false, axisLine: false }

function Chart({ title, data, lines, fmt }) {
  return (
    <div className="chart">
      <div className="chart-title">{title}</div>
      <ResponsiveContainer width="100%" height={120}>
        <LineChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
          <XAxis
            dataKey="t"
            type="number"
            domain={['dataMin', 'dataMax']}
            tickFormatter={(t) => fmtTime(new Date(t).toISOString()).slice(0, 5)}
            minTickGap={40}
            {...AXIS}
          />
          <YAxis width={48} tickFormatter={fmt} {...AXIS} />
          <Tooltip
            contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 6 }}
            labelStyle={{ color: '#94a3b8' }}
            itemStyle={{ color: '#f8fafc' }}
            labelFormatter={(t) => fmtTime(new Date(t).toISOString())}
            formatter={(v) => fmt(v)}
          />
          {lines.length > 1 && <Legend iconType="plainline" wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />}
          {lines.map((l) => (
            <Line
              key={l.key}
              dataKey={l.key}
              name={l.name}
              stroke={l.color}
              strokeDasharray={l.dash}
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
              connectNulls
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

function Stage({ label, s }) {
  return (
    <div className="stage">
      <span className="muted">{label}</span>
      <b>{fmtMs(s?.p50)}</b>
      <span className="muted">p50</span>
      <b>{fmtMs(s?.p95)}</b>
      <span className="muted">p95</span>
    </div>
  )
}

export default function PerfCharts({ history, latest }) {
  const data = history.map((m) => ({
    t: Date.parse(m.at),
    eps: m.events_per_s,
    lag: m.consumer_lag,
    p50: m.detection_latency_ms?.p50 ?? null,
    p95: m.detection_latency_ms?.p95 ?? null,
  }))
  const stage = latest?.stage_latency_ms

  return (
    <Panel
      title="Pipeline performance"
      extra={<span className="muted">last 15 min</span>}
      className="perf"
    >
      <div className="stages">
        <Stage label="Ingest" s={stage?.ingest} />
        <Stage label="Processing" s={stage?.processing} />
        <div className="stage">
          <span className="muted">Watermark delay</span>
          <b>{latest?.watermark_delay_s == null ? '—' : `${fmtNum(latest.watermark_delay_s, 1)} s`}</b>
        </div>
      </div>
      {data.length < 2 ? (
        <Waiting text="Waiting for metrics snapshots…" />
      ) : (
        <>
          <Chart title="Throughput (events/s)" data={data} fmt={(v) => fmtNum(v, 1)} lines={[{ key: 'eps', name: 'events/s', color: C1 }]} />
          <Chart
            title="Detection latency (ms)"
            data={data}
            fmt={fmtMs}
            lines={[
              { key: 'p50', name: 'p50', color: C1 },
              { key: 'p95', name: 'p95', color: C2, dash: '5 3' },
            ]}
          />
          <Chart title="Consumer lag (messages)" data={data} fmt={(v) => fmtNum(v)} lines={[{ key: 'lag', name: 'lag', color: C1 }]} />
        </>
      )}
    </Panel>
  )
}
