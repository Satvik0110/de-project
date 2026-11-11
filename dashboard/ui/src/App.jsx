import { useCallback, useRef, useState } from 'react'
import { getJSON, useLive, usePoll } from './api.js'
import { fmtTime } from './format.js'
import KpiRow from './components/KpiRow.jsx'
import PerfCharts from './components/PerfCharts.jsx'
import AlertsFeed from './components/AlertsFeed.jsx'
import Incidents from './components/Incidents.jsx'
import Scoreboard from './components/Scoreboard.jsx'
import StorageStrip from './components/StorageStrip.jsx'

const RANK = { early: 0, escalated: 1, final: 2 }
const WINDOW_MS = 15 * 60 * 1000
const MAX_ALERTS = 300

// A version replaces the stored one if it is further along early → escalated → final
// (or the same stage but detected later).
const isNewer = (a, old) => {
  if (!old) return true
  const d = (RANK[a.trigger] ?? 0) - (RANK[old.trigger] ?? 0)
  return d > 0 || (d === 0 && (a.detected_at ?? '') >= (old.detected_at ?? ''))
}

function mergeAlerts(prev, list, live) {
  const next = new Map(prev)
  for (const a of list) {
    if (isNewer(a, next.get(a.alert_id))) next.set(a.alert_id, live ? { ...a, live: true } : a)
  }
  if (next.size <= MAX_ALERTS) return next
  const keep = [...next.values()].sort(byDetectedDesc).slice(0, MAX_ALERTS)
  return new Map(keep.map((a) => [a.alert_id, a]))
}

const byDetectedDesc = (a, b) => ((a.detected_at ?? '') < (b.detected_at ?? '') ? 1 : -1)

function mergeMetrics(prev, list) {
  const byAt = new Map(prev.map((m) => [m.at, m]))
  for (const m of list) if (m?.at) byAt.set(m.at, m)
  const all = [...byAt.values()].sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
  const cutoff = Date.parse(all.at(-1)?.at) - WINDOW_MS
  return all.filter((m) => Date.parse(m.at) >= cutoff)
}

export default function App() {
  const [alerts, setAlerts] = useState(() => new Map())
  const [metrics, setMetrics] = useState([])
  const [alertTick, setAlertTick] = useState(0)
  const debounce = useRef()

  const seed = useCallback(() => {
    getJSON('/api/metrics?minutes=15').then((l) => setMetrics((p) => mergeMetrics(p, l))).catch(() => {})
    getJSON('/api/alerts?limit=100').then((l) => setAlerts((p) => mergeAlerts(p, l, false))).catch(() => {})
  }, [])

  const onMessage = useCallback((msg) => {
    if (msg.type === 'alert' && msg.alert) {
      setAlerts((p) => mergeAlerts(p, [msg.alert], true))
      clearTimeout(debounce.current)
      debounce.current = setTimeout(() => setAlertTick((t) => t + 1), 1500)
    } else if (msg.type === 'metrics' && msg.metrics) {
      setMetrics((p) => mergeMetrics(p, [msg.metrics]))
    }
  }, [])

  const status = useLive(onMessage, seed)
  const summary = usePoll('/api/summary', 5000, alertTick)
  const latest = metrics.at(-1) ?? summary?.metrics ?? null
  const alertList = [...alerts.values()].sort(byDetectedDesc)

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="brand-mark">◆</span>
          <div>
            <h1>SOC Dashboard <span className="tag">Blue team</span></h1>
            <p className="muted">Real-time SIEM · detections, incidents and pipeline health</p>
          </div>
        </div>
        <div className="header-right">
          <span className="muted">last snapshot {fmtTime(latest?.at)}</span>
          <span className={`conn conn-${status}`}>
            <span className="dot" />
            {status === 'live' ? 'LIVE' : status === 'down' ? 'BACKEND DOWN — retrying' : 'CONNECTING'}
          </span>
        </div>
      </header>

      <main className="main">
        <KpiRow metrics={latest} summary={summary} />
        <div className="grid-2 wide-left">
          <AlertsFeed alerts={alertList} />
          <PerfCharts history={metrics} latest={latest} />
        </div>
        <div className="grid-2">
          <Incidents refreshKey={alertTick} />
          <Scoreboard refreshKey={alertTick} />
        </div>
        <StorageStrip summary={summary} />
      </main>
    </div>
  )
}
