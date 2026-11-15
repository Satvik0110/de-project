import { usePoll } from '../api.js'
import Panel, { Waiting } from './Panel.jsx'
import { fmtBytes, fmtNum, fmtSec } from '../format.js'

const Step = ({ label, value, sub }) => (
  <div className="flow-step">
    <span className="kpi-label">{label}</span>
    <b>{fmtNum(value)}</b>
    {sub && <span className="muted small">{sub}</span>}
  </div>
)

const Arrow = () => <span className="arrow">→</span>

function Reconciliation({ r }) {
  const lostTone = r.lost == null ? '' : r.lost === 0 ? 'ok' : 'lost'
  return (
    <div className="flow">
      <Step label="Shipped" value={r.shipped} sub="by log shippers" />
      <Arrow />
      <Step label="Kafka" value={r.in_kafka} sub="security.events.raw" />
      <Arrow />
      <Step label="Processed" value={r.processed} sub="stream processor" />
      <Arrow />
      <Step label="Lake" value={r.in_lake} sub={`+ ${fmtNum(r.lake_pending)} pending flush`} />
      <div className={`lost-badge ${lostTone}`}>
        <span className="kpi-label">Events lost</span>
        <b>{fmtNum(r.lost)}</b>
        {r.shipper_failed > 0 && <span className="small warn">{fmtNum(r.shipper_failed)} failed at source</span>}
      </div>
    </div>
  )
}

function Tiers({ tiers }) {
  return (
    <div>
      <table className="table">
        <thead>
          <tr><th>Layer</th><th>Consumer group</th><th>Lag (msgs)</th><th>Freshness</th></tr>
        </thead>
        <tbody>
          {tiers.map((t) => (
            <tr key={t.tier}>
              <td className="rule">{t.tier}</td>
              <td><code className="entity">{t.group}</code></td>
              <td>{fmtNum(t.lag)}</td>
              <td>{fmtSec(t.freshness_s)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small caption">
        Each layer reads Kafka independently; a slow writer never delays detection.
      </p>
    </div>
  )
}

const Item = ({ label, value }) => (
  <div className="store-item">
    <span className="muted">{label}</span>
    <b>{value}</b>
  </div>
)

function Storage({ s, warehouse }) {
  return (
    <div className="store">
      <div className="store-group">
        <span className="store-title">Data lake</span>
        <Item label="files" value={fmtNum(s.lake_files)} />
        <Item label="rows" value={fmtNum(s.lake_rows)} />
        <Item label="partitions" value={fmtNum(s.partitions)} />
      </div>
      <div className="store-group">
        <span className="store-title">Compression</span>
        <Item label="Parquet" value={fmtBytes(s.parquet_bytes)} />
        <Item label="vs raw JSON" value={fmtBytes(s.json_bytes)} />
        {s.compression_ratio != null && <span className="ratio">×{fmtNum(s.compression_ratio, 1)} smaller</span>}
      </div>
      {warehouse && (
        <div className="store-group">
          <span className="store-title">Warehouse</span>
          <Item label="alerts" value={fmtNum(warehouse.alerts)} />
          <Item label="incidents" value={fmtNum(warehouse.incidents)} />
          <Item label="aggregates" value={fmtNum(warehouse.aggregates)} />
          <Item label="campaigns" value={fmtNum(warehouse.campaigns)} />
        </div>
      )}
    </div>
  )
}

export default function PipelineHealth({ warehouse }) {
  const p = usePoll('/api/pipeline', 5000)

  return (
    <Panel title="Pipeline health" extra={<span className="muted">end-to-end completeness · per-layer freshness</span>} className="pipeline">
      {!p ? (
        <Waiting />
      ) : (
        <>
          {p.reconciliation && <Reconciliation r={p.reconciliation} />}
          <div className="pipe-grid">
            {p.tiers?.length > 0 && <Tiers tiers={p.tiers} />}
            {p.storage && <Storage s={p.storage} warehouse={warehouse} />}
          </div>
        </>
      )}
    </Panel>
  )
}
