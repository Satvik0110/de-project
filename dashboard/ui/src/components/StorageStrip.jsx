import { fmtBytes, fmtNum } from '../format.js'

const Item = ({ label, value }) => (
  <div className="store-item">
    <span className="muted">{label}</span>
    <b>{value}</b>
  </div>
)

export default function StorageStrip({ summary }) {
  const lake = summary?.lake ?? {}
  const wh = summary?.warehouse ?? {}
  return (
    <section className="storage">
      <div className="store-group">
        <span className="store-title">Data lake</span>
        <Item label="files" value={fmtNum(lake.files)} />
        <Item label="rows" value={fmtNum(lake.rows)} />
        <Item label="size" value={fmtBytes(lake.bytes)} />
      </div>
      <div className="store-group">
        <span className="store-title">Warehouse</span>
        <Item label="alerts" value={fmtNum(wh.alerts)} />
        <Item label="incidents" value={fmtNum(wh.incidents)} />
        <Item label="aggregates" value={fmtNum(wh.aggregates)} />
        <Item label="campaigns" value={fmtNum(wh.campaigns)} />
      </div>
    </section>
  )
}
