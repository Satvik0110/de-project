function Stat({ label, value, children }) {
  return (
    <div className="metric-card">
      <div className="metric-card-top">{label}</div>
      {value != null && <div className="metric-card-value">{value}</div>}
      {children && <div className="metric-card-sub">{children}</div>}
    </div>
  );
}

function Breakdown({ counts }) {
  return Object.entries(counts).map(([k, v]) => (
    <span key={k} className={`breakdown ${k}`}>
      {k} <b>{v}</b>
    </span>
  ));
}

export default function StatsStrip({ stats }) {
  if (!stats) return null;
  return (
    <div className="metrics-row">
      <Stat label="Requests sent" value={stats.requests_sent} />
      <Stat label="Attack / normal" value={`${stats.attack_requests} / ${stats.normal_requests}`} />
      <Stat label="By kind">
        <Breakdown counts={stats.by_kind} />
      </Stat>
      <Stat label="Outcomes">
        <Breakdown counts={stats.outcomes} />
      </Stat>
    </div>
  );
}
