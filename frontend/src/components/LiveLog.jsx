import { useState } from 'react';
import { Activity } from 'lucide-react';
import { formatTime } from '../format';

const FILTERS = { All: null, Attacks: 'attack', Normal: 'normal' };

export default function LiveLog({ entries, onSelect }) {
  const [filter, setFilter] = useState('All');
  const team = FILTERS[filter];
  const shown = team ? entries.filter((e) => e.team === team) : entries;

  return (
    <section className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={16} /> Live log
        </div>
        <div className="filter-group">
          {Object.keys(FILTERS).map((f) => (
            <button
              key={f}
              className={`filter-btn${f === filter ? ' active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
      </div>
      <div className="table events-list">
        <div className="table-row log-row col-header">
          <span>Time</span>
          <span>Source IP</span>
          <span>Action</span>
          <span>Result</span>
          <span>Scenario</span>
        </div>
        {shown.length === 0 && <div className="empty">Waiting for traffic…</div>}
        {shown.map((e, i) => (
          <div
            key={`${e.at}-${i}`}
            className={`table-row log-row clickable ${e.team}`}
            onClick={() => onSelect(e)}
          >
            <span>{formatTime(e.at)}</span>
            <span>{e.src_ip}</span>
            <span className="cell" title={e.action}>{e.action}</span>
            <span className={`badge-status ${e.outcome}`}>{e.result}</span>
            <span className="cell">{e.scenario ?? '—'}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
