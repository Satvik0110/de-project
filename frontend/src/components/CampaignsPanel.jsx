import { History } from 'lucide-react';
import { formatTime } from '../format';

export default function CampaignsPanel({ campaigns }) {
  return (
    <section className="soc-panel">
      <div className="panel-header">
        <div className="panel-title">
          <History size={16} /> Campaigns
        </div>
      </div>
      <div className="table">
        <div className="table-row campaign-row col-header">
          <span>Status</span>
          <span>Scenario</span>
          <span>Attacker IPs</span>
          <span>Requests</span>
          <span>Started</span>
          <span>Ended</span>
        </div>
        {campaigns.length === 0 && <div className="empty">No campaigns yet.</div>}
        {campaigns.map((c) => (
          <div key={c.campaign_id} className="table-row campaign-row">
            <span className={`badge-status ${c.status}`}>{c.status}</span>
            <span>{c.scenario}</span>
            <span className="cell" title={c.attacker_ips.join(', ')}>
              {c.attacker_ips.join(', ')}
            </span>
            <span>{c.requests}</span>
            <span>{formatTime(c.started_at)}</span>
            <span>{formatTime(c.ended_at)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
