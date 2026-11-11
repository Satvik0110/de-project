import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Search, Filter, Trash2, ArrowDown, ExternalLink } from 'lucide-react';

export default function LiveEventStream({ events, targetBaseUrl = 'http://localhost:8002', onSelectEvent, onClearEvents }) {
  const [filterType, setFilterType] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = 0; // newest at top or bottom? Let's keep newest at top
    }
  }, [events, autoScroll]);

  const filteredEvents = events.filter((ev) => {
    if (filterType === 'auth' && ev.source_type !== 'auth') return false;
    if (filterType === 'network' && ev.source_type !== 'network') return false;
    if (filterType === 'api' && ev.source_type !== 'api') return false;
    if (filterType === 'attacks' && ev.raw_payload?.threat_flag !== 'malicious') return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchIp = ev.src_ip?.toLowerCase().includes(q) || ev['dest_ip:port']?.toLowerCase().includes(q);
      const matchUser = ev.user?.toLowerCase().includes(q);
      const matchId = ev.event_id?.toLowerCase().includes(q);
      const matchAttack = ev.raw_payload?.attack_type?.toLowerCase().includes(q);
      if (!matchIp && !matchUser && !matchId && !matchAttack) return false;
    }

    return true;
  });

  const formatTime = (isoString) => {
    if (!isoString) return '--:--:--';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
    } catch {
      return isoString.slice(11, 23);
    }
  };

  return (
    <div className="soc-panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <div className="panel-title">
          <Terminal size={16} color="var(--accent-cyan)" />
          Live Security Event Stream
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-Scroll
          </label>
          <button
            onClick={onClearEvents}
            className="filter-btn"
            style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', padding: '0.25rem 0.6rem' }}
            title="Clear buffer"
          >
            <Trash2 size={13} />
            Clear
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="feed-controls">
        <div className="filter-group">
          {['all', 'auth', 'network', 'api'].map((ft) => (
            <button
              key={ft}
              className={`filter-btn ${filterType === ft ? 'active' : ''}`}
              onClick={() => setFilterType(ft)}
            >
              {ft === 'all' ? 'All Events' :
               ft === 'auth' ? 'Authorisation' :
               ft.toUpperCase()}
            </button>
          ))}
        </div>

        <div className="search-input-wrapper">
          <Search size={14} color="var(--text-muted)" />
          <input
            type="text"
            className="search-field"
            placeholder="Search IP, user, or attack..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Table Column Headers */}
      <div className="event-row col-header">
        <div className="event-col">TIMESTAMP</div>
        <div className="event-col">SOURCE</div>
        <div className="event-col">STATUS</div>
        <div className="event-col">SRC IP</div>
        <div className="event-col">DEST IP:PORT</div>
        <div className="event-col">USER</div>
        <div className="event-col">CONTEXT AND ATTACK INFO</div>
      </div>


      {/* Event Stream Rows */}
      <div className="events-list" ref={scrollRef}>
        {filteredEvents.length === 0 ? (
          <div style={{
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '260px',
            padding: '2rem',
            color: 'var(--text-muted)'
          }}>
            <div style={{ fontSize: '0.85rem', maxWidth: '460px', lineHeight: '1.5' }}>
              Click <b style={{ color: 'var(--status-success)' }}>START SIMULATION</b> or launch an attack scenario from the Arsenal to begin ingestion.
            </div>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isAttack = ev.raw_payload?.threat_flag === 'malicious';
            const attackTag = ev.raw_payload?.attack_type || ev.raw_payload?.service || ev.raw_payload?.http_method;
            const detail = ev.raw_payload?.description || ev.raw_payload?.failure_reason || ev.raw_payload?.endpoint || '';

            return (
              <div
                key={ev.event_id + Math.random()}
                className={`event-row ${isAttack ? 'is-attack' : ''}`}
                onClick={() => onSelectEvent(ev)}
                title="Click to view full event JSON payload"
              >
                <div className="event-col" style={{ color: 'var(--text-code)' }}>
                  {formatTime(ev.event_time)}
                </div>

                <div className="event-col">
                  <span className={`badge-type ${ev.source_type}`}>
                    {ev.source_type === 'auth' ? 'Authorisation' : ev.source_type}
                  </span>
                </div>

                <div className="event-col">
                  <span className={`badge-status ${ev.status === 'ok' || ev.status === 'success' ? 'ok' : 'invalid'}`}>
                    {ev.status === 'ok' || ev.status === 'success' ? 'OK' : 'INVALID'}
                  </span>
                </div>

                <div className="event-col font-mono" style={{ color: isAttack ? 'var(--status-denied)' : 'var(--text-primary)' }}>
                  {ev.src_ip}
                </div>

                <div className="event-col font-mono">
                  {ev['dest_ip:port']}
                </div>

                <div className="event-col" style={{ color: ev.user ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                  {ev.user || '<none>'}
                </div>

                <div className="event-col" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  {isAttack && (
                    <span className="attack-chip" style={{ fontSize: '0.65rem' }}>
                      {attackTag}
                    </span>
                  )}
                  <span style={{ color: isAttack ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                    {detail}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
