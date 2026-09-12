import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import ControlPanel from './components/ControlPanel';
import AttackArsenal from './components/AttackArsenal';
import MetricsOverview from './components/MetricsOverview';
import LiveEventStream from './components/LiveEventStream';
import EventInspectorModal from './components/EventInspectorModal';
import './App.css';

const API_BASE = 'http://localhost:8001';
const WS_URL = 'ws://localhost:8001/ws/events';

export default function App() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [config, setConfig] = useState({
    running: false,
    events_per_second: 10,
    attack_ratio: 1.0,
    only_attacks: true,
    active_scenario: 'all',
    selected_scenarios: [
      'auth_brute_force', 'auth_jwt_tampering',
      'api_injection_probe', 'api_rate_limit',
      'network_port_scan', 'network_slowloris'
    ],

    target_base_url: 'http://localhost:8002',
    target_ip: '10.0.0.5',
    target_user: 'admin',
    target_api_url: 'http://localhost:8000/api/v1/events',
    forward_to_target: false,
    inject_late_watermark: false,
    inject_duplicates: false
  });

  const [connected, setConnected] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  useEffect(() => {
    let isMounted = true;
    let ws = null;
    let reconnectTimer = null;

    const connect = () => {
      if (!isMounted) return;
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
      }

      try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
          if (isMounted) setConnected(true);
        };

        ws.onmessage = (message) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(message.data);
            if (data.type === 'INITIAL_STATE') {
              if (data.config) setConfig(data.config);
              if (data.stats) setStats(data.stats);
              if (data.stats?.running && data.recent_events) {
                setEvents(data.recent_events.slice().reverse());
              } else {
                setEvents([]);
              }
            } else if (data.type === 'NEW_EVENT') {
              setEvents((prev) => {
                // Deduplication guard: ignore if event_id already in recent state
                if (prev.length > 0 && prev[0].event_id === data.event.event_id) {
                  return prev;
                }
                return [data.event, ...prev.slice(0, 399)];
              });
              if (data.stats) setStats(data.stats);
            } else if (data.type === 'RESET_STATE') {
              setEvents([]);
              if (data.stats) setStats(data.stats);
            }
          } catch (e) {
            console.error('Error parsing WS message', e);
          }
        };

        ws.onclose = () => {
          if (isMounted) {
            setConnected(false);
            if (!reconnectTimer) {
              reconnectTimer = setTimeout(() => {
                reconnectTimer = null;
                connect();
              }, 2000);
            }
          }
        };

        ws.onerror = () => {
          if (isMounted) setConnected(false);
        };
      } catch (e) {
        if (isMounted) {
          setConnected(false);
          if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => {
              reconnectTimer = null;
              connect();
            }, 2000);
          }
        }
      }
    };

    connect();

    fetch(`${API_BASE}/api/stats`)
      .then((res) => res.json())
      .then((data) => { if (isMounted) setStats(data); })
      .catch(() => {});

    fetch(`${API_BASE}/api/config`)
      .then((res) => res.json())
      .then((data) => { if (isMounted) setConfig(data); })
      .catch(() => {});

    return () => {
      isMounted = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) {
        ws.onclose = null; // Prevent reconnect on manual unmount
        ws.close();
      }
    };
  }, []);

  // Simulator actions
  const handleStart = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/start`, { method: 'POST' });
      const data = await res.json();
      setStats(data.stats);
      setConfig((prev) => ({ ...prev, running: true }));
    } catch (e) {
      console.error('Failed to start simulation', e);
    }
  };

  const handlePause = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/pause`, { method: 'POST' });
      const data = await res.json();
      setStats(data.stats);
      setConfig((prev) => ({ ...prev, running: false }));
    } catch (e) {
      console.error('Failed to pause simulation', e);
    }
  };

  const handleStop = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stop`, { method: 'POST' });
      const data = await res.json();
      setStats(data.stats);
      setConfig((prev) => ({ ...prev, running: false }));
    } catch (e) {
      console.error('Failed to stop simulation', e);
    }
  };

  const handleReset = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/reset`, { method: 'POST' });
      const data = await res.json();
      setStats(data.stats);
      setEvents([]);
      setConfig((prev) => ({ ...prev, running: false }));
    } catch (e) {
      console.error('Failed to reset simulation', e);
    }
  };

  const handleUpdateConfig = async (newConfig) => {
    setConfig(newConfig);
    try {
      await fetch(`${API_BASE}/api/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig)
      });
    } catch (e) {
      console.error('Failed to update config', e);
    }
  };

  const handleTriggerAttack = async (scenario, burstCount) => {
    try {
      await fetch(`${API_BASE}/api/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario,
          burst_count: burstCount,
          target_user: config.target_user
        })
      });
    } catch (e) {
      console.error('Failed to trigger attack', e);
    }
  };

  const handleClearEvents = () => {
    setEvents([]);
  };

  return (
    <div className="app-container">
      {/* Header with Master Controls */}
      <Header
        stats={stats}
        onStart={handleStart}
        onPause={handlePause}
        onStop={handleStop}
        onReset={handleReset}
      />

      {/* Main Grid */}
      <main className="main-content">
        {/* Left Column: Target Controls & Attack Arsenal */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <ControlPanel
            config={config}
            onUpdateConfig={handleUpdateConfig}
          />
          <AttackArsenal
            onTriggerAttack={handleTriggerAttack}
            targetBaseUrl={config.target_base_url || 'http://localhost:8002'}
            targetUser={config.target_user || 'admin'}
          />
        </div>

        {/* Right Column: Telemetry & Live Stream */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <MetricsOverview stats={stats} />
          <LiveEventStream
            events={events}
            targetBaseUrl={config.target_base_url || 'http://localhost:8002'}
            onSelectEvent={(ev) => setSelectedEvent(ev)}
            onClearEvents={handleClearEvents}
          />
        </div>
      </main>

      {/* Raw Event Inspector Modal */}
      <EventInspectorModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}
