import { useEffect, useState } from 'react';
import Header from './components/Header';
import AttackLauncher from './components/AttackLauncher';
import CampaignsPanel from './components/CampaignsPanel';
import StatsStrip from './components/StatsStrip';
import LiveLog from './components/LiveLog';
import EventInspectorModal from './components/EventInspectorModal';
import './App.css';

const API_BASE = 'http://localhost:8001';
const WS_URL = 'ws://localhost:8001/ws';
const MAX_LOG = 300;
const MAX_CAMPAIGNS = 20;
const RECONNECT_MS = 2000;

const EMPTY_STATE = { background: false, chaos: false, scenarios: [], campaigns: [], stats: null };

function upsertCampaign(campaigns, campaign) {
  const rest = campaigns.filter((c) => c.campaign_id !== campaign.campaign_id);
  return [campaign, ...rest]
    .sort((a, b) => b.started_at.localeCompare(a.started_at))
    .slice(0, MAX_CAMPAIGNS);
}

async function post(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} failed: HTTP ${res.status}`);
  return res.json();
}

function useSimulator() {
  const [connected, setConnected] = useState(false);
  const [sim, setSim] = useState(EMPTY_STATE);
  const [log, setLog] = useState([]);

  useEffect(() => {
    let ws;
    let timer;
    let closed = false;

    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) timer = setTimeout(connect, RECONNECT_MS);
      };
      ws.onmessage = (msg) => {
        const data = JSON.parse(msg.data);
        switch (data.type) {
          case 'state': {
            const { background, chaos, scenarios, campaigns, stats } = data;
            setSim({ background, chaos, scenarios, campaigns, stats });
            break;
          }
          case 'log':
            setLog((prev) => [data.entry, ...prev].slice(0, MAX_LOG));
            break;
          case 'campaign':
            setSim((s) => ({ ...s, campaigns: upsertCampaign(s.campaigns, data.campaign) }));
            break;
          case 'stats':
            setSim((s) => ({ ...s, stats: data.stats }));
            break;
          case 'toggles':
            setSim((s) => ({ ...s, background: data.background, chaos: data.chaos }));
            break;
        }
      };
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      ws.close();
    };
  }, []);

  const setToggle = async (name, enabled) => {
    const state = await post(`/api/${name}`, { enabled });
    setSim((s) => ({ ...s, background: state.background, chaos: state.chaos }));
  };

  const launch = (scenario) => post('/api/attack', { scenario });

  return { connected, sim, log, setToggle, launch };
}

export default function App() {
  const { connected, sim, log, setToggle, launch } = useSimulator();
  const [error, setError] = useState(null);
  const [inspected, setInspected] = useState(null);

  const guard = (fn) => async (...args) => {
    setError(null);
    try {
      await fn(...args);
    } catch (e) {
      setError(e.message);
    }
  };

  const running = new Set(
    sim.campaigns.filter((c) => c.status === 'running').map((c) => c.scenario),
  );

  return (
    <div className="app-container">
      <Header
        connected={connected}
        background={sim.background}
        chaos={sim.chaos}
        onToggle={guard(setToggle)}
      />
      {error && <div className="error-banner">{error}</div>}
      <main className="main-content">
        <AttackLauncher
          scenarios={sim.scenarios}
          running={running}
          disabled={!connected}
          onLaunch={guard(launch)}
        />
        <div className="main-right">
          <StatsStrip stats={sim.stats} />
          <CampaignsPanel campaigns={sim.campaigns} />
          <LiveLog entries={log} onSelect={setInspected} />
        </div>
      </main>
      <EventInspectorModal entry={inspected} onClose={() => setInspected(null)} />
    </div>
  );
}
