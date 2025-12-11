import { useEffect, useState } from "react";
import { getStatus, triggerConnect, triggerDisconnect } from "./api";
import "./styles/app.css";

type Status = { edgeConnected: boolean; clients: number };

export default function App() {
  const [status, setStatus] = useState<Status>({ edgeConnected: false, clients: 0 });
  const [loading, setLoading] = useState(false);
  const refresh = async () => {
    try {
        setStatus(await getStatus());
    } catch (_) {}
  };
  useEffect(() => { refresh(); const id = setInterval(refresh, 3000); return () => clearInterval(id); }, []);
  const act = async (fn: () => Promise<any>) => {
    setLoading(true);
    try { await fn(); await refresh(); } finally { setLoading(false); }
  };
  return (
    <div className="app">
      <h1>VPN Control</h1>
      <div className="card">
        <div>Edge connected: {status.edgeConnected ? "yes" : "no"}</div>
        <div>Clients: {status.clients}</div>
      </div>
      <div className="actions">
        <button disabled={loading} onClick={() => act(triggerConnect)}>Connect edge</button>
        <button disabled={loading} onClick={() => act(triggerDisconnect)}>Disconnect edge</button>
        <button disabled={loading} onClick={refresh}>Refresh</button>
      </div>
    </div>
  );
}
