import { useEffect, useState } from "react";
import { getStatus, triggerConnect, triggerDisconnect, type Status } from "./api";
import "./styles/app.css";

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    try {
      const s = await getStatus();
      setStatus(s);
    } catch (e) {
      setStatus((prev) => prev ?? { connected: false, relay_host: "-", relay_port: 0, dns_query: "-", error: String(e) });
    }
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, []);

  const act = async (fn: () => Promise<any>) => {
    setLoading(true);
    try {
      await fn();
    } finally {
      await refresh();
      setLoading(false);
    }
  };

  const connected = status?.connected ?? false;

  return (
    <div className="app">
      <header className="header">
        <h1>VPN Control</h1>
        <span className={`badge ${connected ? "badge-green" : "badge-red"}`}>
          {connected ? "Connected" : "Disconnected"}
        </span>
      </header>

      <div className="card">
        <div className="row">
          <span className="label">Relay</span>
          <span className="value">
            {status ? `${status.relay_host}:${status.relay_port}` : "—"}
          </span>
        </div>
        <div className="row">
          <span className="label">DNS query</span>
          <span className="value">{status ? status.dns_query : "—"}</span>
        </div>
        {status?.error ? (
          <div className="alert">
            <strong>Error:</strong> {status.error}
          </div>
        ) : null}
      </div>

      <div className="actions">
        <button disabled={loading} onClick={() => act(triggerConnect)}>
          {loading ? "Working…" : "Connect"}
        </button>
        <button disabled={loading} onClick={() => act(triggerDisconnect)}>
          Disconnect
        </button>
        <button disabled={loading} onClick={refresh}>
          Refresh
        </button>
      </div>
    </div>
  );
}