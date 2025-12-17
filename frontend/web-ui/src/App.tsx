import { useEffect, useState } from "react";
import { getStatus, triggerConnect, triggerDisconnect, type Status } from "./api";
import "./styles/app.css";

// Simple Icons
const IconPower = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg>
);
const IconRefresh = ({ spin }: { spin?: boolean }) => (
  <svg className={spin ? "spin" : ""} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M23 4v6h-6"></path><path d="M1 20v-6h6"></path><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
);
const IconShieldCheck = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
);
const IconShieldOff = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"></path><path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
);

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
    <div className="app-container">
      <div className="glass-panel">
        <header className="header">
          <div className="logo-area">
            <div className={`status-icon ${connected ? "on" : "off"}`}>
              {connected ? <IconShieldCheck /> : <IconShieldOff />}
            </div>
            <div>
              <h1>VPN Control</h1>
              <p className="subtitle">Secure Tunnel Interface</p>
            </div>
          </div>
          <div className={`badge ${connected ? "badge-green" : "badge-red"}`}>
            <span className="dot"></span>
            {connected ? "Active" : "Inactive"}
          </div>
        </header>

        <div className="card-content">
          <div className="info-grid">
            <div className="info-item">
              <span className="label">Relay Host</span>
              <span className="value">{status ? status.relay_host : "—"}</span>
            </div>
            <div className="info-item">
              <span className="label">Port</span>
              <span className="value">{status ? status.relay_port : "—"}</span>
            </div>
            <div className="info-item full-width">
              <span className="label">DNS Query</span>
              <span className="value mono">{status ? status.dns_query : "—"}</span>
            </div>
          </div>

          {status?.error && (
            <div className="alert">
              <strong>Error:</strong> {status.error}
            </div>
          )}
        </div>

        <div className="actions">
          {!connected ? (
            <button 
              className="btn btn-primary" 
              disabled={loading} 
              onClick={() => act(triggerConnect)}
            >
              <IconPower />
              {loading ? "Connecting..." : "Connect VPN"}
            </button>
          ) : (
            <button 
              className="btn btn-danger" 
              disabled={loading} 
              onClick={() => act(triggerDisconnect)}
            >
              <IconPower />
              Disconnect
            </button>
          )}
          
          <button className="btn btn-secondary icon-only" disabled={loading} onClick={refresh} title="Refresh Status">
            <IconRefresh spin={loading} />
          </button>
        </div>
      </div>
      
      <footer className="footer">
        <p>VPN Simple Client v0.1</p>
      </footer>
    </div>
  );
}