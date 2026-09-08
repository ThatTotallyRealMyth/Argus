import React, { useState } from "react";
import { Activity } from "lucide-react";
import NetworkCanvas from "../components/NetworkCanvas.jsx";
import { BRAND } from "../lib/constants.js";

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const text = await res.text();
      let data = {};
      if (text) {
        try { data = JSON.parse(text); } catch { data = {}; }
      }
      if (!res.ok) throw new Error(data.error || "Login failed");
      onLogin(data.token, data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-screen">
      <div className="scan-overlay" aria-hidden="true" />
      <div className="login-coordinates">NODE 31.2304 N / 121.4737 E</div>
      <section className="login-intel">
        <NetworkCanvas />
        <div className="login-brandline"><div className="brand-mark large">{BRAND.mark}</div><span>ARGUS // RESEARCH NODE</span></div>
        <div className="login-heading">
          <span className="eyebrow cyber"><Activity size={14} /> Network intelligence active</span>
          <h1>ARGUS</h1>
          <p>{BRAND.subtitle}</p>
        </div>
        <div className="login-radar" aria-hidden="true">
          <span className="radar-ring r1" /><span className="radar-ring r2" /><span className="radar-ring r3" />
          <i className="radar-node n1" /><i className="radar-node n2" /><i className="radar-node n3" /><i className="radar-node n4" />
          <b>ARGUS_NODE_01</b>
        </div>
        <div className="login-stream" aria-hidden="true"><span>19.873.44.102</span><span>443/TCP</span><span>TLS_1.3</span><span>SIGNAL +82</span></div>
      </section>
      <section className="access-panel">
        <div className="access-status"><span className="status-dot" /> ENCRYPTED CHANNEL <b>01</b></div>
        <form className="login-card" onSubmit={submit}>
        <div className="access-head"><span>AUTHORIZATION REQUIRED</span><strong>Operator sign-in</strong></div>
          <label htmlFor="username">
            Username / USER ID
            <input id="username" name="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </label>
          <label htmlFor="password">
            Password / ACCESS KEY
            <input id="password" name="password" autoComplete="current-password" value={password} type="password" onChange={(e) => setPassword(e.target.value)} />
          </label>
          {error && <div className="error-box">{error}</div>}
          <button className="primary-button" disabled={loading}><span>{loading ? "Signing in..." : "Sign in"}</span><strong>ENTER // 01</strong></button>
          <div className="access-foot"><span>256-BIT CHANNEL</span><span>MONITORED NODE</span></div>
        </form>
      </section>
    </div>
  );
}
