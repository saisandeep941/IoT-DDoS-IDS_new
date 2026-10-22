import { useEffect, useState } from "react";
import axios from "axios";
import { getFlowEndpointLabel, requestFlowSnapshot } from "./flowTelemetry.js";
import "./LiveCapturePanel.css";

const API = `${window.location.protocol}//${window.location.hostname}:8000/api/capture`;
export default function LiveCapturePanel() {
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("");
  const [status, setStatus] = useState({ state: "stopped" });
  const [data, setData] = useState({ packets: 0, bytes: 0, protocols: {}, endpoints: {}, recent: [] });
  const [csrf, setCsrf] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [flowState, setFlowState] = useState("stopped");
  const [flows, setFlows] = useState([]);
  const [flowError, setFlowError] = useState("");
  useEffect(() => {
    let alive = true;
    Promise.all([axios.get(`${API}/csrf`), axios.get(`${API}/interfaces`)]).then(([c, i]) => {
      if (!alive) return; setCsrf(c.data.token); setInterfaces(i.data.interfaces || []); setIface(i.data.interfaces?.[0] || "");
      return axios.get(`${API}/session`, { headers: { "X-Capture-Token": c.data.token } });
    }).then(session => {
      if (alive && session?.data?.token) setToken(session.data.token);
    }).catch(e => alive && setError(e.response?.data?.detail || "Local capture API unavailable"));
    return () => { alive = false; };
  }, []);
  useEffect(() => {
    const poll = async () => {
      try {
        const s = await axios.get(`${API}/status`); setStatus(s.data);
        if (s.data.state === "running" && token) {
          const headers = { "X-Capture-Token": token };
          setData((await axios.get(`${API}/telemetry`, { headers })).data);
        }
      } catch (e) { setError(e.response?.data?.detail || "Unable to read capture status"); }
    };
    poll(); const id = setInterval(poll, 1500); return () => clearInterval(id);
  }, [token]);
  useEffect(() => {
    let active = true;
    if (status.state !== "running" || !token) {
      return () => { active = false; };
    }

    let id;
    const pollFlows = async () => {
      try {
        const result = await requestFlowSnapshot(axios, `${API}/flows`, token);
        if (!active) return;
        if (result.stopped) {
          clearInterval(id);
          setFlows([]);
          setFlowState("stopped");
          return;
        }
        setFlows(result.flows);
        setFlowState(result.flows.length ? "ready" : "empty");
      } catch (e) {
        if (!active) return;
        setFlows([]);
        setFlowError(e.response?.data?.detail || "Unable to read experimental flow telemetry");
        setFlowState("error");
      }
    };
    id = setInterval(pollFlows, 1500);
    pollFlows();
    return () => { active = false; clearInterval(id); };
  }, [status.state, token]);
  async function start() {
    setError("");
    try {
      const r = await axios.post(`${API}/start`, { interface: iface }, { headers: { "X-Capture-Token": csrf } });
      setFlows([]);
      setFlowError("");
      setFlowState("loading");
      setToken(r.data.token);
      setStatus(r.data);
    }
    catch (e) { setError(e.response?.data?.detail || "Capture could not start"); }
  }
  async function stop() {
    setError("");
    try { const r = await axios.post(`${API}/stop`, {}, { headers: token ? { "X-Capture-Token": token } : {} }); setStatus(r.data); setToken(""); setFlows([]); setFlowState("stopped"); }
    catch (e) { setError(e.response?.data?.detail || "Capture could not stop"); }
  }
  const running = status.state === "running";
  const stoppable = running || status.state === "error";
  const startable = status.state === "stopped";
  const visibleFlowState = !running || !token
    ? "stopped"
    : flowState === "stopped"
      ? "loading"
      : flowState;
  return <section className="live-capture-panel">
    <header><div><h2>Live Capture Telemetry</h2><p>Observational telemetry only. This panel does not classify traffic or produce Random Forest V2 predictions.</p></div><span className={`capture-state ${status.state}`}>{status.state}</span></header>
    <div className="capture-controls"><label>Network interface<select value={iface} onChange={e => setIface(e.target.value)} disabled={!startable}><option value="">Choose an available interface</option>{interfaces.map(x => <option key={x} value={x}>{x}</option>)}</select></label><button onClick={start} disabled={!startable || !iface || !csrf}>Start capture</button><button onClick={stop} disabled={!stoppable || !token}>Stop capture</button></div>
    {(error || status.error) && <p className="capture-error">{error || status.error}</p>}
    <div className="capture-metrics"><div><b>{data.packets}</b><span>Packets</span></div><div><b>{data.bytes}</b><span>Observed bytes</span></div><div><b>{data.dropped}</b><span>Dropped capture batches</span></div></div>
    <h3>Protocol counts</h3><p>{Object.entries(data.protocols || {}).map(([k,v]) => `${k}: ${v}`).join(" · ") || "No packet metadata yet"}</p>
    <h3>Recent packet metadata</h3><div className="capture-table-wrap"><table><thead><tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Bytes</th></tr></thead><tbody>{(data.recent || []).slice(-20).reverse().map((p,i)=><tr key={`${p.timestamp}-${i}`}><td>{new Date(p.timestamp).toLocaleTimeString()}</td><td>{p.protocol}</td><td>{p.src || "—"}</td><td>{p.dst || "—"}</td><td>{p.bytes}</td></tr>)}</tbody></table></div>
    <section className="flow-telemetry" aria-labelledby="flow-telemetry-title">
      <div className="flow-telemetry-heading"><div><h3 id="flow-telemetry-title">Experimental flow telemetry</h3><p>Observed flow summaries only. These are not attack classifications or V2 predictions.</p></div><span className={`flow-state ${visibleFlowState}`}>{visibleFlowState}</span></div>
      {visibleFlowState === "loading" && <p role="status">Loading flow summaries…</p>}
      {visibleFlowState === "stopped" && <p role="status">Capture is stopped. Flow summaries are unavailable.</p>}
      {visibleFlowState === "empty" && <p role="status">No flow summaries have been observed in this capture session yet.</p>}
      {visibleFlowState === "error" && <p className="capture-error" role="alert">{flowError}</p>}
      {running && token && flows.length > 0 && <div className="capture-table-wrap flow-table-wrap"><table><thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes</th><th>Duration (s)</th><th>Forward</th><th>Backward</th></tr></thead><tbody>{flows.map(flow => <tr key={flow.flow_id}><td>{flow.protocol || "—"}</td><td>{getFlowEndpointLabel(flow.forward_src)}</td><td>{getFlowEndpointLabel(flow.forward_dst)}</td><td>{flow.packets ?? "—"}</td><td>{flow.bytes ?? "—"}</td><td>{typeof flow.duration_seconds === "number" ? flow.duration_seconds.toFixed(3) : "—"}</td><td>{flow.forward?.packets ?? "—"}</td><td>{flow.backward?.packets ?? "—"}</td></tr>)}</tbody></table></div>}
    </section>
    <small>Payloads are not displayed or persisted. Metadata remains in bounded memory for this backend session.</small>
  </section>;
}
