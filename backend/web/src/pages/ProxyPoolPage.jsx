import React, { useState } from "react";
import { Edit3, Plus, RefreshCw, Shuffle, Trash2, X } from "lucide-react";
import { Badge, DataTable, Panel, SelectAllCheckbox } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api } from "../lib/api.js";

export default function ProxyPoolPage() {
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState(null);
  const [batch, setBatch] = useState(null);
  const [batchError, setBatchError] = useState("");
  const [message, setMessage] = useState("");
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [batchAction, setBatchAction] = useState("");
  const { data, loading, error } = useQuery(`proxies-${refresh}`, () => api("/proxies"));
  const blank = { name: "", scheme: "http", host: "127.0.0.1", port: 8080, username: "", password: "", is_enabled: true };
  async function save(event) {
    event.preventDefault();
    try {
      await api(`/proxies${editing.id ? `/${editing.id}` : ""}`, { method: editing.id ? "PUT" : "POST", body: JSON.stringify(editing) });
      setEditing(null); setMessage("Proxy node saved"); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`Save failed: ${error.message}`); }
  }
  async function test(id) { setMessage("Testing proxy..."); try { const result = await api(`/proxies/${id}/test`, { method: "POST", body: "{}" }); setMessage(`Proxy is available; latency ${result.latency_ms} ms`); } catch (error) { setMessage(error.message); } setRefresh((x) => x + 1); }
  async function testAll() { setMessage("Testing all enabled proxies..."); try { const result = await api("/proxies/test-all", { method: "POST", body: "{}" }); setMessage(`Validation complete: ${result.healthy} healthy / ${result.dead} unavailable`); } catch (error) { setMessage(error.message); } setRefresh((x) => x + 1); }
  async function testSelected() {
    if (!selectedIDs.length) return;
    setBatchAction("test"); setMessage(`Testing ${selectedIDs.length} selected proxy node(s)...`);
    try {
      const result = await api("/proxies/batch/test", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) });
      setMessage(`Validation complete: ${result.healthy} healthy / ${result.dead} unavailable`); setSelectedIDs([]);
    } catch (error) { setMessage(`Batch validation failed: ${error.message}`); }
    finally { setBatchAction(""); setRefresh((x) => x + 1); }
  }
  async function removeSelected() {
    if (!selectedIDs.length || !window.confirm(`Delete ${selectedIDs.length} selected proxy node(s)?`)) return;
    setBatchAction("delete");
    try {
      const result = await api("/proxies/batch/delete", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) });
      setMessage(`Deleted ${result.deleted} proxy node(s)`); setSelectedIDs([]); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`Batch deletion failed: ${error.message}`); }
    finally { setBatchAction(""); }
  }
  async function importBatch(event) {
    event.preventDefault();
    setBatchError("");
    try {
      const proxies = batch.split("\n").map((line) => line.trim()).filter(Boolean).map((line, index) => {
        let value; try { value = new URL(line); } catch { throw new Error(`Line ${index + 1} is not a valid URL`); }
        const scheme = value.protocol.replace(":", "");
        if (!["http", "https", "socks5"].includes(scheme) || !value.hostname || !value.port) throw new Error(`Line ${index + 1} is missing a supported scheme, host, or port`);
        return { name: `proxy-${String(index + 1).padStart(3, "0")}`, scheme, host: value.hostname, port: Number(value.port), username: decodeURIComponent(value.username), password: decodeURIComponent(value.password), is_enabled: true };
      });
      if (!proxies.length) throw new Error("Enter at least one proxy node");
      const result = await api("/proxies/batch", { method: "POST", body: JSON.stringify({ proxies }) });
      const detail = result.errors?.length ? ` Errors: ${result.errors.map((x) => `line ${x.index}: ${x.error}`).join("; ")}` : "";
      setBatch(null); setMessage(`Import complete: ${result.created} added / ${result.skipped} skipped.${detail} Validate the imported nodes before use.`); setRefresh((x) => x + 1);
    } catch (error) { setBatchError(`${error.message}. Example: http://127.0.0.1:8080 or socks5://user:pass@127.0.0.1:1080`); }
  }
  async function remove(id) {
    if (!window.confirm("Confirm deletion of the proxy node?")) return;
    try { await api(`/proxies/${id}`, { method: "DELETE" }); setMessage("Proxy node deleted"); setSelectedIDs((current) => current.filter((value) => value !== id)); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`Delete failed: ${error.message}`); }
  }
  const proxies = data?.proxies || [];
  const visibleIDs = proxies.map((item) => item.id);
  const rows = proxies.map((item) => [<input key="select" className="row-check" type="checkbox" aria-label={`Select ${item.name}`} checked={selectedIDs.includes(item.id)} onChange={() => setSelectedIDs((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} />, item.name, item.scheme.toUpperCase(), `${item.host}:${item.port}`, item.username ? <Badge key="auth" tone="warn">Credentials configured</Badge> : "No credentials", <Badge key="status" tone={item.status === "healthy" ? "ok" : item.status === "dead" ? "danger" : "muted"}>{item.status}</Badge>, item.latency_ms ? `${item.latency_ms} ms` : "-", <div className="row-actions" key="actions"><button className="ghost-button compact" onClick={() => test(item.id)}>Test</button><button className="icon-button" title="Edit" onClick={() => setEditing({ ...item, password: "" })}><Edit3 size={14} /></button><button className="icon-button danger" title="Delete" onClick={() => remove(item.id)}><Trash2 size={14} /></button></div>]);
  return <div className="stack"><Panel title="Proxy pool" icon={<Shuffle size={17} />} action={<div className="row-actions"><button className="ghost-button" onClick={testAll}><RefreshCw size={14} />Test all</button><button className="ghost-button" onClick={() => { setBatch("http://127.0.0.1:8080"); setBatchError(""); }}><Plus size={14} />Bulk import</button><button className="primary-button" onClick={() => setEditing({ ...blank })}><Plus size={15} />Add proxy</button></div>}>
    <div className="proxy-summary"><div><span>VERIFIED ROUTING</span><strong>{(data?.proxies || []).filter((x) => x.is_enabled && x.status === "healthy").length}</strong></div><p>ONLY HEALTHY NODES // ROUND ROBIN // HTTP / HTTPS / SOCKS5</p></div>
    {error && <div className="error-box">Failed to load: {error}</div>}
    {message && <div className="hint">{message}</div>}
    <div className="task-toolbar"><div className="row-actions task-batch-actions"><button className="ghost-button" disabled={!selectedIDs.length || Boolean(batchAction)} onClick={testSelected}>{batchAction === "test" ? "Testing..." : "Test selected"}</button><button className="ghost-button danger" disabled={!selectedIDs.length || Boolean(batchAction)} onClick={removeSelected}>{batchAction === "delete" ? "Removing..." : "Delete selected"}</button></div></div>
    <DataTable storageKey="proxy-pool" loading={loading} columns={["Selection", "Node", "Type", "Address", "Credentials", "Status", "Latency", "Actions"]} rows={rows} headerCells={{ 0: <SelectAllCheckbox ids={visibleIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="proxy nodes" /> }} selectionColumn empty="No proxy nodes are configured; scan requests will connect directly." />
  </Panel>{editing && <div className="modal-backdrop"><form className="library-editor proxy-editor" autoComplete="off" onSubmit={save}><div className="editor-head"><div><span className="eyebrow">Egress node</span><h3>{editing.id ? "Edit proxy" : "Add proxy"}</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close" onClick={() => setEditing(null)}><X size={16} /></button></div><div className="editor-grid"><label>Node name<input name="proxy-name" required value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></label><label>Proxy type<select name="proxy-scheme" value={editing.scheme} onChange={(e) => setEditing({ ...editing, scheme: e.target.value })}>{["http", "https", "socks5"].map((x) => <option key={x}>{x.toUpperCase()}</option>)}</select></label><label>Host<input name="proxy-host" required value={editing.host} onChange={(e) => setEditing({ ...editing, host: e.target.value })} /></label><label>Port<input name="proxy-port" type="number" min="1" max="65535" required value={editing.port} onChange={(e) => setEditing({ ...editing, port: Number(e.target.value) })} /></label><label>Username (optional)<input name="proxy-auth-user" autoComplete="off" value={editing.username || ""} onChange={(e) => setEditing({ ...editing, username: e.target.value })} /></label><label>Password (optional)<input name="proxy-auth-secret" type="password" autoComplete="new-password" value={editing.password || ""} placeholder={editing.id ? "Leave blank to keep the saved password" : ""} onChange={(e) => setEditing({ ...editing, password: e.target.value })} /></label></div><label className="check-line"><input name="proxy-enabled" type="checkbox" checked={editing.is_enabled} onChange={(e) => setEditing({ ...editing, is_enabled: e.target.checked })} />Enable this node after it passes validation</label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditing(null)}>Cancel</button><button className="primary-button">Save node</button></div></form></div>}{batch !== null && <div className="modal-backdrop"><form className="library-editor" onSubmit={importBatch}><div className="editor-head"><div><span className="eyebrow">Bulk import</span><h3>Import proxy nodes</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close" onClick={() => setBatch(null)}><X size={16} /></button></div><label>One proxy URL per line<textarea name="proxy-batch" rows="14" required value={batch} onChange={(e) => setBatch(e.target.value)} placeholder={"http://host:port\nhttp://user:pass@host:port\nsocks5://user:pass@host:port"} /></label>{batchError && <div className="error-box">{batchError}</div>}<div className="hint">Supports HTTP, HTTPS, and SOCKS5, up to 1,000 entries. Imported nodes are not used until they pass validation.</div><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setBatch(null)}>Cancel</button><button className="primary-button">Import nodes</button></div></form></div>}</div>;
}
