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
      setEditing(null); setMessage("代理节点已保存"); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`保存失败：${error.message}`); }
  }
  async function test(id) { setMessage("正在测试出口..."); try { const result = await api(`/proxies/${id}/test`, { method: "POST", body: "{}" }); setMessage(`节点可用，延迟 ${result.latency_ms}ms`); } catch (error) { setMessage(error.message); } setRefresh((x) => x + 1); }
  async function testAll() { setMessage("正在批量验证所有启用节点..."); try { const result = await api("/proxies/test-all", { method: "POST", body: "{}" }); setMessage(`验证完成：${result.healthy} 可用 / ${result.dead} 失效`); } catch (error) { setMessage(error.message); } setRefresh((x) => x + 1); }
  async function testSelected() {
    if (!selectedIDs.length) return;
    setBatchAction("test"); setMessage(`正在验证选中的 ${selectedIDs.length} 个节点...`);
    try {
      const result = await api("/proxies/batch/test", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) });
      setMessage(`批量验证完成：${result.healthy} 可用 / ${result.dead} 失效`); setSelectedIDs([]);
    } catch (error) { setMessage(`批量验证失败：${error.message}`); }
    finally { setBatchAction(""); setRefresh((x) => x + 1); }
  }
  async function removeSelected() {
    if (!selectedIDs.length || !window.confirm(`确认删除选中的 ${selectedIDs.length} 个代理节点？`)) return;
    setBatchAction("delete");
    try {
      const result = await api("/proxies/batch/delete", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) });
      setMessage(`已删除 ${result.deleted} 个代理节点`); setSelectedIDs([]); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`批量删除失败：${error.message}`); }
    finally { setBatchAction(""); }
  }
  async function importBatch(event) {
    event.preventDefault();
    setBatchError("");
    try {
      const proxies = batch.split("\n").map((line) => line.trim()).filter(Boolean).map((line, index) => {
        let value; try { value = new URL(line); } catch { throw new Error(`第 ${index + 1} 行不是合法 URL`); }
        const scheme = value.protocol.replace(":", "");
        if (!["http", "https", "socks5"].includes(scheme) || !value.hostname || !value.port) throw new Error(`第 ${index + 1} 行缺少受支持的协议、主机或端口`);
        return { name: `proxy-${String(index + 1).padStart(3, "0")}`, scheme, host: value.hostname, port: Number(value.port), username: decodeURIComponent(value.username), password: decodeURIComponent(value.password), is_enabled: true };
      });
      if (!proxies.length) throw new Error("至少输入一个代理节点");
      const result = await api("/proxies/batch", { method: "POST", body: JSON.stringify({ proxies }) });
      const detail = result.errors?.length ? ` 错误：${result.errors.map((x) => `第 ${x.index} 条 ${x.error}`).join("；")}` : "";
      setBatch(null); setMessage(`导入完成：${result.created} 新增 / ${result.skipped} 跳过。${detail} 请执行批量验证后再使用。`); setRefresh((x) => x + 1);
    } catch (error) { setBatchError(`${error.message}。示例：http://127.0.0.1:8080 或 socks5://user:pass@127.0.0.1:1080`); }
  }
  async function remove(id) {
    if (!window.confirm("确认删除该代理节点？")) return;
    try { await api(`/proxies/${id}`, { method: "DELETE" }); setMessage("代理节点已删除"); setSelectedIDs((current) => current.filter((value) => value !== id)); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`删除失败：${error.message}`); }
  }
  const proxies = data?.proxies || [];
  const visibleIDs = proxies.map((item) => item.id);
  const rows = proxies.map((item) => [<input key="select" className="row-check" type="checkbox" aria-label={`选择 ${item.name}`} checked={selectedIDs.includes(item.id)} onChange={() => setSelectedIDs((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} />, item.name, item.scheme.toUpperCase(), `${item.host}:${item.port}`, item.username ? <Badge key="auth" tone="warn">认证</Badge> : "无认证", <Badge key="status" tone={item.status === "healthy" ? "ok" : item.status === "dead" ? "danger" : "muted"}>{item.status}</Badge>, item.latency_ms ? `${item.latency_ms} ms` : "-", <div className="row-actions" key="actions"><button className="ghost-button compact" onClick={() => test(item.id)}>验证</button><button className="icon-button" title="编辑" onClick={() => setEditing({ ...item, password: "" })}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" onClick={() => remove(item.id)}><Trash2 size={14} /></button></div>]);
  return <div className="stack"><Panel title="代理出口池" icon={<Shuffle size={17} />} action={<div className="row-actions"><button className="ghost-button" onClick={testAll}><RefreshCw size={14} />验证全部</button><button className="ghost-button" onClick={() => { setBatch("http://127.0.0.1:8080"); setBatchError(""); }}><Plus size={14} />批量导入</button><button className="primary-button" onClick={() => setEditing({ ...blank })}><Plus size={15} />新增节点</button></div>}>
    <div className="proxy-summary"><div><span>VERIFIED ROUTING</span><strong>{(data?.proxies || []).filter((x) => x.is_enabled && x.status === "healthy").length}</strong></div><p>ONLY HEALTHY NODES // ROUND ROBIN // HTTP / HTTPS / SOCKS5</p></div>
    {error && <div className="error-box">加载失败：{error}</div>}
    {message && <div className="hint">{message}</div>}
    <div className="task-toolbar"><div className="row-actions task-batch-actions"><button className="ghost-button" disabled={!selectedIDs.length || Boolean(batchAction)} onClick={testSelected}>{batchAction === "test" ? "验证中..." : "批量验证"}</button><button className="ghost-button danger" disabled={!selectedIDs.length || Boolean(batchAction)} onClick={removeSelected}>{batchAction === "delete" ? "删除中..." : "批量删除"}</button></div></div>
    <DataTable storageKey="proxy-pool" loading={loading} columns={["选择", "节点", "类型", "地址", "认证", "状态", "延迟", "操作"]} rows={rows} headerCells={{ 0: <SelectAllCheckbox ids={visibleIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="全部代理节点" /> }} selectionColumn empty="暂无代理节点，扫描请求将直连" />
  </Panel>{editing && <div className="modal-backdrop"><form className="library-editor proxy-editor" autoComplete="off" onSubmit={save}><div className="editor-head"><div><span className="eyebrow">Egress node</span><h3>{editing.id ? "编辑代理" : "新增代理"}</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭" onClick={() => setEditing(null)}><X size={16} /></button></div><div className="editor-grid"><label>节点名称<input name="proxy-name" required value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></label><label>代理类型<select name="proxy-scheme" value={editing.scheme} onChange={(e) => setEditing({ ...editing, scheme: e.target.value })}>{["http", "https", "socks5"].map((x) => <option key={x}>{x.toUpperCase()}</option>)}</select></label><label>主机<input name="proxy-host" required value={editing.host} onChange={(e) => setEditing({ ...editing, host: e.target.value })} /></label><label>端口<input name="proxy-port" type="number" min="1" max="65535" required value={editing.port} onChange={(e) => setEditing({ ...editing, port: Number(e.target.value) })} /></label><label>用户名（可选）<input name="proxy-auth-user" autoComplete="off" value={editing.username || ""} onChange={(e) => setEditing({ ...editing, username: e.target.value })} /></label><label>密码（可选）<input name="proxy-auth-secret" type="password" autoComplete="new-password" value={editing.password || ""} placeholder={editing.id ? "留空则保持原密码" : ""} onChange={(e) => setEditing({ ...editing, password: e.target.value })} /></label></div><label className="check-line"><input name="proxy-enabled" type="checkbox" checked={editing.is_enabled} onChange={(e) => setEditing({ ...editing, is_enabled: e.target.checked })} />启用此节点（仍需验证成功后才会进入轮询）</label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditing(null)}>取消</button><button className="primary-button">保存节点</button></div></form></div>}{batch !== null && <div className="modal-backdrop"><form className="library-editor" onSubmit={importBatch}><div className="editor-head"><div><span className="eyebrow">Bulk import</span><h3>批量导入代理</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭" onClick={() => setBatch(null)}><X size={16} /></button></div><label>每行一个代理 URL<textarea name="proxy-batch" rows="14" required value={batch} onChange={(e) => setBatch(e.target.value)} placeholder={"http://host:port\nhttp://user:pass@host:port\nsocks5://user:pass@host:port"} /></label>{batchError && <div className="error-box">{batchError}</div>}<div className="hint">支持 HTTP、HTTPS、SOCKS5，最多 1000 条。导入后状态为 unknown，批量验证通过前不会参与扫描。</div><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setBatch(null)}>取消</button><button className="primary-button">导入节点</button></div></form></div>}</div>;
}
