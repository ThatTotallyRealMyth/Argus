import React, { useState } from "react";
import { Download, Play, Plus, RefreshCw, RotateCcw, TerminalSquare, Trash2, X } from "lucide-react";
import { Badge, DataTable, Modal, Pager, Panel, SelectAllCheckbox, Tabs } from "../components/ui.jsx";
import AdvancedSearch from "../components/AdvancedSearch.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate } from "../lib/api.js";
import { filtersToExpression } from "../lib/searchSyntax.js";

export default function TasksPage({ setPage: navigate }) {
  const [page, setPageNumber] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [status, setStatus] = useState("all");
  const [search, setSearch] = useState("");
  const [columnFilters, setColumnFilters] = useState({});
  const [editor, setEditor] = useState(null);
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [sortState, setSortState] = useState({ index: 7, direction: "desc" });
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const query = new URLSearchParams({ page, page_size: 20 });
  if (status !== "all") query.set("status", status);
  const combinedSearch = [search, filtersToExpression(columnFilters)].filter(Boolean).join(" && ");
  if (combinedSearch) query.set("q", combinedSearch);
  query.set("sort_by", ["", "name", "target", "", "", "status", "progress", "created_at", ""][sortState.index] || "created_at");
  query.set("sort_order", sortState.direction);
  const { data, loading, error } = useQuery(`tasks-${page}-${status}-${combinedSearch}-${refresh}-${sortState.index}-${sortState.direction}`, () => api(`/tasks?${query}`));
  const { data: policyData } = useQuery("task-policies", () => api("/policies?page=1&page_size=100"));
  const { data: scopeData } = useQuery("task-scan-scopes", () => api("/scan-scopes"));
  const featureGroups = [
    { title: "域名发现", index: "01", items: [["enable_domain_brute", "域名爆破"], ["smart_dict_gen", "智能字典"], ["enable_domain_plugins", "测绘数据源"], ["enable_arl_history", "历史资产"]] },
    { title: "网络识别", index: "02", items: [["enable_c_segment", "C 段扫描"], ["enable_service_detect", "服务识别"], ["enable_os_detect", "操作系统"], ["enable_ssl_cert", "SSL 证书"], ["skip_cdn", "跳过 CDN"]] },
    { title: "站点与风险", index: "03", items: [["enable_site_detect", "站点识别"], ["enable_search_engine", "搜索引擎"], ["enable_crawler", "站点爬虫"], ["enable_screenshot", "站点截图"], ["enable_file_leak", "文件泄露"], ["enable_host_collision", "Host 碰撞"], ["enable_poc_detection", "PoC 检测"], ["enable_wih", "WIH"], ["enable_passive_scan", "被动扫描"]] },
  ];
  const pluginOptions = ["crtsh", "certspotter", "alienvault", "hackertarget", "virustotal", "fofa", "hunter", "quake", "zoomeye", "custom_space_api"];

  function blankTask() {
    return {
      name: "", target: "", policy_id: "", scope_id: "", start_now: true, domain_brute_type: "big", port_scan_type: "top100", crawler_depth: 3, crawler_pages: 100,
      domain_plugins: ["crtsh", "hackertarget"],
      flags: { enable_domain_brute: true, smart_dict_gen: true, enable_domain_plugins: true, enable_arl_history: false, enable_c_segment: false, enable_service_detect: true, enable_os_detect: false, enable_ssl_cert: true, skip_cdn: true, enable_site_detect: true, enable_search_engine: false, enable_crawler: true, enable_screenshot: true, enable_file_leak: true, enable_host_collision: false, enable_poc_detection: false, enable_wih: false, enable_passive_scan: false },
    };
  }

  async function createTask(event) {
    event.preventDefault();
    setSaving(true); setMessage("");
    try {
      const hasPolicy = Boolean(editor.policy_id);
      await api("/tasks", { method: "POST", body: JSON.stringify({ name: editor.name, target: editor.target, policy_id: editor.policy_id, scope_id: editor.scope_id, start_now: editor.start_now, options: { ...editor.flags, enable_port_scan: true, domain_brute_type: hasPolicy ? "" : editor.domain_brute_type, port_scan_type: hasPolicy ? "" : editor.port_scan_type, domain_plugins: hasPolicy ? [] : editor.domain_plugins, crawler_depth: Number(editor.crawler_depth), crawler_pages: Number(editor.crawler_pages) } }) });
      setEditor(null); setMessage(editor.start_now ? "任务已创建并进入队列" : "任务已创建，等待手动启动"); setPageNumber(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`创建失败：${error.message}`); } finally { setSaving(false); }
  }

  async function start(id) {
    try { await api(`/tasks/${id}/start`, { method: "POST", body: "{}" }); setMessage("任务已进入队列"); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`启动失败：${error.message}`); }
  }

  async function cancel(id) {
    try { await api(`/tasks/${id}/cancel`, { method: "POST", body: "{}" }); setMessage("任务已取消"); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`取消失败：${error.message}`); }
  }

  async function retry(task) {
    if (!window.confirm("将按原配置创建新任务并进入队列，原任务和结果会保留。确认重新运行？")) return;
    try {
      const result = await api(`/tasks/${task.id}/retry`, { method: "POST", body: "{}" });
      setMessage(`已创建重跑任务：${result.task?.name || task.name}`);
      setPageNumber(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`重新运行失败：${error.message}`); }
  }

  async function remove(id) {
    if (!window.confirm("删除任务将同时删除其关联资产，确认继续？")) return;
    try { await api(`/tasks/${id}`, { method: "DELETE" }); setMessage("任务及关联资产已删除"); setSelectedIDs((current) => current.filter((selectedID) => selectedID !== id)); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`删除失败：${error.message}`); }
  }

  async function batchCancel() {
    if (!selectedIDs.length) return;
    const results = await Promise.allSettled(selectedIDs.map((id) => api(`/tasks/${id}/cancel`, { method: "POST", body: "{}" })));
    const failed = results.filter((item) => item.status === "rejected").length;
    setMessage(failed ? `批量取消完成，${failed} 个失败` : `已取消 ${selectedIDs.length} 个任务`); setSelectedIDs([]); setRefresh((x) => x + 1);
  }

  async function batchDelete() {
    if (!selectedIDs.length || !window.confirm(`删除选中的 ${selectedIDs.length} 个任务及关联资产？`)) return;
    try { const result = await api("/tasks/batch/delete", { method: "POST", body: JSON.stringify({ task_ids: selectedIDs }) }); setMessage(`已删除 ${result.success_count} 个任务`); setSelectedIDs([]); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`批量删除失败：${error.message}`); }
  }

  async function exportTask(task, format) {
    setMessage(`正在生成 ${format.toUpperCase()} 导出...`);
    try {
      const result = await api(`/export/task/${task.id}?format=${format}`);
      const token = localStorage.getItem("eclipse_token");
      const response = await fetch(`/api/v1/export/download?file=${encodeURIComponent(result.filename)}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!response.ok) throw new Error("下载导出文件失败");
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = result.filename; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url); setMessage(`${format.toUpperCase()} 导出完成`);
    } catch (error) { setMessage(`导出失败：${error.message}`); }
  }

  function toggleFlag(key) { setEditor((current) => ({ ...current, flags: { ...current.flags, [key]: !current.flags[key] } })); }
  function togglePlugin(name) { setEditor((current) => ({ ...current, domain_plugins: current.domain_plugins.includes(name) ? current.domain_plugins.filter((item) => item !== name) : [...current.domain_plugins, name] })); }
  function optionSummary(options = {}) {
    const labels = [];
    if (options.enable_domain_brute) labels.push("域名爆破");
    labels.push(options.port_scan_type || "top100");
    if (options.enable_site_detect) labels.push("站点识别");
    if (options.enable_poc_detection) labels.push("PoC");
    if (options.enable_screenshot) labels.push("截图");
    return labels.join(" / ");
  }

  const visibleTaskIDs = (data?.tasks || []).map((task) => task.id);
  const scanScopes = scopeData?.scopes || [];
  const defaultScope = scanScopes.find((scope) => scope.is_default);
  const scopeNames = Object.fromEntries(scanScopes.map((scope) => [scope.id, scope.name]));

  return (
    <div className="stack task-workspace">
      <Panel title="任务列表" icon={<TerminalSquare size={17} />} action={<div className="row-actions"><button className="icon-button" title="刷新" onClick={() => setRefresh((x) => x + 1)}><RefreshCw size={16} /></button><button className="primary-button" onClick={() => { setMessage(""); setEditor(blankTask()); }}><Plus size={15} />新建任务</button></div>}>
        <div className="task-toolbar"><Tabs value={status} setValue={(value) => { setStatus(value); setPageNumber(1); setSelectedIDs([]); }} items={["all", "pending", "queued", "running", "completed", "failed", "cancelled"]} labels={{ all: "全部", pending: "待启动", queued: "排队中", running: "运行中", completed: "已完成", failed: "失败", cancelled: "已取消" }} /><AdvancedSearch compact value={search} fields={["name", "target", "status", "error"]} placeholder="检索任务，例如 target:example.com && !status:failed" onApply={(value) => { setSearch(value); setPageNumber(1); setSelectedIDs([]); }} /><div className="row-actions task-batch-actions"><button className="ghost-button" disabled={!selectedIDs.length} onClick={batchCancel}>批量取消</button><button className="ghost-button danger" disabled={!selectedIDs.length} onClick={batchDelete}>批量删除</button></div></div>
        {error && <div className="error-box">{error}</div>}
        {message && <div className={message.includes("失败") ? "error-box" : "success-box"}>{message}</div>}
        <DataTable
          storageKey="tasks-list"
          loading={loading}
          columns={["选择", "名称", "目标", "授权范围", "配置摘要", "状态", "进度", "创建时间", "操作"]}
          rows={(data?.tasks || []).map((task) => [
            <input key="select" className="row-check" type="checkbox" aria-label={`选择 ${task.name}`} checked={selectedIDs.includes(task.id)} onChange={() => setSelectedIDs((current) => current.includes(task.id) ? current.filter((id) => id !== task.id) : [...current, task.id])} />,
            <button key="name" className="link-button" onClick={() => navigate(`task:${task.id}`)}>{task.name}</button>,
            task.target,
            task.scope_id ? <Badge key="scope" tone="ok">{scopeNames[task.scope_id] || task.scope_id.slice(0, 8)}</Badge> : <Badge key="scope">兼容模式</Badge>,
            optionSummary(task.options),
            <Badge key="status" tone={task.status === "completed" ? "ok" : task.status === "failed" ? "danger" : "warn"}>{task.status}</Badge>,
            `${task.progress || 0}%`,
            formatDate(task.created_at),
            <div className="row-actions" key="actions">
              <button className="icon-button" title="启动" disabled={task.status !== "pending"} onClick={() => start(task.id)}><Play size={15} /></button>
              <button className="icon-button" title="重新运行" disabled={!["completed", "failed", "cancelled"].includes(task.status)} onClick={() => retry(task)}><RotateCcw size={15} /></button>
              <button className="icon-button" title="取消" disabled={!["queued", "running"].includes(task.status)} onClick={() => cancel(task.id)}><X size={15} /></button>
              <button className="icon-button" title="导出 JSON" onClick={() => exportTask(task, "json")}><Download size={15} /></button>
              <button className="icon-button danger" title="删除" onClick={() => remove(task.id)}><Trash2 size={15} /></button>
            </div>,
          ])}
          sortKeys={["", "name", "target", "", "", "status", "progress", "created_at", ""]}
          sortState={sortState}
          onSortChange={(key, direction) => setSortState({ index: ["", "name", "target", "", "", "status", "progress", "created_at", ""].indexOf(key), direction })}
          headerCells={{ 0: <SelectAllCheckbox ids={visibleTaskIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="本页任务" /> }}
          selectionColumn
          filterKeys={["", "name", "target", "", "", "status", "progress", "created_at", ""]}
          filters={columnFilters}
          filterOptions={{ status: ["pending", "queued", "running", "completed", "failed", "cancelled"] }}
          onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [key]: value })); setPageNumber(1); }}
          empty="暂无任务"
        />
        <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPageNumber} />
      </Panel>
      <Modal open={Boolean(editor)}>{editor && <form className="library-editor task-editor" onSubmit={createTask}>
        <div className="editor-head"><div><span className="eyebrow">Recon task profile</span><h3>新建扫描任务</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setEditor(null)}><X size={16} /></button></div>
        <div className="task-editor-body">
          <section className="editor-section"><div className="editor-section-head"><span>00</span><strong>任务目标</strong></div><div className="editor-grid editor-grid-4"><label className="field-span-2">任务名称<input required value={editor.name} onChange={(e) => setEditor({ ...editor, name: e.target.value })} /></label><label>扫描策略<select value={editor.policy_id} onChange={(e) => setEditor({ ...editor, policy_id: e.target.value })}><option value="">使用当前配置</option>{(policyData?.policies || []).map((policy) => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</select></label><label>授权范围<select value={editor.scope_id} onChange={(e) => setEditor({ ...editor, scope_id: e.target.value })}><option value="">{defaultScope ? `默认：${defaultScope.name}` : "兼容模式（未配置默认范围）"}</option>{scanScopes.filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}</select></label><label className="field-span-4">目标<textarea required rows="4" value={editor.target} onChange={(e) => setEditor({ ...editor, target: e.target.value })} placeholder="example.com, 10.0.0.1/24" /></label></div></section>
          <section className="task-strategy-row"><label>域名爆破<select value={editor.domain_brute_type} onChange={(e) => setEditor({ ...editor, domain_brute_type: e.target.value })}><option value="big">大字典</option><option value="test">测试字典</option></select></label><label>端口扫描<select value={editor.port_scan_type} onChange={(e) => setEditor({ ...editor, port_scan_type: e.target.value })}><option value="test">测试端口</option><option value="top100">TOP 100</option><option value="top1000">TOP 1000</option><option value="all">全端口</option></select></label><label>爬虫深度<input type="number" min="1" max="10" value={editor.crawler_depth} onChange={(e) => setEditor({ ...editor, crawler_depth: e.target.value })} /></label><label>最大页面<input type="number" min="1" max="10000" value={editor.crawler_pages} onChange={(e) => setEditor({ ...editor, crawler_pages: e.target.value })} /></label></section>
          <div className="task-feature-grid">{featureGroups.map((group) => <section className="task-feature-group" key={group.title}><div className="editor-section-head"><span>{group.index}</span><strong>{group.title}</strong></div>{group.items.map(([key, label]) => <label className="feature-toggle" key={key}><input type="checkbox" checked={editor.flags[key]} onChange={() => toggleFlag(key)} /><span>{label}</span></label>)}</section>)}</div>
          <section className="editor-section"><div className="editor-section-head"><span>04</span><strong>测绘数据源</strong></div><div className="plugin-grid">{pluginOptions.map((plugin) => <label className="feature-toggle" key={plugin}><input type="checkbox" checked={editor.domain_plugins.includes(plugin)} onChange={() => togglePlugin(plugin)} /><span>{plugin}</span></label>)}</div></section>
        </div>
        <div className="editor-actions task-editor-actions"><label className="feature-toggle start-toggle"><input type="checkbox" checked={editor.start_now} onChange={(e) => setEditor({ ...editor, start_now: e.target.checked })} /><span>创建后立即启动</span></label><button type="button" className="ghost-button" onClick={() => setEditor(null)}>取消</button><button className="primary-button" disabled={saving}>{saving ? "创建中..." : "创建任务"}</button></div>
      </form>}</Modal>
    </div>
  );
}
