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
    { title: "Domain discovery", index: "01", items: [["enable_domain_brute", "Subdomain brute force"], ["smart_dict_gen", "Smart wordlist"], ["enable_domain_plugins", "Intelligence providers"], ["enable_arl_history", "Historical assets"]] },
    { title: "Network discovery", index: "02", items: [["enable_c_segment", "C-class scan"], ["enable_service_detect", "Service detection"], ["enable_os_detect", "Operating-system detection"], ["enable_ssl_cert", "TLS certificates"], ["skip_cdn", "Skip CDN targets"]] },
    { title: "Web and findings", index: "03", items: [["enable_site_detect", "Site detection"], ["enable_search_engine", "Search engine discovery"], ["enable_crawler", "Web crawler"], ["enable_screenshot", "Screenshots"], ["enable_file_leak", "Exposed-file checks"], ["enable_host_collision", "Host-header collision"], ["enable_poc_detection", "PoC validation"], ["enable_wih", "WIH"], ["enable_passive_scan", "Passive scan"]] },
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
      setEditor(null); setMessage(editor.start_now ? "Task created and queued" : "Task created; waiting for manual start"); setPageNumber(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`Creation failed: ${error.message}`); } finally { setSaving(false); }
  }

  async function start(id) {
    try { await api(`/tasks/${id}/start`, { method: "POST", body: "{}" }); setMessage("Task in Queue"); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`Start failed: ${error.message}`); }
  }

  async function cancel(id) {
    try { await api(`/tasks/${id}/cancel`, { method: "POST", body: "{}" }); setMessage("Task canceled"); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`Cancellation failed: ${error.message}`); }
  }

  async function retry(task) {
    if (!window.confirm("Create and queue a new task with the original configuration? The original task and its results will be retained.")) return;
    try {
      const result = await api(`/tasks/${task.id}/retry`, { method: "POST", body: "{}" });
      setMessage(`Rerun task created: ${result.task?.name || task.name}`);
      setPageNumber(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`Rerun failed: ${error.message}`); }
  }

  async function remove(id) {
    if (!window.confirm("Delete this task and all of its associated assets?")) return;
    try { await api(`/tasks/${id}`, { method: "DELETE" }); setMessage("Task and associated assets deleted"); setSelectedIDs((current) => current.filter((selectedID) => selectedID !== id)); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`Delete failed: ${error.message}`); }
  }

  async function batchCancel() {
    if (!selectedIDs.length) return;
    const results = await Promise.allSettled(selectedIDs.map((id) => api(`/tasks/${id}/cancel`, { method: "POST", body: "{}" })));
    const failed = results.filter((item) => item.status === "rejected").length;
    setMessage(failed ? `Batch cancellation completed with ${failed} failure(s)` : `Cancelled ${selectedIDs.length} task(s)`); setSelectedIDs([]); setRefresh((x) => x + 1);
  }

  async function batchDelete() {
    if (!selectedIDs.length || !window.confirm(`Delete Selected ${selectedIDs.length} Tasks and associated assets?`)) return;
    try { const result = await api("/tasks/batch/delete", { method: "POST", body: JSON.stringify({ task_ids: selectedIDs }) }); setMessage(`Deleted ${result.success_count} task(s)`); setSelectedIDs([]); setRefresh((x) => x + 1); }
    catch (error) { setMessage(`Batch deletion failed: ${error.message}`); }
  }

  async function exportTask(task, format) {
    setMessage(`Generating ${format.toUpperCase()} Export...`);
    try {
      const result = await api(`/export/task/${task.id}?format=${format}`);
      const token = localStorage.getItem("eclipse_token");
      const response = await fetch(`/api/v1/export/download?file=${encodeURIComponent(result.filename)}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!response.ok) throw new Error("Failed to download export file");
      const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = result.filename; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url); setMessage(`${format.toUpperCase()} Export complete`);
    } catch (error) { setMessage(`Export failed: ${error.message}`); }
  }

  function toggleFlag(key) { setEditor((current) => ({ ...current, flags: { ...current.flags, [key]: !current.flags[key] } })); }
  function togglePlugin(name) { setEditor((current) => ({ ...current, domain_plugins: current.domain_plugins.includes(name) ? current.domain_plugins.filter((item) => item !== name) : [...current.domain_plugins, name] })); }
  function optionSummary(options = {}) {
    const labels = [];
    if (options.enable_domain_brute) labels.push("Subdomain brute force");
    labels.push(options.port_scan_type || "top100");
    if (options.enable_site_detect) labels.push("Site detection");
    if (options.enable_poc_detection) labels.push("PoC");
    if (options.enable_screenshot) labels.push("Screenshot");
    return labels.join(" / ");
  }

  const visibleTaskIDs = (data?.tasks || []).map((task) => task.id);
  const scanScopes = scopeData?.scopes || [];
  const defaultScope = scanScopes.find((scope) => scope.is_default);
  const scopeNames = Object.fromEntries(scanScopes.map((scope) => [scope.id, scope.name]));

  return (
    <div className="stack task-workspace">
      <Panel title="Scan tasks" icon={<TerminalSquare size={17} />} action={<div className="row-actions"><button className="icon-button" title="Refresh" onClick={() => setRefresh((x) => x + 1)}><RefreshCw size={16} /></button><button className="primary-button" onClick={() => { setMessage(""); setEditor(blankTask()); }}><Plus size={15} />New scan task</button></div>}>
        <div className="task-toolbar"><Tabs value={status} setValue={(value) => { setStatus(value); setPageNumber(1); setSelectedIDs([]); }} items={["all", "pending", "queued", "running", "completed", "failed", "cancelled"]} labels={{ all: "All", pending: "Pending", queued: "Queued", running: "Running", completed: "Completed", failed: "Failed", cancelled: "Cancelled" }} /><AdvancedSearch compact value={search} fields={["name", "target", "status", "error"]} placeholder="Search tasks, e.g. target:example.com && !status:failed" onApply={(value) => { setSearch(value); setPageNumber(1); setSelectedIDs([]); }} /><div className="row-actions task-batch-actions"><button className="ghost-button" disabled={!selectedIDs.length} onClick={batchCancel}>Cancel selected</button><button className="ghost-button danger" disabled={!selectedIDs.length} onClick={batchDelete}>Delete selected</button></div></div>
        {error && <div className="error-box">{error}</div>}
        {message && <div className={message.includes("Failed") ? "error-box" : "success-box"}>{message}</div>}
        <DataTable
          storageKey="tasks-list"
          loading={loading}
          columns={["Selection", "Name", "Target", "Authorization scope", "Configuration", "Status", "Progress", "Created", "Actions"]}
          rows={(data?.tasks || []).map((task) => [
            <input key="select" className="row-check" type="checkbox" aria-label={`Select ${task.name}`} checked={selectedIDs.includes(task.id)} onChange={() => setSelectedIDs((current) => current.includes(task.id) ? current.filter((id) => id !== task.id) : [...current, task.id])} />,
            <button key="name" className="link-button" onClick={() => navigate(`task:${task.id}`)}>{task.name}</button>,
            task.target,
            task.scope_id ? <Badge key="scope" tone="ok">{scopeNames[task.scope_id] || task.scope_id.slice(0, 8)}</Badge> : <Badge key="scope">Compatibility Mode</Badge>,
            optionSummary(task.options),
            <Badge key="status" tone={task.status === "completed" ? "ok" : task.status === "failed" ? "danger" : "warn"}>{task.status}</Badge>,
            `${task.progress || 0}%`,
            formatDate(task.created_at),
            <div className="row-actions" key="actions">
              <button className="icon-button" title="Start" disabled={task.status !== "pending"} onClick={() => start(task.id)}><Play size={15} /></button>
              <button className="icon-button" title="Rerun" disabled={!["completed", "failed", "cancelled"].includes(task.status)} onClick={() => retry(task)}><RotateCcw size={15} /></button>
              <button className="icon-button" title="Cancel" disabled={!["queued", "running"].includes(task.status)} onClick={() => cancel(task.id)}><X size={15} /></button>
              <button className="icon-button" title="Export JSON" onClick={() => exportTask(task, "json")}><Download size={15} /></button>
              <button className="icon-button danger" title="Delete" onClick={() => remove(task.id)}><Trash2 size={15} /></button>
            </div>,
          ])}
          sortKeys={["", "name", "target", "", "", "status", "progress", "created_at", ""]}
          sortState={sortState}
          onSortChange={(key, direction) => setSortState({ index: ["", "name", "target", "", "", "status", "progress", "created_at", ""].indexOf(key), direction })}
          headerCells={{ 0: <SelectAllCheckbox ids={visibleTaskIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="tasks on this page" /> }}
          selectionColumn
          filterKeys={["", "name", "target", "", "", "status", "progress", "created_at", ""]}
          filters={columnFilters}
          filterOptions={{ status: ["pending", "queued", "running", "completed", "failed", "cancelled"] }}
          onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [key]: value })); setPageNumber(1); }}
          empty="No scan tasks found."
        />
        <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPageNumber} />
      </Panel>
      <Modal open={Boolean(editor)}>{editor && <form className="library-editor task-editor" onSubmit={createTask}>
        <div className="editor-head"><div><span className="eyebrow">Recon task profile</span><h3>New Scan Task</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setEditor(null)}><X size={16} /></button></div>
        <div className="task-editor-body">
          <section className="editor-section"><div className="editor-section-head"><span>00</span><strong>Scan target</strong></div><div className="editor-grid editor-grid-4"><label className="field-span-2">Task name<input required value={editor.name} onChange={(e) => setEditor({ ...editor, name: e.target.value })} /></label><label>Scan policy<select value={editor.policy_id} onChange={(e) => setEditor({ ...editor, policy_id: e.target.value })}><option value="">Use current configuration</option>{(policyData?.policies || []).map((policy) => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</select></label><label>Authorization scope<select value={editor.scope_id} onChange={(e) => setEditor({ ...editor, scope_id: e.target.value })}><option value="">{defaultScope ? `Default: ${defaultScope.name}` : "Compatibility mode (no default scope configured)"}</option>{scanScopes.filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}</select></label><label className="field-span-4">Target<textarea required rows="4" value={editor.target} onChange={(e) => setEditor({ ...editor, target: e.target.value })} placeholder="example.com, 10.0.0.1/24" /></label></div></section>
          <section className="task-strategy-row"><label>Subdomain wordlist<select value={editor.domain_brute_type} onChange={(e) => setEditor({ ...editor, domain_brute_type: e.target.value })}><option value="big">Full wordlist</option><option value="test">Test wordlist</option></select></label><label>Port scan<select value={editor.port_scan_type} onChange={(e) => setEditor({ ...editor, port_scan_type: e.target.value })}><option value="test">Test ports</option><option value="top100">Top 100</option><option value="top1000">Top 1,000</option><option value="all">All ports</option></select></label><label>Crawl depth<input type="number" min="1" max="10" value={editor.crawler_depth} onChange={(e) => setEditor({ ...editor, crawler_depth: e.target.value })} /></label><label>Maximum pages<input type="number" min="1" max="10000" value={editor.crawler_pages} onChange={(e) => setEditor({ ...editor, crawler_pages: e.target.value })} /></label></section>
          <div className="task-feature-grid">{featureGroups.map((group) => <section className="task-feature-group" key={group.title}><div className="editor-section-head"><span>{group.index}</span><strong>{group.title}</strong></div>{group.items.map(([key, label]) => <label className="feature-toggle" key={key}><input type="checkbox" checked={editor.flags[key]} onChange={() => toggleFlag(key)} /><span>{label}</span></label>)}</section>)}</div>
          <section className="editor-section"><div className="editor-section-head"><span>04</span><strong>Intelligence providers</strong></div><div className="plugin-grid">{pluginOptions.map((plugin) => <label className="feature-toggle" key={plugin}><input type="checkbox" checked={editor.domain_plugins.includes(plugin)} onChange={() => togglePlugin(plugin)} /><span>{plugin}</span></label>)}</div></section>
        </div>
        <div className="editor-actions task-editor-actions"><label className="feature-toggle start-toggle"><input type="checkbox" checked={editor.start_now} onChange={(e) => setEditor({ ...editor, start_now: e.target.checked })} /><span>Start immediately after creation</span></label><button type="button" className="ghost-button" onClick={() => setEditor(null)}>Cancel</button><button className="primary-button" disabled={saving}>{saving ? "Creating..." : "Create Task"}</button></div>
      </form>}</Modal>
    </div>
  );
}
