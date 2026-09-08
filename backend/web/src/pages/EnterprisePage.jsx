import React, { useEffect, useState } from "react";
import {
  Building2,
  ExternalLink,
  Globe2,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Send,
  Database,
  Trash2,
  X,
} from "lucide-react";
import {
  Badge,
  DataTable,
  Metric,
  Modal,
  Pager,
  Panel,
  SelectAllCheckbox,
  Tabs,
} from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate } from "../lib/api.js";

const kindLabels = {
  web: "Website",
  app: "Apply",
  miniapp: "Applet",
  quickapp: "Quick app",
};
const requestKinds = [
  ["web", "Website"],
  ["app", "Apply"],
  ["mapp", "Applet"],
  ["kapp", "Quick app"],
];

function statusBadge(status, errorMessage) {
  const label = { queued: "Queue", running: "Querying", completed: "Completed", failed: "Failed" }[status] || status;
  return <span title={errorMessage || undefined}><Badge tone={status === "completed" ? "ok" : status === "failed" ? "danger" : status === "running" ? "warn" : "muted"}>{label}</Badge>{errorMessage && <small className="enterprise-error-mark">There's been a mistake.</small>}</span>;
}

export default function EnterprisePage({ setPage }) {
  const [tab, setTab] = useState("queries");
  const [refresh, setRefresh] = useState(0);
  const [queryPage, setQueryPage] = useState(1);
  const [assetPage, setAssetPage] = useState(1);
  const [queryID, setQueryID] = useState("");
  const [kind, setKind] = useState("all");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [editor, setEditor] = useState(null);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [syncEditor, setSyncEditor] = useState(null);
  const [scanEditor, setScanEditor] = useState(null);

  const { data: providerData } = useQuery(`enterprise-providers-${refresh}`, () => api("/enterprise/providers"));
  const { data: groupData } = useQuery(`enterprise-groups-${refresh}`, () => api("/asset-groups"));
  const { data: scopeData } = useQuery("enterprise-scan-scopes", () => api("/scan-scopes"));
  const { data: queryData, loading: queryLoading, error: queryError } = useQuery(
    `enterprise-queries-${queryPage}-${refresh}`,
    () => api(`/enterprise/queries?page=${queryPage}&page_size=20`),
  );
  const assetParams = new URLSearchParams({ page: String(assetPage), page_size: "50" });
  if (queryID) assetParams.set("query_id", queryID);
  if (kind !== "all") assetParams.set("kind", kind);
  if (search) assetParams.set("q", search);
  const { data: assetData, loading: assetLoading, error: assetError } = useQuery(
    `enterprise-assets-${assetParams}-${refresh}`,
    () => api(`/enterprise/assets?${assetParams}`),
  );

  const providers = providerData?.providers || [];
  const provider = providers[0];
  const queries = queryData?.queries || [];
  const assets = assetData?.assets || [];
  const hasActiveQuery = queries.some((item) => item.status === "queued" || item.status === "running");
  useEffect(() => {
    if (!hasActiveQuery) return undefined;
    const timer = window.setInterval(() => setRefresh((value) => value + 1), 2500);
    return () => window.clearInterval(timer);
  }, [hasActiveQuery]);
  useEffect(() => setSelectedIDs([]), [queryID, kind, search, assetPage]);
  useEffect(() => {
    if (!message) return undefined;
    const timer = window.setTimeout(() => setMessage(""), 3000);
    return () => window.clearTimeout(timer);
  }, [message]);

  const totals = queryData?.stats || {};

  async function createQuery(event) {
    event.preventDefault();
    setSaving(true);
    setMessage("");
    try {
      await api("/enterprise/queries", {
        method: "POST",
        body: JSON.stringify({ name: editor.name, keyword: editor.keyword, provider: "icp_query", query_types: editor.queryTypes }),
      });
      setEditor(null);
      setMessage("Enterprise query in queue");
      setQueryPage(1);
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage(`Creation failed: ${error.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function removeQuery(item) {
    if (!window.confirm(`Confirm Delete"${item.name}"and its corporate assets?`)) return;
    try {
      await api(`/enterprise/queries/${item.id}`, { method: "DELETE" });
      if (queryID === item.id) setQueryID("");
      setMessage("Enterprise query deleted");
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage(`Delete failed: ${error.message}`);
    }
  }

  function viewAssets(item) {
    setQueryID(item.id);
    setAssetPage(1);
    setKind("all");
    setSearch("");
    setSearchInput("");
    setTab("assets");
  }

  async function launchScan(event) {
    event.preventDefault();
    if (!selectedIDs.length) return;
    setSaving(true);
    setMessage("");
    try {
      const result = await api("/enterprise/scans", {
        method: "POST",
        body: JSON.stringify({ asset_ids: selectedIDs, scope_id: scanEditor.scopeID, start: false, options: { enable_port_scan: true, port_scan_type: "top100", enable_service_detect: true, enable_site_detect: true } }),
      });
      setScanEditor(null);
      setMessage(`Created a scan task for ${result.target_count} domain${result.target_count === 1 ? "" : "s"}`);
      setSelectedIDs([]);
    } catch (error) {
      setMessage(`Dispatch failed: ${error.message}`);
    } finally { setSaving(false); }
  }

  async function syncAssets(event) {
	 event.preventDefault();
	 setSaving(true);
	 setMessage("");
	 try {
	   const result = await api("/enterprise/sync", {
		 method: "POST",
		 body: JSON.stringify({
		   asset_ids: selectedIDs,
		   group_id: syncEditor.mode === "existing" ? syncEditor.groupID : "",
		   new_group_name: syncEditor.mode === "new" ? syncEditor.groupName : "",
		 }),
	   });
	   setSyncEditor(null);
	   setSelectedIDs([]);
	   setMessage(`Synced ${result.synced_count} enterprise asset${result.synced_count === 1 ? "" : "s"} to the global inventory${result.group_name ? `; asset group: ${result.group_name}` : ""}`);
	   setRefresh((value) => value + 1);
	 } catch (error) {
	   setMessage(`Synchronization failed: ${error.message}`);
	 } finally {
	   setSaving(false);
	 }
  }

  function openSyncEditor() {
	 setSyncEditor({ mode: "catalog", groupID: "", groupName: "" });
	 setMessage("");
  }

  const scannableIDs = assets.filter((item) => item.domain).map((item) => item.id);
  const queryRows = queries.map((item) => [
    <div className="enterprise-primary" key="name"><strong>{item.name}</strong><span>{item.keyword}</span></div>,
    item.provider === "icp_query" ? "ICP_Query" : item.provider,
    <div className="enterprise-kinds" key="types">{(item.query_types || []).map((value) => <span key={value}>{requestKinds.find(([id]) => id === value)?.[1] || value}</span>)}</div>,
    statusBadge(item.status, item.error_msg),
    `${item.total_count} / ${item.synced_count || 0}`,
    item.domain_count,
    item.app_count,
    item.mini_app_count + item.quick_app_count,
    formatDate(item.created_at),
    <div className="row-actions" key="actions">
      <button className="ghost-button compact" onClick={() => viewAssets(item)}><ExternalLink size={13} />View</button>
      <button className="icon-button danger" title="Remove Query" disabled={item.status === "queued" || item.status === "running"} onClick={() => removeQuery(item)}><Trash2 size={14} /></button>
    </div>,
  ]);
  const assetRows = assets.map((item) => [
    item.domain ? <input key="select" className="row-check" type="checkbox" aria-label={`Select ${item.domain}`} checked={selectedIDs.includes(item.id)} onChange={() => setSelectedIDs((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} /> : <span key="empty" className="selection-placeholder">-</span>,
    <div className="enterprise-primary" key="asset"><strong>{item.domain || item.name || item.company_name || "-"}</strong><span>{item.company_name || "-"}</span></div>,
    kindLabels[item.kind] || item.kind,
    item.name || "-",
    item.license || "-",
    formatDate(item.created_at),
  ]);

  return <div className="enterprise-workspace">
    <div className="metric-grid enterprise-metrics">
      <Metric label="Query Tasks" value={queryData?.total || 0} icon={<Building2 size={18} />} />
      <Metric label="Assets found" value={totals.TotalAssets || totals.total_assets || 0} icon={<Radar size={18} />} />
      <Metric label="Scannable domains" value={totals.Domains || totals.domains || 0} icon={<Globe2 size={18} />} />
      <Metric label="Apps / mini apps" value={(totals.Apps || totals.apps || 0) + (totals.MiniApps || totals.mini_apps || 0) + (totals.QuickApps || totals.quick_apps || 0)} icon={<Search size={18} />} />
    </div>
    <Panel title="Enterprise multi-dimensional asset discovery" icon={<Building2 size={17} />} action={<div className="enterprise-provider-status">{provider?.enabled ? <Badge tone="ok">ICP_Query Ready</Badge> : <><Badge tone="warn">Data source not configured</Badge><button className="ghost-button compact" onClick={() => setPage("mapping")}>Go to Mapping Configuration</button></>}</div>}>
      <div className="task-toolbar enterprise-toolbar">
        <Tabs value={tab} setValue={setTab} items={["queries", "assets"]} labels={{ queries: "Query Tasks", assets: "Enterprise assets" }} />
        <div className="row-actions">
          <button className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={15} /></button>
          <button className="primary-button" disabled={!provider?.enabled} onClick={() => setEditor({ name: "", keyword: "", queryTypes: ["web"] })}><Plus size={15} />New Query</button>
        </div>
      </div>
      {message && <div className={message.includes("Failed") ? "error-box enterprise-message" : "success-box enterprise-message"}>{message}<button className="icon-button" title="Close" onClick={() => setMessage("")}><X size={13} /></button></div>}
      {tab === "queries" ? <>
        {queryError && <div className="error-box">Failed to load: {queryError}</div>}
        <DataTable storageKey="enterprise-queries" loading={queryLoading} columns={["Name / Keywords", "Data Sources", "Type", "Status", "Found / Sync", "Domain name", "Apply", "Applet", "Created", "Actions"]} rows={queryRows} empty="No enterprise query task available" />
        <Pager page={queryData?.page || queryPage} totalPages={Math.max(1, Number(queryData?.total_pages || 1))} setPage={setQueryPage} />
      </> : <>
        <div className="enterprise-asset-toolbar">
          <select value={queryID} onChange={(event) => { setQueryID(event.target.value); setAssetPage(1); }}><option value="">Query all tasks</option>{queries.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select>
          <select value={kind} onChange={(event) => { setKind(event.target.value); setAssetPage(1); }}><option value="all">All Types</option>{Object.entries(kindLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select>
          <form className="search-box" onSubmit={(event) => { event.preventDefault(); setSearch(searchInput.trim()); setAssetPage(1); }}><Search size={14} /><input aria-label="Search enterprise assets" value={searchInput} onChange={(event) => setSearchInput(event.target.value)} placeholder="Enterprise, Name, Domain name or filing number" /></form>
          <div className="row-actions enterprise-asset-actions"><button className="ghost-button" disabled={!selectedIDs.length} onClick={openSyncEditor}><Database size={14} />Sync assets ({selectedIDs.length})</button><button className="primary-button enterprise-launch" disabled={!selectedIDs.length} onClick={() => { setMessage(""); setScanEditor({ scopeID: "" }); }}><Send size={14} />Create scan ({selectedIDs.length})</button></div>
        </div>
        {assetError && <div className="error-box">Failed to load: {assetError}</div>}
        <DataTable storageKey="enterprise-assets" loading={assetLoading} selectionColumn columns={["Selection", "Assets / Enterprise", "Type", "Product Name", "File number", "Time of discovery"]} headerCells={{ 0: <SelectAllCheckbox ids={scannableIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="This page is scanned domain names" /> }} rows={assetRows} empty="No enterprise assets match the current filter" />
        <Pager page={assetData?.page || assetPage} totalPages={Math.max(1, Number(assetData?.total_pages || 1))} setPage={setAssetPage} />
      </>}
    </Panel>
    {editor && <Modal><form className="library-editor enterprise-editor" onSubmit={createQuery}>
      <div className="editor-head"><div><span className="eyebrow">Enterprise discovery</span><h3>New enterprise query</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close" onClick={() => setEditor(null)}><X size={16} /></button></div>
      <div className="editor-grid"><label>Task Name<input value={editor.name} placeholder="Defaults to the enterprise keyword" onChange={(event) => setEditor({ ...editor, name: event.target.value })} /></label><label>Enterprise keyword<input autoFocus required value={editor.keyword} placeholder="Enterprise full name or brand keyword" onChange={(event) => setEditor({ ...editor, keyword: event.target.value })} /></label></div>
      <fieldset className="enterprise-kind-picker"><legend>Query asset type</legend>{requestKinds.map(([value, label]) => <label key={value}><input type="checkbox" checked={editor.queryTypes.includes(value)} onChange={() => setEditor((current) => ({ ...current, queryTypes: current.queryTypes.includes(value) ? current.queryTypes.filter((item) => item !== value) : [...current.queryTypes, value] }))} /><span>{label}</span></label>)}</fieldset>
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditor(null)}>Cancel</button><button className="primary-button" disabled={saving || !editor.keyword.trim() || !editor.queryTypes.length}>{saving ? "Submitting..." : "Queue query"}</button></div>
    </form></Modal>}
    {syncEditor && <Modal><form className="library-editor enterprise-editor" onSubmit={syncAssets}>
      <div className="editor-head"><div><span className="eyebrow">Canonical asset sync</span><h3>Synchronize enterprise assets</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close Sync" onClick={() => setSyncEditor(null)}><X size={16} /></button></div>
      <div className="hint">Selected {selectedIDs.length} scannable domain{selectedIDs.length === 1 ? "" : "s"}. This adds them to the global inventory while retaining their enterprise-query source. It does not start a network scan.</div>
      <Tabs value={syncEditor.mode} setValue={(mode) => setSyncEditor((current) => ({ ...current, mode }))} items={["catalog", "existing", "new"]} labels={{ catalog: "Inventory only", existing: "Existing group", new: "New Group" }} />
      {syncEditor.mode === "existing" && <label>Target asset grouping<select required value={syncEditor.groupID} onChange={(event) => setSyncEditor({ ...syncEditor, groupID: event.target.value })}><option value="">Select asset group</option>{(groupData?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>}
      {syncEditor.mode === "new" && <label>New Group Name<input required maxLength="255" value={syncEditor.groupName} placeholder="For example: Target business boundaries" onChange={(event) => setSyncEditor({ ...syncEditor, groupName: event.target.value })} /></label>}
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setSyncEditor(null)}>Cancel</button><button className="primary-button" disabled={saving || (syncEditor.mode === "existing" && !syncEditor.groupID) || (syncEditor.mode === "new" && !syncEditor.groupName.trim())}>{saving ? "Syncing..." : "Synchronize assets"}</button></div>
    </form></Modal>}
    {scanEditor && <Modal><form className="library-editor enterprise-editor" onSubmit={launchScan}>
      <div className="editor-head"><div><span className="eyebrow">Scoped scan handoff</span><h3>Create an enterprise-asset scan</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close scan editor" onClick={() => setScanEditor(null)}><X size={16} /></button></div>
      <div className="hint">Selected {selectedIDs.length} domain{selectedIDs.length === 1 ? "" : "s"}. The backend verifies the authorization scope when the task is created and started.</div>
      <label>Authorization scope<select value={scanEditor.scopeID} onChange={(event) => setScanEditor({ scopeID: event.target.value })}><option value="">{(scopeData?.scopes || []).find((scope) => scope.is_default)?.name ? `Default: ${(scopeData?.scopes || []).find((scope) => scope.is_default).name}` : "Compatibility Mode (No default scope configured)"}</option>{(scopeData?.scopes || []).filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}</select></label>
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setScanEditor(null)}>Cancel</button><button className="primary-button" disabled={saving}>{saving ? "Creating..." : "Create pending task"}</button></div>
    </form></Modal>}
  </div>;
}
