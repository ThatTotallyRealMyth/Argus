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
  web: "网站",
  app: "应用",
  miniapp: "小程序",
  quickapp: "快应用",
};
const requestKinds = [
  ["web", "网站"],
  ["app", "应用"],
  ["mapp", "小程序"],
  ["kapp", "快应用"],
];

function statusBadge(status, errorMessage) {
  const label = { queued: "排队中", running: "查询中", completed: "已完成", failed: "失败" }[status] || status;
  return <span title={errorMessage || undefined}><Badge tone={status === "completed" ? "ok" : status === "failed" ? "danger" : status === "running" ? "warn" : "muted"}>{label}</Badge>{errorMessage && <small className="enterprise-error-mark">有错误</small>}</span>;
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
      setMessage("企业查询已进入队列");
      setQueryPage(1);
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage(`创建失败：${error.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function removeQuery(item) {
    if (!window.confirm(`确认删除“${item.name}”及其企业资产？`)) return;
    try {
      await api(`/enterprise/queries/${item.id}`, { method: "DELETE" });
      if (queryID === item.id) setQueryID("");
      setMessage("企业查询已删除");
      setRefresh((value) => value + 1);
    } catch (error) {
      setMessage(`删除失败：${error.message}`);
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
      setMessage(`已创建待执行扫描任务，包含 ${result.target_count} 个域名`);
      setSelectedIDs([]);
    } catch (error) {
      setMessage(`下发失败：${error.message}`);
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
	   setMessage(`已同步 ${result.synced_count} 条企业资产到全局清单${result.group_name ? `，资产分组：${result.group_name}` : ""}`);
	   setRefresh((value) => value + 1);
	 } catch (error) {
	   setMessage(`同步失败：${error.message}`);
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
      <button className="ghost-button compact" onClick={() => viewAssets(item)}><ExternalLink size={13} />查看</button>
      <button className="icon-button danger" title="删除查询" disabled={item.status === "queued" || item.status === "running"} onClick={() => removeQuery(item)}><Trash2 size={14} /></button>
    </div>,
  ]);
  const assetRows = assets.map((item) => [
    item.domain ? <input key="select" className="row-check" type="checkbox" aria-label={`选择 ${item.domain}`} checked={selectedIDs.includes(item.id)} onChange={() => setSelectedIDs((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} /> : <span key="empty" className="selection-placeholder">-</span>,
    <div className="enterprise-primary" key="asset"><strong>{item.domain || item.name || item.company_name || "-"}</strong><span>{item.company_name || "-"}</span></div>,
    kindLabels[item.kind] || item.kind,
    item.name || "-",
    item.license || "-",
    formatDate(item.created_at),
  ]);

  return <div className="enterprise-workspace">
    <div className="metric-grid enterprise-metrics">
      <Metric label="查询任务" value={queryData?.total || 0} icon={<Building2 size={18} />} />
      <Metric label="发现资产" value={totals.TotalAssets || totals.total_assets || 0} icon={<Radar size={18} />} />
      <Metric label="可扫描域名" value={totals.Domains || totals.domains || 0} icon={<Globe2 size={18} />} />
      <Metric label="应用 / 小程序" value={(totals.Apps || totals.apps || 0) + (totals.MiniApps || totals.mini_apps || 0) + (totals.QuickApps || totals.quick_apps || 0)} icon={<Search size={18} />} />
    </div>
    <Panel title="企业多维资产发现" icon={<Building2 size={17} />} action={<div className="enterprise-provider-status">{provider?.enabled ? <Badge tone="ok">ICP_Query 已就绪</Badge> : <><Badge tone="warn">数据源未配置</Badge><button className="ghost-button compact" onClick={() => setPage("mapping")}>前往测绘配置</button></>}</div>}>
      <div className="task-toolbar enterprise-toolbar">
        <Tabs value={tab} setValue={setTab} items={["queries", "assets"]} labels={{ queries: "查询任务", assets: "企业资产" }} />
        <div className="row-actions">
          <button className="icon-button" title="刷新" aria-label="刷新" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={15} /></button>
          <button className="primary-button" disabled={!provider?.enabled} onClick={() => setEditor({ name: "", keyword: "", queryTypes: ["web"] })}><Plus size={15} />新建查询</button>
        </div>
      </div>
      {message && <div className={message.includes("失败") ? "error-box enterprise-message" : "success-box enterprise-message"}>{message}<button className="icon-button" title="关闭" onClick={() => setMessage("")}><X size={13} /></button></div>}
      {tab === "queries" ? <>
        {queryError && <div className="error-box">加载失败：{queryError}</div>}
        <DataTable storageKey="enterprise-queries" loading={queryLoading} columns={["名称 / 关键词", "数据源", "类型", "状态", "发现 / 同步", "域名", "应用", "小程序", "创建时间", "操作"]} rows={queryRows} empty="还没有企业查询任务" />
        <Pager page={queryData?.page || queryPage} totalPages={Math.max(1, Number(queryData?.total_pages || 1))} setPage={setQueryPage} />
      </> : <>
        <div className="enterprise-asset-toolbar">
          <select value={queryID} onChange={(event) => { setQueryID(event.target.value); setAssetPage(1); }}><option value="">全部查询任务</option>{queries.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select>
          <select value={kind} onChange={(event) => { setKind(event.target.value); setAssetPage(1); }}><option value="all">全部类型</option>{Object.entries(kindLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select>
          <form className="search-box" onSubmit={(event) => { event.preventDefault(); setSearch(searchInput.trim()); setAssetPage(1); }}><Search size={14} /><input aria-label="检索企业资产" value={searchInput} onChange={(event) => setSearchInput(event.target.value)} placeholder="企业、名称、域名或备案号" /></form>
          <div className="row-actions enterprise-asset-actions"><button className="ghost-button" disabled={!selectedIDs.length} onClick={openSyncEditor}><Database size={14} />同步资产（{selectedIDs.length}）</button><button className="primary-button enterprise-launch" disabled={!selectedIDs.length} onClick={() => { setMessage(""); setScanEditor({ scopeID: "" }); }}><Send size={14} />下发扫描（{selectedIDs.length}）</button></div>
        </div>
        {assetError && <div className="error-box">加载失败：{assetError}</div>}
        <DataTable storageKey="enterprise-assets" loading={assetLoading} selectionColumn columns={["选择", "资产 / 企业", "类型", "产品名称", "备案号", "发现时间"]} headerCells={{ 0: <SelectAllCheckbox ids={scannableIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="本页可扫描域名" /> }} rows={assetRows} empty="当前筛选下没有企业资产" />
        <Pager page={assetData?.page || assetPage} totalPages={Math.max(1, Number(assetData?.total_pages || 1))} setPage={setAssetPage} />
      </>}
    </Panel>
    {editor && <Modal><form className="library-editor enterprise-editor" onSubmit={createQuery}>
      <div className="editor-head"><div><span className="eyebrow">Enterprise discovery</span><h3>新建企业查询</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭" onClick={() => setEditor(null)}><X size={16} /></button></div>
      <div className="editor-grid"><label>任务名称<input value={editor.name} placeholder="默认使用企业关键词" onChange={(event) => setEditor({ ...editor, name: event.target.value })} /></label><label>企业关键词<input autoFocus required value={editor.keyword} placeholder="企业全称或品牌关键词" onChange={(event) => setEditor({ ...editor, keyword: event.target.value })} /></label></div>
      <fieldset className="enterprise-kind-picker"><legend>查询资产类型</legend>{requestKinds.map(([value, label]) => <label key={value}><input type="checkbox" checked={editor.queryTypes.includes(value)} onChange={() => setEditor((current) => ({ ...current, queryTypes: current.queryTypes.includes(value) ? current.queryTypes.filter((item) => item !== value) : [...current.queryTypes, value] }))} /><span>{label}</span></label>)}</fieldset>
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditor(null)}>取消</button><button className="primary-button" disabled={saving || !editor.keyword.trim() || !editor.queryTypes.length}>{saving ? "提交中..." : "加入查询队列"}</button></div>
    </form></Modal>}
    {syncEditor && <Modal><form className="library-editor enterprise-editor" onSubmit={syncAssets}>
      <div className="editor-head"><div><span className="eyebrow">Canonical asset sync</span><h3>同步企业资产</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭同步" onClick={() => setSyncEditor(null)}><X size={16} /></button></div>
      <div className="hint">已选择 {selectedIDs.length} 条可扫描域名。同步后会进入全局资产清单并保留企业查询来源，不会启动网络扫描。</div>
      <Tabs value={syncEditor.mode} setValue={(mode) => setSyncEditor((current) => ({ ...current, mode }))} items={["catalog", "existing", "new"]} labels={{ catalog: "仅全局清单", existing: "已有分组", new: "新建分组" }} />
      {syncEditor.mode === "existing" && <label>目标资产分组<select required value={syncEditor.groupID} onChange={(event) => setSyncEditor({ ...syncEditor, groupID: event.target.value })}><option value="">请选择资产分组</option>{(groupData?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>}
      {syncEditor.mode === "new" && <label>新分组名称<input required maxLength="255" value={syncEditor.groupName} placeholder="例如：目标企业边界" onChange={(event) => setSyncEditor({ ...syncEditor, groupName: event.target.value })} /></label>}
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setSyncEditor(null)}>取消</button><button className="primary-button" disabled={saving || (syncEditor.mode === "existing" && !syncEditor.groupID) || (syncEditor.mode === "new" && !syncEditor.groupName.trim())}>{saving ? "同步中..." : "确认同步"}</button></div>
    </form></Modal>}
    {scanEditor && <Modal><form className="library-editor enterprise-editor" onSubmit={launchScan}>
      <div className="editor-head"><div><span className="eyebrow">Scoped scan handoff</span><h3>下发企业资产扫描</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭扫描下发" onClick={() => setScanEditor(null)}><X size={16} /></button></div>
      <div className="hint">已选择 {selectedIDs.length} 条域名。后端会在创建和启动任务时分别校验授权边界。</div>
      <label>授权范围<select value={scanEditor.scopeID} onChange={(event) => setScanEditor({ scopeID: event.target.value })}><option value="">{(scopeData?.scopes || []).find((scope) => scope.is_default)?.name ? `默认：${(scopeData?.scopes || []).find((scope) => scope.is_default).name}` : "兼容模式（未配置默认范围）"}</option>{(scopeData?.scopes || []).filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}</select></label>
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setScanEditor(null)}>取消</button><button className="primary-button" disabled={saving}>{saving ? "创建中..." : "创建待执行任务"}</button></div>
    </form></Modal>}
  </div>;
}
