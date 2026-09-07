import React, { useEffect, useState } from "react";
import { Copy, Crosshair, ExternalLink, NotebookPen, Play, Radar, RefreshCw, Route, Search, X } from "lucide-react";
import { Badge, EmptyState, Modal, Pager, Panel, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate, severityClass } from "../lib/api.js";
import { leadPoCExecutionPayload, leadQueueParams, leadStatusLabel, leadStatusOptions, leadStatusTone, leadTargetURL, leadTriagePayload, leadTypeLabel } from "../lib/leadQueue.js";

const leadTypeOptions = [
  ["all", "全部类型"], ["confirmed_vulnerability", "确认漏洞"], ["subdomain_takeover", "接管候选"],
  ["sensitive_service", "敏感服务"], ["management_surface", "入口暴露"], ["poc_opportunity", "PoC 机会"],
  ["surface_change", "攻击面变化"], ["recent_exposure", "新增暴露"],
];

export default function LeadsPage({ setPage: navigate }) {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("all");
  const [type, setType] = useState("all");
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [message, setMessage] = useState("");
  const [noteEditor, setNoteEditor] = useState(null);
  const [running, setRunning] = useState("");
  const params = leadQueueParams({ page, status, severity, type, query });
  const { data, loading, error } = useQuery(`lead-queue-${params}-${refresh}`, () => api(`/assets/leads?${params}`), { ttl: 0 });
  const stats = data?.stats || {};
  const totalPages = Math.max(data?.total_pages || 1, 1);

  useEffect(() => {
    if (!loading && page > totalPages) setPage(totalPages);
  }, [loading, page, totalPages]);

  async function updateTriage(lead, nextStatus, note = lead.triage_note || "") {
    try {
      await api("/assets/leads/triage", { method: "PUT", body: JSON.stringify(leadTriagePayload(lead, nextStatus, note)) });
      setMessage(`已更新为${leadStatusLabel(nextStatus)}`);
      setNoteEditor(null);
      setRefresh((value) => value + 1);
    } catch (updateError) { setMessage(`更新失败：${updateError.message}`); }
  }

  function openAsset(asset) {
    window.history.pushState({}, "", `/assets?asset=${encodeURIComponent(asset.asset_id)}`);
    navigate("assets");
  }

  async function copyTarget(value) {
    try { await navigator.clipboard.writeText(value); setMessage("目标已复制"); }
    catch { setMessage("复制失败"); }
  }

  async function executePoC(lead) {
    if (!lead.poc || !window.confirm(`使用“${lead.poc.name}”验证目标 ${lead.target}？`)) return;
    setRunning(`${lead.asset_id}:${lead.id}`);
    try {
      const result = await api("/assets/leads/execute-poc", { method: "POST", body: JSON.stringify(leadPoCExecutionPayload(lead)) });
      setMessage(result.finding ? `验证命中，${result.finding_created ? "已固化" : "已更新"}可提交漏洞证据` : `验证结果：${({ vulnerable: "命中", safe: "未命中", error: "失败" })[result.result] || result.result || "已完成"}，已写入审计链`);
      setRefresh((value) => value + 1);
    } catch (runError) { setMessage(`验证失败：${runError.message}`); }
    finally { setRunning(""); }
  }

  return <Panel title="狩猎线索" icon={<Radar size={17} />} action={<button className="icon-button" title="刷新线索" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={16} /></button>}>
    <div className="lead-queue-toolbar">
      <Tabs value={status} setValue={(value) => { setStatus(value); setPage(1); }} items={["open", "new", "investigating", "validated", "ignored", "all"]} labels={{ open: "待处理", new: "新线索", investigating: "调查中", validated: "已验证", ignored: "已忽略", all: "全部" }} />
      <select name="severity" aria-label="线索级别" value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }}><option value="all">全部级别</option>{["critical", "high", "medium", "low", "info"].map((value) => <option value={value} key={value}>{value}</option>)}</select>
      <select name="type" aria-label="线索类型" value={type} onChange={(event) => { setType(event.target.value); setPage(1); }}>{leadTypeOptions.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select>
      <form className="lead-queue-search" onSubmit={(event) => { event.preventDefault(); setQuery(draft); setPage(1); }}><Search size={14} /><input name="query" aria-label="检索狩猎线索" value={draft} placeholder="目标、线索或笔记" onChange={(event) => setDraft(event.target.value)} /><button type="submit">检索</button></form>
    </div>
    <div className="lead-queue-stats">
      <div><span>全部线索</span><strong>{stats.total || 0}</strong></div><div><span>新线索</span><strong>{stats.new || 0}</strong></div>
      <div><span>调查中</span><strong>{stats.investigating || 0}</strong></div><div><span>已验证</span><strong>{stats.validated || 0}</strong></div>
      <div><span>严重 / 高危</span><strong>{stats.critical_high || 0}</strong></div><div><span>关联资产</span><strong>{stats.assets || 0}</strong></div>
    </div>
    {error && <div className="error-box">加载失败：{error}</div>}{message && <div className={message.includes("失败") ? "error-box" : "success-box"}>{message}</div>}
    {data?.truncated && <div className="hint lead-queue-limit">当前按最近和风险优先生成前 {data.candidate_assets} 个资产的线索。</div>}
    <div className="lead-queue-list">
      {loading && <div className="route-loading"><span className="status-dot" />正在聚合攻击面线索...</div>}
      {!loading && !(data?.leads || []).length && <EmptyState text="当前筛选下没有线索" />}
      {(data?.leads || []).map((lead) => {
        const targetURL = leadTargetURL(lead);
        const runKey = `${lead.asset_id}:${lead.id}`;
        const relatedAssets = lead.related_assets?.length ? lead.related_assets : [{ asset_id: lead.asset_id, kind: lead.asset_kind, value: lead.asset_value }];
        return <article className={`hunt-lead severity-${lead.severity || "info"}`} key={runKey}>
          <div className="hunt-lead-priority"><strong>{lead.priority}</strong><span>优先级</span></div>
          <div className="hunt-lead-main">
            <div className="hunt-lead-title"><Badge tone={severityClass[lead.severity] || "muted"}>{lead.severity}</Badge><Badge>{leadTypeLabel(lead.type)}</Badge><Badge tone={leadStatusTone(lead.triage_status)}>{leadStatusLabel(lead.triage_status)}</Badge>{lead.affected_assets > 1 && <Badge tone="accent">影响 {lead.affected_assets} 个资产</Badge>}<strong>{lead.title}</strong><span>置信度 {lead.confidence}%</span></div>
            <div className="hunt-lead-assets">{relatedAssets.map((asset) => <button className="hunt-lead-asset" key={asset.asset_id} onClick={() => openAsset(asset)}><span>{asset.kind}</span><strong>{asset.value}</strong></button>)}</div>
            <p>{lead.reason}</p><div className="hunt-lead-next"><Crosshair size={13} /><span>{lead.suggested_action}</span></div>
            {lead.triage_note && <div className="hunt-lead-note"><NotebookPen size={12} /><span>{lead.triage_note}</span></div>}
          </div>
          <div className="hunt-lead-meta"><span>{lead.target}</span><time>{formatDate(lead.observed_at)}</time><small>来源 {lead.task_id ? lead.task_id.slice(0, 8) : "资产库"}</small></div>
          <div className="hunt-lead-actions">
            <select name={`triage_status_${lead.id}`} aria-label={`更新 ${lead.title} 状态`} value={lead.triage_status || "new"} onChange={(event) => updateTriage(lead, event.target.value)}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
            <div className="row-actions"><button className="icon-button" title="编辑笔记" onClick={() => setNoteEditor({ lead, note: lead.triage_note || "", status: lead.triage_status || "new" })}><NotebookPen size={14} /></button><button className="icon-button" title="复制目标" onClick={() => copyTarget(lead.target)}><Copy size={14} /></button>{targetURL && <button className="icon-button" title="打开目标" onClick={() => window.open(targetURL, "_blank", "noopener,noreferrer")}><ExternalLink size={14} /></button>}{lead.task_id && <button className="icon-button" title="查看来源任务" onClick={() => navigate(`task:${lead.task_id}`)}><Route size={14} /></button>}</div>
            {lead.poc && <button className="primary-button compact" disabled={running === runKey} onClick={() => executePoC(lead)}><Play size={13} />{running === runKey ? "验证中" : "验证 PoC"}</button>}
          </div>
        </article>;
      })}
    </div>
    <Pager page={page} totalPages={totalPages} setPage={setPage} />
    <Modal open={Boolean(noteEditor)}>{noteEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); updateTriage(noteEditor.lead, noteEditor.status, noteEditor.note); }}><div className="editor-head"><div><span className="eyebrow">Hunter note</span><h3>{noteEditor.lead.title}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setNoteEditor(null)}><X size={16} /></button></div><label>研判状态<select name="triage_status" value={noteEditor.status} onChange={(event) => setNoteEditor({ ...noteEditor, status: event.target.value })}>{leadStatusOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}</select></label><label>个人笔记<textarea name="triage_note" autoFocus rows="8" maxLength="5000" value={noteEditor.note} onChange={(event) => setNoteEditor({ ...noteEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setNoteEditor(null)}>取消</button><button className="primary-button">保存研判</button></div></form>}</Modal>
  </Panel>;
}
