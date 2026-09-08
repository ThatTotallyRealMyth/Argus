import React, { useEffect, useState } from "react";
import { Copy, Crosshair, ExternalLink, NotebookPen, Play, Radar, RefreshCw, Route, Search, X } from "lucide-react";
import { Badge, EmptyState, Modal, Pager, Panel, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate, severityClass } from "../lib/api.js";
import { leadPoCExecutionPayload, leadQueueParams, leadStatusLabel, leadStatusOptions, leadStatusTone, leadTargetURL, leadTriagePayload, leadTypeLabel } from "../lib/leadQueue.js";

const leadTypeOptions = [
  ["all", "All types"], ["confirmed_vulnerability", "Confirmed findings"], ["subdomain_takeover", "Subdomain takeover candidates"],
  ["sensitive_service", "Sensitive services"], ["management_surface", "Access is compromised."], ["poc_opportunity", "PoC Opportunities"],
  ["surface_change", "Change in the attack."], ["recent_exposure", "Add Exposure"],
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
      setMessage(`Updated As${leadStatusLabel(nextStatus)}`);
      setNoteEditor(null);
      setRefresh((value) => value + 1);
    } catch (updateError) { setMessage(`Update failed: ${updateError.message}`); }
  }

  function openAsset(asset) {
    window.history.pushState({}, "", `/assets?asset=${encodeURIComponent(asset.asset_id)}`);
    navigate("assets");
  }

  async function copyTarget(value) {
    try { await navigator.clipboard.writeText(value); setMessage("Target copied"); }
    catch { setMessage("Copy Failed"); }
  }

  async function executePoC(lead) {
    if (!lead.poc || !window.confirm(`Use"${lead.poc.name}"Validate Target ${lead.target}?`)) return;
    setRunning(`${lead.asset_id}:${lead.id}`);
    try {
      const result = await api("/assets/leads/execute-poc", { method: "POST", body: JSON.stringify(leadPoCExecutionPayload(lead)) });
      setMessage(result.finding ? `Verify hit, ${result.finding_created ? "Recorded" : "Updated"}; finding evidence is ready for submission` : `Validate Results: ${({ vulnerable: "Hit!", safe: "Missed.", error: "Failed" })[result.result] || result.result || "Completed"}, Written to the audit trail`);
      setRefresh((value) => value + 1);
    } catch (runError) { setMessage(`Validation failed: ${runError.message}`); }
    finally { setRunning(""); }
  }

  return <Panel title="Hunting trail." icon={<Radar size={17} />} action={<button className="icon-button" title="Refresh Threads" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={16} /></button>}>
    <div className="lead-queue-toolbar">
      <Tabs value={status} setValue={(value) => { setStatus(value); setPage(1); }} items={["open", "new", "investigating", "validated", "ignored", "all"]} labels={{ open: "Pending", new: "New Thread", investigating: "In progress", validated: "Verifyed", ignored: "Ignored", all: "All" }} />
      <select name="severity" aria-label="Thread Level" value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }}><option value="all">All Levels</option>{["critical", "high", "medium", "low", "info"].map((value) => <option value={value} key={value}>{value}</option>)}</select>
      <select name="type" aria-label="Thread Type" value={type} onChange={(event) => { setType(event.target.value); setPage(1); }}>{leadTypeOptions.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select>
      <form className="lead-queue-search" onSubmit={(event) => { event.preventDefault(); setQuery(draft); setPage(1); }}><Search size={14} /><input name="query" aria-label="Search for hunting clues." value={draft} placeholder="Target, lead, or notes" onChange={(event) => setDraft(event.target.value)} /><button type="submit">Search</button></form>
    </div>
    <div className="lead-queue-stats">
      <div><span>All Threads</span><strong>{stats.total || 0}</strong></div><div><span>New Thread</span><strong>{stats.new || 0}</strong></div>
      <div><span>In progress</span><strong>{stats.investigating || 0}</strong></div><div><span>Verifyed</span><strong>{stats.validated || 0}</strong></div>
      <div><span>Serious / High risk</span><strong>{stats.critical_high || 0}</strong></div><div><span>Associated assets</span><strong>{stats.assets || 0}</strong></div>
    </div>
    {error && <div className="error-box">Failed to load: {error}</div>}{message && <div className={message.includes("Failed") ? "error-box" : "success-box"}>{message}</div>}
    {data?.truncated && <div className="hint lead-queue-limit">This view is limited to the {data.candidate_assets} most recent, highest-risk asset leads.</div>}
    <div className="lead-queue-list">
      {loading && <div className="route-loading"><span className="status-dot" />Building the attack-path view...</div>}
      {!loading && !(data?.leads || []).length && <EmptyState text="No threads under the current filter" />}
      {(data?.leads || []).map((lead) => {
        const targetURL = leadTargetURL(lead);
        const runKey = `${lead.asset_id}:${lead.id}`;
        const relatedAssets = lead.related_assets?.length ? lead.related_assets : [{ asset_id: lead.asset_id, kind: lead.asset_kind, value: lead.asset_value }];
        return <article className={`hunt-lead severity-${lead.severity || "info"}`} key={runKey}>
          <div className="hunt-lead-priority"><strong>{lead.priority}</strong><span>Priority</span></div>
          <div className="hunt-lead-main">
            <div className="hunt-lead-title"><Badge tone={severityClass[lead.severity] || "muted"}>{lead.severity}</Badge><Badge>{leadTypeLabel(lead.type)}</Badge><Badge tone={leadStatusTone(lead.triage_status)}>{leadStatusLabel(lead.triage_status)}</Badge>{lead.affected_assets > 1 && <Badge tone="accent">Impact {lead.affected_assets} Assets</Badge>}<strong>{lead.title}</strong><span>Confidence {lead.confidence}%</span></div>
            <div className="hunt-lead-assets">{relatedAssets.map((asset) => <button className="hunt-lead-asset" key={asset.asset_id} onClick={() => openAsset(asset)}><span>{asset.kind}</span><strong>{asset.value}</strong></button>)}</div>
            <p>{lead.reason}</p><div className="hunt-lead-next"><Crosshair size={13} /><span>{lead.suggested_action}</span></div>
            {lead.triage_note && <div className="hunt-lead-note"><NotebookPen size={12} /><span>{lead.triage_note}</span></div>}
          </div>
          <div className="hunt-lead-meta"><span>{lead.target}</span><time>{formatDate(lead.observed_at)}</time><small>Source {lead.task_id ? lead.task_id.slice(0, 8) : "Asset base"}</small></div>
          <div className="hunt-lead-actions">
            <select name={`triage_status_${lead.id}`} aria-label={`Update ${lead.title} Status`} value={lead.triage_status || "new"} onChange={(event) => updateTriage(lead, event.target.value)}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
            <div className="row-actions"><button className="icon-button" title="Edit Notes" onClick={() => setNoteEditor({ lead, note: lead.triage_note || "", status: lead.triage_status || "new" })}><NotebookPen size={14} /></button><button className="icon-button" title="Copy Target" onClick={() => copyTarget(lead.target)}><Copy size={14} /></button>{targetURL && <button className="icon-button" title="Open Target" onClick={() => window.open(targetURL, "_blank", "noopener,noreferrer")}><ExternalLink size={14} /></button>}{lead.task_id && <button className="icon-button" title="View Source Tasks" onClick={() => navigate(`task:${lead.task_id}`)}><Route size={14} /></button>}</div>
            {lead.poc && <button className="primary-button compact" disabled={running === runKey} onClick={() => executePoC(lead)}><Play size={13} />{running === runKey ? "Validation" : "Validation PoC"}</button>}
          </div>
        </article>;
      })}
    </div>
    <Pager page={page} totalPages={totalPages} setPage={setPage} />
    <Modal open={Boolean(noteEditor)}>{noteEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); updateTriage(noteEditor.lead, noteEditor.status, noteEditor.note); }}><div className="editor-head"><div><span className="eyebrow">Hunter note</span><h3>{noteEditor.lead.title}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setNoteEditor(null)}><X size={16} /></button></div><label>Triage status<select name="triage_status" value={noteEditor.status} onChange={(event) => setNoteEditor({ ...noteEditor, status: event.target.value })}>{leadStatusOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}</select></label><label>Personal notes<textarea name="triage_note" autoFocus rows="8" maxLength="5000" value={noteEditor.note} onChange={(event) => setNoteEditor({ ...noteEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setNoteEditor(null)}>Cancel</button><button className="primary-button">Save triage</button></div></form>}</Modal>
  </Panel>;
}
