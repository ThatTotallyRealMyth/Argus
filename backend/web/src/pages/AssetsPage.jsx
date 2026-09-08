import React, { useEffect, useState } from "react";
import { Activity, Clock3, Copy, Crosshair, Database, Edit3, ExternalLink, FileText, GitCompareArrows, Network, NotebookPen, Play, Route, ShieldAlert, Trash2, X } from "lucide-react";
import { Badge, DataTable, EmptyState, Modal, Pager, Panel, SelectAllCheckbox, Tabs } from "../components/ui.jsx";
import AdvancedSearch from "../components/AdvancedSearch.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, compactNumber, formatDate, parseJSON, severityClass } from "../lib/api.js";
import { assetPivot, assetTargetURL, leadSummary } from "../lib/assetWorkbench.js";
import { leadStatusLabel, leadStatusOptions, leadStatusTone, leadTypeLabel } from "../lib/leadQueue.js";
import { filtersToExpression } from "../lib/searchSyntax.js";
import { findingStatusLabel, findingStatusOptions, findingStatusTone, verificationResultLabel, verificationResultTone } from "../lib/findingWorkflow.js";
import { formatVulnerabilityEvidence, vulnerabilityEvidenceSections } from "../lib/vulnerabilityEvidence.js";

function riskTone(score) { return score >= 70 ? "danger" : score >= 45 ? "warn" : score > 0 ? "ok" : "muted"; }
function riskLabel(score) { return score >= 90 ? "Serious" : score >= 70 ? "High risk" : score >= 45 ? "- It's dangerous." : score > 0 ? "Low risk." : "Normal"; }
function matchTypeLabel(value) { return ({ hostname: "Hostname", host_ip: "Target IP", endpoint: "Service endpoint", exact_site: "Exact site", exact_url: "Exact URL", site_origin: "Same-origin site", poc_validated: "PoC validated" })[value] || value || "Association"; }
function changeFieldLabel(value) { return ({ domain: "Domain", ip_address: "IP", cdn: "CDN", takeover_vulnerable: "Takeover risk", takeover_service: "Takeover service", takeover_cname: "CNAME", takeover_severity: "Takeover severity", os: "Operating system", location: "Location", endpoint: "Endpoint", protocol: "Protocol", service: "Service", version: "Version", banner_sha256: "Banner", ssl_cert_sha256: "Certificate", url: "URL", title: "Title", status_code: "Status code", ip: "Site IP", content_type: "Content type", server: "Server", fingerprints: "Fingerprints", has_screenshot: "Screenshot" })[value] || value; }
function leadOpenURL(lead, asset) {
  const target = String(lead?.target || "");
  if (/^https?:\/\//i.test(target)) return target;
  if (lead?.type === "sensitive_service") return assetTargetURL({ kind: "port", display_value: target });
  if (target === asset?.display_value) return assetTargetURL(asset);
  return "";
}

function CatalogLeadPanel({ detail, runs, onCopy, onOpen, onTask, onExecute, onTriage, onNote }) {
  const leads = detail.leads || [];
  const summary = leadSummary(leads);
  return <div className="catalog-workbench-pane catalog-leads-pane">
    <div className="catalog-lead-summary">
      <div><span>Operational clues</span><strong>{summary.total}</strong></div>
      <div><span>Serious / High risk</span><strong>{summary.critical + summary.high}</strong></div>
      <div><span>Authenticable PoC</span><strong>{summary.poc}</strong></div>
      <div><span>Top priority</span><strong>{leads[0]?.priority || 0}</strong></div>
    </div>
    {leads.length ? <div className="attack-lead-list">{leads.map((lead) => {
      const run = runs[lead.id];
      const openURL = leadOpenURL(lead, detail.asset);
      return <article className={`attack-lead severity-${lead.severity || "info"}`} key={lead.id} data-testid={`attack-lead-${lead.type}`}>
        <div className="attack-lead-priority"><strong>{lead.priority}</strong><span>Priority</span></div>
        <div className="attack-lead-body">
          <div className="attack-lead-title"><Badge tone={severityClass[lead.severity] || "muted"}>{lead.severity}</Badge><Badge>{leadTypeLabel(lead.type)}</Badge><strong>{lead.title}</strong><span>Confidence {lead.confidence}%</span></div>
          <p>{lead.reason}</p>
          <div className="attack-lead-evidence">{(lead.evidence || []).map((item) => <span key={`${item.label}:${item.value}`}><small>{item.label}</small>{item.value}</span>)}</div>
          <div className="attack-lead-next"><Crosshair size={13} /><span>{lead.suggested_action}</span></div>
          {lead.triage_note && <div className="attack-lead-note"><NotebookPen size={12} /><span>{lead.triage_note}</span></div>}
          {run && <div className={run.state === "error" ? "lead-run-result error" : `lead-run-result ${run.result || ""}`}><strong>{run.state === "running" ? "Validating..." : run.state === "error" ? "Validation failed" : `Validate Results: ${run.result}`}</strong>{run.details && <span>{run.details}</span>}</div>}
        </div>
        <div className="attack-lead-actions">
          <select aria-label={`Update ${lead.title} Status`} value={lead.triage_status || "new"} onChange={(event) => onTriage(lead, event.target.value)}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
          <Badge tone={leadStatusTone(lead.triage_status)}>{leadStatusLabel(lead.triage_status)}</Badge>
          <button className="icon-button" title="Edit the notes" onClick={() => onNote(lead)}><NotebookPen size={14} /></button>
          <button className="icon-button" title="Copy Target" onClick={() => onCopy(lead.target)}><Copy size={14} /></button>
          {openURL && <button className="icon-button" title="Open Target" onClick={() => onOpen(openURL)}><ExternalLink size={14} /></button>}
          {lead.task_id && <button className="icon-button" title="View Source Tasks" onClick={() => onTask(lead.task_id)}><Route size={14} /></button>}
          {lead.poc && <button className="primary-button compact" disabled={run?.state === "running"} onClick={() => onExecute(lead)}><Play size={13} />Validation</button>}
        </div>
      </article>;
    })}</div> : <EmptyState text="The evidence is not yet actionable." />}
  </div>;
}

function CatalogEvidencePanel({ detail, onTask, onTriage, onNote }) {
  return <div className="catalog-workbench-pane">
    <section className="catalog-detail-section catalog-findings"><h4><ShieldAlert size={14} /> Plugging evidence.</h4>
      {detail.findings?.length ? detail.findings.map((finding) => <div className="catalog-evidence-record" key={finding.id}>
        <div className="catalog-finding-row"><Badge tone={severityClass[finding.severity] || "muted"}>{finding.severity}</Badge><div><strong>{finding.title || "Unnamed Fault"}</strong><span title={finding.url}>{finding.url}</span></div><small>{matchTypeLabel(finding.match_type)}</small><time>{formatDate(finding.created_at)}</time></div>
        <div className="catalog-finding-workflow"><Badge tone={findingStatusTone(finding.status)}>{findingStatusLabel(finding.status)}</Badge><select aria-label={`Update ${finding.title} Finding status`} value={finding.status || "new"} onChange={(event) => onTriage(finding, event.target.value)}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><Badge tone={verificationResultTone(finding.last_verification_result)}>{verificationResultLabel(finding.last_verification_result)}</Badge><time>{finding.last_verified_at ? formatDate(finding.last_verified_at) : "-"}</time><button className="icon-button" title="Edit Gaps" onClick={() => onNote(finding)}><NotebookPen size={14} /></button></div>
        {finding.triage_note && <div className="catalog-finding-note"><NotebookPen size={12} /><span>{finding.triage_note}</span></div>}
        {(finding.description || finding.payload || finding.proof) && <details><summary>View bug proof</summary><div className="catalog-proof-grid">{finding.description && <div><span>Description</span><pre>{finding.description}</pre></div>}{finding.payload && <div><span>Payload</span><pre>{finding.payload}</pre></div>}{finding.proof && <div><span>Proof</span><pre>{finding.proof}</pre></div>}</div></details>}
        {finding.task_id && <button className="link-button catalog-task-link" onClick={() => onTask(finding.task_id)}>Source missions {finding.task_id.slice(0, 8)}</button>}
      </div>) : <EmptyState text="There's no confirmation of the gaps." />}
    </section>
    <section className="catalog-detail-section"><h4><FileText size={14} /> Current snapshot</h4><pre>{JSON.stringify(parseJSON(detail.asset?.current_data, {}), null, 2)}</pre></section>
  </div>;
}

function CatalogRelationsPanel({ detail, onPivot, onOpen }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Route size={14} /> Asset relations</h4>
    {detail.relations?.length ? detail.relations.map((relation) => {
      const openURL = assetTargetURL(relation.asset);
      return <div className="catalog-relation-row" key={relation.id}><Badge>{relation.direction === "incoming" ? "Enter" : "Out"}</Badge><div><strong>{relation.relation_type}</strong><button className="link-button" onClick={() => onPivot(relation.asset)}>{relation.asset?.display_value || "Unknown assets"}</button></div><Badge tone={relation.asset?.risk_score > 0 ? "warn" : "muted"}>Risk {relation.asset?.risk_score || 0}</Badge><time>{formatDate(relation.last_seen_at)}</time><div className="row-actions"><button className="icon-button" title="Positioning associated assets" onClick={() => onPivot(relation.asset)}><Crosshair size={14} /></button>{openURL && <button className="icon-button" title="Open Associated Assets" onClick={() => onOpen(openURL)}><ExternalLink size={14} /></button>}</div></div>;
    }) : <EmptyState text="No assets at present" />}
  </section></div>;
}

function originLabel(originType, originID) { return `${originType === "enterprise_query" ? "Enterprise queries" : "Source missions"} ${originID?.slice(0, 8) || "-"}`; }

function CatalogChangesPanel({ detail, onOrigin }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section catalog-changes"><h4><GitCompareArrows size={14} /> Change Time Line</h4>
    {detail.changes?.length ? detail.changes.map((change) => <div className="catalog-change-record" key={change.id}><div className="catalog-change-row"><Badge tone={change.event_type === "modified" ? "warn" : "ok"}>{change.event_type === "modified" ? "Change" : "Found"}</Badge><div><strong>{change.event_type === "modified" ? "Change in asset status" : "Establishment of asset baselines"}</strong><span>{change.event_type === "modified" ? (change.changed_fields || []).map(changeFieldLabel).join(", ") : "First main observation"}</span></div><button className="link-button" onClick={() => onOrigin(change.task_id, change.origin_type)}>{originLabel(change.origin_type, change.task_id)}</button><time>{formatDate(change.observed_at)}</time></div>
      {change.event_type === "modified" && <details><summary>Recomp with the status before and after</summary><div className="catalog-diff-grid"><div><span>Before</span><pre>{JSON.stringify(parseJSON(change.before_data, {}), null, 2)}</pre></div><div><span>After</span><pre>{JSON.stringify(parseJSON(change.after_data, {}), null, 2)}</pre></div></div></details>}
    </div>) : <EmptyState text="No change recorded" />}
  </section></div>;
}

function CatalogObservationsPanel({ detail, onOrigin }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Clock3 size={14} /> Observation history</h4>
    {detail.observations?.length ? detail.observations.map((observation) => <div className="catalog-observation-row" key={observation.id}><div className="history-row"><Badge>{observation.source_type}</Badge><button className="link-button" onClick={() => onOrigin(observation.task_id, observation.origin_type)}>{originLabel(observation.origin_type, observation.task_id)}</button><time>{formatDate(observation.observed_at)}</time></div><details><summary>View this observation</summary><pre>{JSON.stringify(parseJSON(observation.payload, {}), null, 2)}</pre></details></div>) : <EmptyState text="No observations recorded" />}
  </section></div>;
}

function verificationLabel(value) { return ({ vulnerable: "Hit!", safe: "Missed.", error: "Failed" })[value] || value || "Unknown"; }
function verificationTone(value) { return value === "vulnerable" || value === "error" ? "danger" : value === "safe" ? "ok" : "muted"; }

function CatalogExecutionsPanel({ detail, onTask }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Activity size={14} /> Validate records</h4>
    {detail.executions?.length ? detail.executions.map((execution) => <div className="catalog-execution-record" key={execution.id}>
      <div className="catalog-execution-row"><Badge tone={verificationTone(execution.result)}>{verificationLabel(execution.result)}</Badge><div><strong>{execution.target}</strong><span>PoC {execution.poc_id?.slice(0, 8) || "-"} · {execution.invocation_source === "mcp" ? "MCP" : "Web"}</span></div><div className="catalog-execution-badges">{execution.vulnerability_id && <Badge tone={execution.result === "vulnerable" ? "danger" : "accent"}>{execution.result === "vulnerable" ? "Evidence hit." : "Association Reaction"}</Badge>}{execution.scope_id ? <Badge tone="ok">Delegation of authority {execution.scope_id.slice(0, 8)}</Badge> : <Badge tone="warn">Compatibility Mode</Badge>}</div><time>{formatDate(execution.created_at)}</time>{execution.task_id ? <button className="link-button" onClick={() => onTask(execution.task_id)}>Tasks {execution.task_id.slice(0, 8)}</button> : <span />}</div>
      {execution.details && <details><summary>View Validation</summary><pre>{execution.details}</pre></details>}
    </div>) : <EmptyState text="Not implemented PoC Validation" />}
  </section></div>;
}

function VulnerabilityEvidenceEditor({ finding, onClose, onSave, onCopy }) {
  const [draft, setDraft] = useState(() => ({ ...finding }));
  useEffect(() => setDraft({ ...finding }), [finding?.id]);
  if (!finding) return null;
  const sections = vulnerabilityEvidenceSections(draft);
  return <form className="library-editor risk-evidence-editor" onSubmit={(event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    onSave(String(formData.get("finding_status") || "new"), String(formData.get("finding_note") || ""));
  }}>
    <div className="editor-head"><div><span className="eyebrow"><ShieldAlert size={14} /> Confirmed evidence</span><h3>{draft.title || "Unnamed risk"}</h3></div><button type="button" className="icon-button" title="Close" onClick={onClose}><X size={16} /></button></div>
    <div className="risk-evidence-meta"><Badge tone={severityClass[draft.severity] || "muted"}>{draft.severity || "info"}</Badge><Badge tone={findingStatusTone(draft.status)}>{findingStatusLabel(draft.status)}</Badge><Badge tone={verificationResultTone(draft.last_verification_result)}>{verificationResultLabel(draft.last_verification_result)}</Badge><time>{draft.last_verified_at ? formatDate(draft.last_verified_at) : formatDate(draft.created_at)}</time></div>
    <div className="risk-evidence-target"><div><span>Objective</span><strong>{draft.url || "-"}</strong></div>{draft.url && <button type="button" className="icon-button" title="Copy Target" onClick={() => onCopy(draft.url, "Objective")}><Copy size={15} /></button>}</div>
    <div className="risk-evidence-triage"><label>Finding status<select name="finding_status" value={draft.status || "new"} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>Triage notes<textarea name="finding_note" rows="4" maxLength="5000" value={draft.triage_note || ""} onChange={(event) => setDraft({ ...draft, triage_note: event.target.value })} /></label></div>
    <div className="risk-evidence-sections">{sections.length ? sections.map((section) => <section key={section.key}><div><span>{section.label}</span><button type="button" className="icon-button" title={`Copy${section.label}`} aria-label={`Copy${section.label}`} onClick={() => onCopy(section.value, section.label)}><Copy size={14} /></button></div><pre>{section.value}</pre></section>) : <EmptyState text="No description, payload, or proof is available" />}</div>
    <div className="editor-actions"><button type="button" className="ghost-button" onClick={onClose}>Close</button><button type="submit" className="ghost-button">Save triage</button><button type="button" className="primary-button" onClick={() => onCopy(formatVulnerabilityEvidence(draft), "Complete evidence")}><Copy size={15} />Copy All Evidence</button></div>
  </form>;
}

export default function AssetsPage({ setPage: navigate }) {
  const [tab, setTab] = useState("inventory");
  const [page, setPage] = useState(1);
  const [searches, setSearches] = useState({});
  const [columnFilters, setColumnFilters] = useState({});
  const [groupEditor, setGroupEditor] = useState(null);
  const [groupDetail, setGroupDetail] = useState(null);
  const [assigning, setAssigning] = useState(null);
  const [catalogDetail, setCatalogDetail] = useState(null);
  const [catalogDetailTab, setCatalogDetailTab] = useState("leads");
  const [leadRuns, setLeadRuns] = useState({});
  const [workbenchMessage, setWorkbenchMessage] = useState("");
  const [triageEditor, setTriageEditor] = useState(null);
  const [findingEditor, setFindingEditor] = useState(null);
  const [globalFindingDetail, setGlobalFindingDetail] = useState(null);
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [batchGroupID, setBatchGroupID] = useState("");
  const [groupRefresh, setGroupRefresh] = useState(0);
  const [message, setMessage] = useState("");
  const search = searches[tab] || "";
  const params = new URLSearchParams({ page, page_size: 20 });
  const combinedSearch = [search, filtersToExpression(columnFilters[tab] || {})].filter(Boolean).join(" && ");
  if (combinedSearch) params.set("q", combinedSearch);
  const endpoint = tab === "inventory" ? "/assets/inventory" : tab === "groups" ? "/asset-groups" : tab === "vulnerabilities" ? "/assets/vulnerabilities" : `/assets/${tab}`;
  const { data, loading, error } = useQuery(`assets-${tab}-${page}-${combinedSearch}-${groupRefresh}`, () => api(`${endpoint}?${params}`));
  const { data: groupOptions } = useQuery(`asset-group-options-${groupRefresh}`, () => api("/asset-groups"));
  const { data: catalogStats } = useQuery(`asset-catalog-stats-${groupRefresh}`, () => api("/assets/inventory/stats"));

  useEffect(() => {
    const assetID = new URLSearchParams(window.location.search).get("asset");
    if (!assetID) return;
    openCatalogAssetByID(assetID);
    window.history.replaceState({}, "", "/assets");
  }, []);

  async function saveGroup(event) { event.preventDefault(); try { await api(`/asset-groups${groupEditor.id ? `/${groupEditor.id}` : ""}`, { method: groupEditor.id ? "PUT" : "POST", body: JSON.stringify(groupEditor) }); setGroupEditor(null); setMessage("Asset group saved"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`Save failed: ${error.message}`); } }
  async function removeGroup(group) { if (!window.confirm(`Remove Group"${group.name}"and its membership?`)) return; try { await api(`/asset-groups/${group.id}`, { method: "DELETE" }); setMessage("Asset group deleted"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`Delete failed: ${error.message}`); } }
  async function openGroup(group) { try { const result = await api(`/asset-groups/${group.id}/items`); setGroupDetail({ ...group, items: result.items || [] }); } catch (error) { setMessage(`Failed to load group members: ${error.message}`); } }
  async function removeGroupMember(item) { try { await api(`/asset-groups/${groupDetail.id}/items/${item.id}`, { method: "DELETE" }); setGroupDetail({ ...groupDetail, items: groupDetail.items.filter((member) => member.id !== item.id) }); setMessage("Group member removed"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`Removal failed: ${error.message}`); } }
  async function assignGroup(event) { event.preventDefault(); try { await api(`/asset-groups/${assigning.group_id}/items`, { method: "POST", body: JSON.stringify({ asset_type: assigning.asset_type, asset_ids: [assigning.asset_id] }) }); setAssigning(null); setMessage("Asset added to the group"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`Could not add asset to group: ${error.message}`); } }
  async function assignSelectedGroup() { const groupID = batchGroupID || groupOptions?.groups?.[0]?.id; if (!selectedIDs.length || !groupID) return; try { const result = await api(`/asset-groups/${groupID}/items`, { method: "POST", body: JSON.stringify({ asset_type: "canonical", asset_ids: selectedIDs }) }); setMessage(`Added ${result.created_count || 0} global assets to the group${result.skipped?.length ? `; skipped ${result.skipped.length}` : ""}`); setSelectedIDs([]); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`Batch add failed: ${error.message}`); } }
  async function openCatalogAssetByID(assetID, asset = null) { try { setCatalogDetailTab("leads"); setLeadRuns({}); setWorkbenchMessage(""); setCatalogDetail({ asset: asset || { id: assetID, display_value: "Loading assets..." }, loading: true }); const result = await api(`/assets/inventory/${assetID}`); setCatalogDetail({ ...result, loading: false }); } catch (error) { setCatalogDetail(null); setMessage(`Failed to load asset details: ${error.message}`); } }
  async function openCatalogAsset(asset) { return openCatalogAssetByID(asset.id, asset); }
  async function copyWorkbenchValue(value) { try { await navigator.clipboard.writeText(value); setWorkbenchMessage("Target copied"); } catch { setWorkbenchMessage("Copy Failed, Please choose your target manually."); } }
  function openWorkbenchURL(url) { window.open(url, "_blank", "noopener,noreferrer"); }
  function pivotToAsset(asset) { const pivot = assetPivot(asset); setCatalogDetail(null); setTab(pivot.tab); setSearches((current) => ({ ...current, [pivot.tab]: pivot.search })); setPage(1); setSelectedIDs([]); }
  function openSourceTask(taskID) { if (!taskID) return; setCatalogDetail(null); navigate(`task:${taskID}`); }
  function openCatalogOrigin(originID, originType) { if (!originID) return; setCatalogDetail(null); navigate(originType === "enterprise_query" ? "enterprise" : `task:${originID}`); }
  async function updateLeadTriage(lead, status, note = lead.triage_note || "") {
    try {
      const result = await api("/assets/leads/triage", { method: "PUT", body: JSON.stringify({ asset_id: lead.asset_id || catalogDetail.asset.id, lead_id: lead.id, status, note }) });
      setCatalogDetail((current) => ({ ...current, leads: current.leads.map((item) => item.id === lead.id ? { ...item, triage_status: result.triage.status, triage_note: result.triage.note, triage_updated_at: result.triage.updated_at } : item) }));
      setWorkbenchMessage(`Thread updated as${leadStatusLabel(status)}`);
      setTriageEditor(null);
    } catch (error) { setWorkbenchMessage(`Update failed: ${error.message}`); }
  }
  async function executeLeadPoC(lead) {
    if (!lead.poc || !window.confirm(`Use"${lead.poc.name}"Validate Target ${lead.target}?`)) return;
    setLeadRuns((current) => ({ ...current, [lead.id]: { state: "running" } }));
    try {
      const result = await api("/assets/leads/execute-poc", { method: "POST", body: JSON.stringify({ asset_id: lead.asset_id || catalogDetail.asset.id, lead_id: lead.id, confirm: true }) });
      setLeadRuns((current) => ({ ...current, [lead.id]: { state: "done", result: result.result, details: result.details || result.message } }));
      const assetID = lead.asset_id || catalogDetail.asset.id;
      try {
        const refreshed = await api(`/assets/inventory/${assetID}`);
        setCatalogDetail({ ...refreshed, loading: false });
      } catch {
        setCatalogDetail((current) => ({ ...current, executions: [result.execution_log, ...(current.executions || []).filter((item) => item.id !== result.execution_log.id)] }));
      }
      setCatalogDetailTab(result.result === "vulnerable" ? "evidence" : "executions");
      setWorkbenchMessage(result.result === "vulnerable" ? `Verify hit, ${result.finding_created ? "Recorded" : "Updated"}; finding evidence is ready for submission` : result.finding ? `Retest complete: ${verificationLabel(result.result)}, Finding evidence was retained and its retest status was updated` : `Validation complete: ${verificationLabel(result.result)}, The result was written to the audit trail`);
    } catch (error) {
      const execution = error.payload?.execution_log;
      if (execution) setCatalogDetail((current) => ({ ...current, executions: [execution, ...(current.executions || []).filter((item) => item.id !== execution.id)] }));
      setLeadRuns((current) => ({ ...current, [lead.id]: { state: "error", details: error.payload?.details || error.message } }));
      setWorkbenchMessage(`Validation failed: ${error.message}`);
    }
  }

  async function updateFindingTriage(finding, status, note = finding.triage_note || "") {
    try {
      await api(`/assets/vulnerabilities/${finding.vulnerability_id}/triage`, { method: "PUT", body: JSON.stringify({ status, note }) });
      const refreshed = await api(`/assets/inventory/${catalogDetail.asset.id}`);
      setCatalogDetail({ ...refreshed, loading: false });
      setGroupRefresh((value) => value + 1);
      setWorkbenchMessage(`The bug has been updated as${findingStatusLabel(status)}${["resolved", "false_positive"].includes(status) ? ", Asset risk recalculated" : ""}`);
      setFindingEditor(null);
    } catch (error) { setWorkbenchMessage(`Update failed: ${error.message}`); }
  }

  async function saveGlobalFindingTriage(status, note) {
    if (!globalFindingDetail) return;
    try {
      const result = await api(`/assets/vulnerabilities/${globalFindingDetail.id}/triage`, { method: "PUT", body: JSON.stringify({ status, note }) });
      setGlobalFindingDetail(result.finding || { ...globalFindingDetail, status, triage_note: note });
      setMessage(`The bug has been updated as${findingStatusLabel(status)}`);
      setGroupRefresh((value) => value + 1);
    } catch (error) { setMessage(`Update failed: ${error.message}`); }
  }

  async function copyFindingValue(value, label) {
    if (!value) return;
    try { await navigator.clipboard.writeText(value); setMessage(`Copyed${label}`); }
    catch { setMessage("Copy Failed: No clipboard privileges were granted by browser"); }
  }

  const inventoryAssets = data?.assets || [];
  const visibleInventoryIDs = inventoryAssets.map((asset) => asset.id);
  const inventorySelect = (asset) => <input key="select" className="row-check" type="checkbox" aria-label={`Select ${asset.display_value}`} checked={selectedIDs.includes(asset.id)} onChange={() => setSelectedIDs((current) => current.includes(asset.id) ? current.filter((id) => id !== asset.id) : [...current, asset.id])} />;
  const rows = {
    inventory: inventoryAssets.map((x) => [inventorySelection(x), <Badge key="kind" tone={x.kind === "site" ? "ok" : x.kind === "port" ? "warn" : "muted"}>{x.kind}</Badge>, <button key="value" className="link-button" onClick={() => openCatalogAsset(x)}>{x.display_value}</button>, <Badge key="risk" tone={riskTone(x.risk_score)}>{riskLabel(x.risk_score)} · {x.risk_score}</Badge>, compactNumber(x.vulnerability_count), compactNumber(x.change_count), compactNumber(x.observation_count), formatDate(x.last_seen_at)]),
    domains: (data?.domains || []).map((x) => [x.domain, x.ip_address || "-", x.source || "-", formatDate(x.created_at), <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "domain", asset_id: x.id, label: x.domain, group_id: groupOptions.groups[0]?.id || "" })}>Add Group</button>]),
    ips: (data?.ips || []).map((x) => [x.ip_address, x.domain || "-", x.location || "-", formatDate(x.created_at), <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "ip", asset_id: x.id, label: x.ip_address, group_id: groupOptions.groups[0]?.id || "" })}>Add Group</button>]),
    ports: (data?.ports || []).map((x) => [x.ip_address, x.port, x.service || "-", x.banner || "-"]),
    sites: (data?.sites || []).map((x) => [x.url, x.status_code, x.title || "-", x.fingerprint || "-", <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "site", asset_id: x.id, label: x.url, group_id: groupOptions.groups[0]?.id || "" })}>Add Group</button>]),
    urls: (data?.urls || []).map((x) => [x.method || "GET", x.url, x.status_code, x.content_length]),
    vulnerabilities: (data?.vulnerabilities || []).map((x) => [<Badge key="sev" tone={severityClass[x.severity] || "muted"}>{x.severity}</Badge>, <Badge key="status" tone={findingStatusTone(x.status)}>{findingStatusLabel(x.status)}</Badge>, x.title, x.url, x.type, <button key="view" type="button" className="ghost-button compact" onClick={() => setGlobalFindingDetail(x)}><FileText size={13} />View</button>]),
    groups: (data?.groups || []).map((x) => [<button key="name" className="link-button" onClick={() => openGroup(x)}>{x.name}</button>, x.description || "-", x.member_count || 0, formatDate(x.updated_at), <div className="row-actions" key="actions"><button className="icon-button" title="Edit" onClick={() => setGroupEditor({ id: x.id, name: x.name, description: x.description || "" })}><Edit3 size={14} /></button><button className="icon-button danger" title="Delete" onClick={() => removeGroup(x)}><Trash2 size={14} /></button></div>]),
  }[tab];
  const columns = {
    inventory: ["Selection", "Type", "Asset", "Risk", "Findings", "Changes", "Observations", "Last seen"],
    domains: ["Domain name", "IP", "Source", "Time", "Group"],
    ips: ["IP", "Domain name", "Location", "Time", "Group"],
    ports: ["IP", "Port", "Services", "Banner"],
    sites: ["URL", "Status", "Title", "Fingerprints", "Group"],
    urls: ["Methodology", "URL", "Status", "Length"],
    vulnerabilities: ["Level", "Status", "Title", "URL", "Type", "Actions"],
    groups: ["Group Name", "Description", "Number of members", "Updated", "Actions"],
  }[tab];
  const searchFields = {
    inventory: ["kind", "value", "status", "risk", "vulnerabilities", "changes", "observations"],
    domains: ["domain", "ip", "source", "takeover"], ips: ["ip", "domain", "source", "os", "location"],
    ports: ["ip", "port", "protocol", "service", "version", "banner"], sites: ["url", "title", "status", "ip", "type", "server", "fingerprint"],
    urls: ["url", "method", "status", "type", "source"], vulnerabilities: ["severity", "status", "title", "url", "type", "source", "description"], groups: ["name", "description"],
  }[tab];
  const tableFilterKeys = {
    inventory: ["", "kind", "value", "risk", "vulnerabilities", "changes", "observations", ""],
    domains: ["domain", "ip", "source", "", ""], ips: ["ip", "domain", "location", "", ""],
    ports: ["ip", "port", "service", "banner"], sites: ["url", "status", "title", "fingerprint", ""],
    urls: ["method", "url", "status", ""], vulnerabilities: ["severity", "status", "title", "url", "type", ""], groups: ["name", "description", "", "", ""],
  }[tab];

  return (
    <Panel title="Asset Browser" icon={<Network size={17} />}>
      <div className="toolbar">
        <Tabs value={tab} setValue={(v) => { setTab(v); setPage(1); setMessage(""); setSelectedIDs([]); }} items={["inventory", "domains", "ips", "ports", "sites", "urls", "vulnerabilities", "groups"]} labels={{ inventory: "Global assets", domains: "Domains", ips: "IPs", ports: "Ports", sites: "Sites", urls: "URLs", vulnerabilities: "Findings", groups: "Groups" }} />
        <AdvancedSearch key={tab} value={search} fields={searchFields} placeholder="Search assets, Support &&, ||, ! and field limits" onApply={(value) => { setSearches((current) => ({ ...current, [tab]: value })); setPage(1); }} />
        {tab === "groups" && <button className="primary-button" onClick={() => setGroupEditor({ id: "", name: "", description: "" })}><Plus size={15} />New Group</button>}
      </div>
      {error && <div className="error-box">Failed to load: {error}</div>}{message && <div className={message.includes("Failed") ? "error-box" : "success-box"}>{message}</div>}
      {tab === "inventory" && <div className="asset-catalog-strip">{[["Total assets", "total"], ["Domains", "domains"], ["IPs", "ips"], ["Ports", "ports"], ["Sites", "sites"], ["URLs", "urls"], ["At-risk assets", "at_risk"], ["Change events", "changes"], ["Finding links", "vulnerability_links"], ["Asset relationships", "relations"]].map(([label, key]) => <div key={key}><span>{label}</span><strong>{compactNumber(catalogStats?.[key])}</strong></div>)}</div>}
      {tab === "inventory" && <div className="task-toolbar"><div className="row-actions task-batch-actions"><select name="batch_group_id" aria-label="Target asset grouping" value={batchGroupID || groupOptions?.groups?.[0]?.id || ""} disabled={!groupOptions?.groups?.length} onChange={(event) => setBatchGroupID(event.target.value)}>{(groupOptions?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="primary-button" disabled={!selectedIDs.length || !groupOptions?.groups?.length} onClick={assignSelectedGroup}>Add Group{selectedIDs.length ? ` (${selectedIDs.length})` : ""}</button></div></div>}
      <DataTable storageKey={`assets-${tab}`} loading={loading} columns={columns} rows={rows} filterKeys={tableFilterKeys} filters={columnFilters[tab] || {}} filterOptions={{ severity: ["critical", "high", "medium", "low", "info"], kind: ["domain", "ip", "port", "site", "url"] }} onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [tab]: { ...(current[tab] || {}), [key]: value } })); setPage(1); }} headerCells={tab === "inventory" ? { 0: <SelectAllCheckbox ids={visibleInventoryIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="Global assets on this page" /> } : {}} selectionColumn={tab === "inventory"} empty={tab === "groups" ? "No assets grouping available" : "Assets not available"} />
      <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPage} />
      <Modal open={Boolean(groupEditor)}>{groupEditor && <form className="library-editor proxy-editor" onSubmit={saveGroup}><div className="editor-head"><div><span className="eyebrow">Asset scope</span><h3>{groupEditor.id ? "Edit Group" : "New Group"}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setGroupEditor(null)}><X size={16} /></button></div><label>Group Name<input required value={groupEditor.name} onChange={(e) => setGroupEditor({ ...groupEditor, name: e.target.value })} /></label><label>Description<textarea rows="4" value={groupEditor.description} onChange={(e) => setGroupEditor({ ...groupEditor, description: e.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setGroupEditor(null)}>Cancel</button><button className="primary-button">Save Group</button></div></form>}</Modal>
      <Modal open={Boolean(groupDetail)}>{groupDetail && <div className="library-editor automation-detail"><div className="editor-head"><div><span className="eyebrow">Group members</span><h3>{groupDetail.name}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setGroupDetail(null)}><X size={16} /></button></div>{groupDetail.items.length ? groupDetail.items.map((item) => <div className="history-row member-row" key={item.id}><Badge>{item.asset_source === "catalog" ? "Global" : "Tasks"} · {item.kind || item.asset_type}</Badge><span title={item.asset_id}>{item.label || item.asset_id}</span><time>{formatDate(item.created_at)}</time><button className="icon-button danger" title="Move Out Group" onClick={() => removeGroupMember(item)}><Trash2 size={14} /></button></div>) : <EmptyState text="No assets in the group" />}</div>}</Modal>
      <Modal open={Boolean(assigning)}>{assigning && <form className="library-editor proxy-editor" onSubmit={assignGroup}><div className="editor-head"><div><span className="eyebrow">Assign asset</span><h3>Add asset group</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setAssigning(null)}><X size={16} /></button></div><div className="hint">{assigning.label}</div><label>Target group<select value={assigning.group_id} onChange={(e) => setAssigning({ ...assigning, group_id: e.target.value })}>{(groupOptions?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setAssigning(null)}>Cancel</button><button className="primary-button">Confirmed accession</button></div></form>}</Modal>
      <Modal open={Boolean(catalogDetail)}>{catalogDetail && <div className="library-editor catalog-detail">
        <div className="editor-head catalog-workbench-head"><div><span className="eyebrow"><Database size={14} /> Attack surface workbench</span><h3>{catalogDetail.asset?.display_value}</h3></div><div className="row-actions"><button type="button" className="icon-button" title="Copy Current Assets" onClick={() => copyWorkbenchValue(catalogDetail.asset?.display_value)}><Copy size={16} /></button>{assetTargetURL(catalogDetail.asset) && <button type="button" className="icon-button" title="Open current asset" onClick={() => openWorkbenchURL(assetTargetURL(catalogDetail.asset))}><ExternalLink size={16} /></button>}<button type="button" className="icon-button" title="Positioning to Classified Assets" onClick={() => pivotToAsset(catalogDetail.asset)}><Crosshair size={16} /></button><button type="button" className="icon-button" title="Close" onClick={() => setCatalogDetail(null)}><X size={16} /></button></div></div>
        {catalogDetail.loading ? <div className="route-loading"><span className="status-dot" />Loading attack leads...</div> : <>
          <div className="catalog-detail-metrics"><div><span>Type</span><strong>{catalogDetail.asset?.kind}</strong></div><div><span>Risk</span><strong><Badge tone={riskTone(catalogDetail.asset?.risk_score)}>{riskLabel(catalogDetail.asset?.risk_score)} · {catalogDetail.asset?.risk_score}</Badge></strong></div><div><span>Leaks</span><strong>{compactNumber(catalogDetail.asset?.vulnerability_count)}</strong></div><div><span>Change</span><strong>{compactNumber(catalogDetail.asset?.change_count)}</strong></div><div><span>Observation</span><strong>{compactNumber(catalogDetail.asset?.observation_count)}</strong></div><div><span>Last found</span><strong>{formatDate(catalogDetail.asset?.last_seen_at)}</strong></div></div>
          {workbenchMessage && <div className={workbenchMessage.includes("Failed") ? "error-box workbench-message" : "success-box workbench-message"}>{workbenchMessage}</div>}
          <div className="catalog-workbench-tabs"><Tabs value={catalogDetailTab} setValue={setCatalogDetailTab} items={["leads", "evidence", "executions", "relations", "changes", "observations"]} labels={{ leads: `Threads ${catalogDetail.leads?.length || 0}`, evidence: `Evidence ${catalogDetail.findings?.length || 0}`, executions: `Validation ${catalogDetail.executions?.length || 0}`, relations: `Relations ${catalogDetail.relations?.length || 0}`, changes: `Change ${catalogDetail.changes?.length || 0}`, observations: `Observation ${catalogDetail.observations?.length || 0}` }} /></div>
          {catalogDetailTab === "leads" && <CatalogLeadPanel detail={catalogDetail} runs={leadRuns} onCopy={copyWorkbenchValue} onOpen={openWorkbenchURL} onTask={openSourceTask} onExecute={executeLeadPoC} onTriage={updateLeadTriage} onNote={(lead) => setTriageEditor({ lead, status: lead.triage_status || "new", note: lead.triage_note || "" })} />}
          {catalogDetailTab === "evidence" && <CatalogEvidencePanel detail={catalogDetail} onTask={openSourceTask} onTriage={updateFindingTriage} onNote={(finding) => setFindingEditor({ finding, status: finding.status || "new", note: finding.triage_note || "" })} />}
          {catalogDetailTab === "executions" && <CatalogExecutionsPanel detail={catalogDetail} onTask={openSourceTask} />}
          {catalogDetailTab === "relations" && <CatalogRelationsPanel detail={catalogDetail} onPivot={pivotToAsset} onOpen={openWorkbenchURL} />}
          {catalogDetailTab === "changes" && <CatalogChangesPanel detail={catalogDetail} onOrigin={openCatalogOrigin} />}
          {catalogDetailTab === "observations" && <CatalogObservationsPanel detail={catalogDetail} onOrigin={openCatalogOrigin} />}
        </>}
      </div>}</Modal>
      <Modal open={Boolean(triageEditor)}>{triageEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); const formData = new FormData(event.currentTarget); updateLeadTriage(triageEditor.lead, String(formData.get("lead_status") || "new"), String(formData.get("lead_note") || "")); }}><div className="editor-head"><div><span className="eyebrow">Hunter note</span><h3>{triageEditor.lead.title}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setTriageEditor(null)}><X size={16} /></button></div><label>Triage status<select name="lead_status" value={triageEditor.status} onChange={(event) => setTriageEditor({ ...triageEditor, status: event.target.value })}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>Personal notes<textarea name="lead_note" autoFocus rows="8" maxLength="5000" value={triageEditor.note} onChange={(event) => setTriageEditor({ ...triageEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setTriageEditor(null)}>Cancel</button><button className="primary-button">Save triage</button></div></form>}</Modal>
      <Modal open={Boolean(findingEditor)}>{findingEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); const formData = new FormData(event.currentTarget); updateFindingTriage(findingEditor.finding, String(formData.get("finding_status") || "new"), String(formData.get("finding_note") || "")); }}><div className="editor-head"><div><span className="eyebrow">Finding workflow</span><h3>{findingEditor.finding.title}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setFindingEditor(null)}><X size={16} /></button></div><label>Finding status<select name="finding_status" value={findingEditor.status} onChange={(event) => setFindingEditor({ ...findingEditor, status: event.target.value })}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>Triage notes<textarea name="finding_note" autoFocus rows="8" maxLength="5000" value={findingEditor.note} onChange={(event) => setFindingEditor({ ...findingEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setFindingEditor(null)}>Cancel</button><button className="primary-button">Save finding</button></div></form>}</Modal>
      <Modal open={Boolean(globalFindingDetail)}>{globalFindingDetail && <VulnerabilityEvidenceEditor finding={globalFindingDetail} onClose={() => setGlobalFindingDetail(null)} onSave={saveGlobalFindingTriage} onCopy={copyFindingValue} />}</Modal>
    </Panel>
  );
}
