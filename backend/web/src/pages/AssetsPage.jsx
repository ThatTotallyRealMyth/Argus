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
function riskLabel(score) { return score >= 90 ? "严重" : score >= 70 ? "高危" : score >= 45 ? "中危" : score > 0 ? "低危" : "正常"; }
function matchTypeLabel(value) { return ({ hostname: "主机名", host_ip: "目标 IP", endpoint: "服务端点", exact_site: "精确站点", exact_url: "精确 URL", site_origin: "同源站点", poc_validated: "PoC 验证" })[value] || value || "关联"; }
function changeFieldLabel(value) { return ({ domain: "域名", ip_address: "IP", cdn: "CDN", takeover_vulnerable: "接管风险", takeover_service: "接管服务", takeover_cname: "CNAME", takeover_severity: "接管级别", os: "操作系统", location: "位置", endpoint: "端点", protocol: "协议", service: "服务", version: "版本", banner_sha256: "Banner", ssl_cert_sha256: "证书", url: "URL", title: "标题", status_code: "状态码", ip: "站点 IP", content_type: "内容类型", server: "Server", fingerprints: "指纹", has_screenshot: "截图" })[value] || value; }
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
      <div><span>行动线索</span><strong>{summary.total}</strong></div>
      <div><span>严重 / 高危</span><strong>{summary.critical + summary.high}</strong></div>
      <div><span>可验证 PoC</span><strong>{summary.poc}</strong></div>
      <div><span>最高优先级</span><strong>{leads[0]?.priority || 0}</strong></div>
    </div>
    {leads.length ? <div className="attack-lead-list">{leads.map((lead) => {
      const run = runs[lead.id];
      const openURL = leadOpenURL(lead, detail.asset);
      return <article className={`attack-lead severity-${lead.severity || "info"}`} key={lead.id} data-testid={`attack-lead-${lead.type}`}>
        <div className="attack-lead-priority"><strong>{lead.priority}</strong><span>优先级</span></div>
        <div className="attack-lead-body">
          <div className="attack-lead-title"><Badge tone={severityClass[lead.severity] || "muted"}>{lead.severity}</Badge><Badge>{leadTypeLabel(lead.type)}</Badge><strong>{lead.title}</strong><span>置信度 {lead.confidence}%</span></div>
          <p>{lead.reason}</p>
          <div className="attack-lead-evidence">{(lead.evidence || []).map((item) => <span key={`${item.label}:${item.value}`}><small>{item.label}</small>{item.value}</span>)}</div>
          <div className="attack-lead-next"><Crosshair size={13} /><span>{lead.suggested_action}</span></div>
          {lead.triage_note && <div className="attack-lead-note"><NotebookPen size={12} /><span>{lead.triage_note}</span></div>}
          {run && <div className={run.state === "error" ? "lead-run-result error" : `lead-run-result ${run.result || ""}`}><strong>{run.state === "running" ? "正在验证..." : run.state === "error" ? "验证失败" : `验证结果：${run.result}`}</strong>{run.details && <span>{run.details}</span>}</div>}
        </div>
        <div className="attack-lead-actions">
          <select aria-label={`更新 ${lead.title} 状态`} value={lead.triage_status || "new"} onChange={(event) => onTriage(lead, event.target.value)}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
          <Badge tone={leadStatusTone(lead.triage_status)}>{leadStatusLabel(lead.triage_status)}</Badge>
          <button className="icon-button" title="编辑研判笔记" onClick={() => onNote(lead)}><NotebookPen size={14} /></button>
          <button className="icon-button" title="复制目标" onClick={() => onCopy(lead.target)}><Copy size={14} /></button>
          {openURL && <button className="icon-button" title="打开目标" onClick={() => onOpen(openURL)}><ExternalLink size={14} /></button>}
          {lead.task_id && <button className="icon-button" title="查看来源任务" onClick={() => onTask(lead.task_id)}><Route size={14} /></button>}
          {lead.poc && <button className="primary-button compact" disabled={run?.state === "running"} onClick={() => onExecute(lead)}><Play size={13} />验证</button>}
        </div>
      </article>;
    })}</div> : <EmptyState text="当前证据尚未形成可行动线索" />}
  </div>;
}

function CatalogEvidencePanel({ detail, onTask, onTriage, onNote }) {
  return <div className="catalog-workbench-pane">
    <section className="catalog-detail-section catalog-findings"><h4><ShieldAlert size={14} /> 漏洞证据</h4>
      {detail.findings?.length ? detail.findings.map((finding) => <div className="catalog-evidence-record" key={finding.id}>
        <div className="catalog-finding-row"><Badge tone={severityClass[finding.severity] || "muted"}>{finding.severity}</Badge><div><strong>{finding.title || "未命名漏洞"}</strong><span title={finding.url}>{finding.url}</span></div><small>{matchTypeLabel(finding.match_type)}</small><time>{formatDate(finding.created_at)}</time></div>
        <div className="catalog-finding-workflow"><Badge tone={findingStatusTone(finding.status)}>{findingStatusLabel(finding.status)}</Badge><select aria-label={`更新 ${finding.title} 漏洞状态`} value={finding.status || "new"} onChange={(event) => onTriage(finding, event.target.value)}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><Badge tone={verificationResultTone(finding.last_verification_result)}>{verificationResultLabel(finding.last_verification_result)}</Badge><time>{finding.last_verified_at ? formatDate(finding.last_verified_at) : "-"}</time><button className="icon-button" title="编辑漏洞研判" onClick={() => onNote(finding)}><NotebookPen size={14} /></button></div>
        {finding.triage_note && <div className="catalog-finding-note"><NotebookPen size={12} /><span>{finding.triage_note}</span></div>}
        {(finding.description || finding.payload || finding.proof) && <details><summary>查看漏洞证明</summary><div className="catalog-proof-grid">{finding.description && <div><span>描述</span><pre>{finding.description}</pre></div>}{finding.payload && <div><span>Payload</span><pre>{finding.payload}</pre></div>}{finding.proof && <div><span>Proof</span><pre>{finding.proof}</pre></div>}</div></details>}
        {finding.task_id && <button className="link-button catalog-task-link" onClick={() => onTask(finding.task_id)}>来源任务 {finding.task_id.slice(0, 8)}</button>}
      </div>) : <EmptyState text="暂无确认漏洞证据" />}
    </section>
    <section className="catalog-detail-section"><h4><FileText size={14} /> 当前快照</h4><pre>{JSON.stringify(parseJSON(detail.asset?.current_data, {}), null, 2)}</pre></section>
  </div>;
}

function CatalogRelationsPanel({ detail, onPivot, onOpen }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Route size={14} /> 资产关系</h4>
    {detail.relations?.length ? detail.relations.map((relation) => {
      const openURL = assetTargetURL(relation.asset);
      return <div className="catalog-relation-row" key={relation.id}><Badge>{relation.direction === "incoming" ? "入" : "出"}</Badge><div><strong>{relation.relation_type}</strong><button className="link-button" onClick={() => onPivot(relation.asset)}>{relation.asset?.display_value || "未知资产"}</button></div><Badge tone={relation.asset?.risk_score > 0 ? "warn" : "muted"}>风险 {relation.asset?.risk_score || 0}</Badge><time>{formatDate(relation.last_seen_at)}</time><div className="row-actions"><button className="icon-button" title="定位关联资产" onClick={() => onPivot(relation.asset)}><Crosshair size={14} /></button>{openURL && <button className="icon-button" title="打开关联资产" onClick={() => onOpen(openURL)}><ExternalLink size={14} /></button>}</div></div>;
    }) : <EmptyState text="暂无资产关系" />}
  </section></div>;
}

function originLabel(originType, originID) { return `${originType === "enterprise_query" ? "企业查询" : "来源任务"} ${originID?.slice(0, 8) || "-"}`; }

function CatalogChangesPanel({ detail, onOrigin }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section catalog-changes"><h4><GitCompareArrows size={14} /> 变化时间线</h4>
    {detail.changes?.length ? detail.changes.map((change) => <div className="catalog-change-record" key={change.id}><div className="catalog-change-row"><Badge tone={change.event_type === "modified" ? "warn" : "ok"}>{change.event_type === "modified" ? "变化" : "发现"}</Badge><div><strong>{change.event_type === "modified" ? "资产状态发生变化" : "建立资产基线"}</strong><span>{change.event_type === "modified" ? (change.changed_fields || []).map(changeFieldLabel).join("、") : "首次主观测"}</span></div><button className="link-button" onClick={() => onOrigin(change.task_id, change.origin_type)}>{originLabel(change.origin_type, change.task_id)}</button><time>{formatDate(change.observed_at)}</time></div>
      {change.event_type === "modified" && <details><summary>对比前后状态</summary><div className="catalog-diff-grid"><div><span>之前</span><pre>{JSON.stringify(parseJSON(change.before_data, {}), null, 2)}</pre></div><div><span>之后</span><pre>{JSON.stringify(parseJSON(change.after_data, {}), null, 2)}</pre></div></div></details>}
    </div>) : <EmptyState text="暂无变化记录" />}
  </section></div>;
}

function CatalogObservationsPanel({ detail, onOrigin }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Clock3 size={14} /> 观测历史</h4>
    {detail.observations?.length ? detail.observations.map((observation) => <div className="catalog-observation-row" key={observation.id}><div className="history-row"><Badge>{observation.source_type}</Badge><button className="link-button" onClick={() => onOrigin(observation.task_id, observation.origin_type)}>{originLabel(observation.origin_type, observation.task_id)}</button><time>{formatDate(observation.observed_at)}</time></div><details><summary>查看本次观测</summary><pre>{JSON.stringify(parseJSON(observation.payload, {}), null, 2)}</pre></details></div>) : <EmptyState text="暂无观测记录" />}
  </section></div>;
}

function verificationLabel(value) { return ({ vulnerable: "命中", safe: "未命中", error: "失败" })[value] || value || "未知"; }
function verificationTone(value) { return value === "vulnerable" || value === "error" ? "danger" : value === "safe" ? "ok" : "muted"; }

function CatalogExecutionsPanel({ detail, onTask }) {
  return <div className="catalog-workbench-pane"><section className="catalog-detail-section"><h4><Activity size={14} /> 验证记录</h4>
    {detail.executions?.length ? detail.executions.map((execution) => <div className="catalog-execution-record" key={execution.id}>
      <div className="catalog-execution-row"><Badge tone={verificationTone(execution.result)}>{verificationLabel(execution.result)}</Badge><div><strong>{execution.target}</strong><span>PoC {execution.poc_id?.slice(0, 8) || "-"} · {execution.invocation_source === "mcp" ? "MCP" : "Web"}</span></div><div className="catalog-execution-badges">{execution.vulnerability_id && <Badge tone={execution.result === "vulnerable" ? "danger" : "accent"}>{execution.result === "vulnerable" ? "证据命中" : "关联复测"}</Badge>}{execution.scope_id ? <Badge tone="ok">授权 {execution.scope_id.slice(0, 8)}</Badge> : <Badge tone="warn">兼容模式</Badge>}</div><time>{formatDate(execution.created_at)}</time>{execution.task_id ? <button className="link-button" onClick={() => onTask(execution.task_id)}>任务 {execution.task_id.slice(0, 8)}</button> : <span />}</div>
      {execution.details && <details><summary>查看验证回显</summary><pre>{execution.details}</pre></details>}
    </div>) : <EmptyState text="尚未执行 PoC 验证" />}
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
    <div className="editor-head"><div><span className="eyebrow"><ShieldAlert size={14} /> Confirmed evidence</span><h3>{draft.title || "未命名风险"}</h3></div><button type="button" className="icon-button" title="关闭" onClick={onClose}><X size={16} /></button></div>
    <div className="risk-evidence-meta"><Badge tone={severityClass[draft.severity] || "muted"}>{draft.severity || "info"}</Badge><Badge tone={findingStatusTone(draft.status)}>{findingStatusLabel(draft.status)}</Badge><Badge tone={verificationResultTone(draft.last_verification_result)}>{verificationResultLabel(draft.last_verification_result)}</Badge><time>{draft.last_verified_at ? formatDate(draft.last_verified_at) : formatDate(draft.created_at)}</time></div>
    <div className="risk-evidence-target"><div><span>目标</span><strong>{draft.url || "-"}</strong></div>{draft.url && <button type="button" className="icon-button" title="复制目标" onClick={() => onCopy(draft.url, "目标")}><Copy size={15} /></button>}</div>
    <div className="risk-evidence-triage"><label>漏洞状态<select name="finding_status" value={draft.status || "new"} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>研判笔记<textarea name="finding_note" rows="4" maxLength="5000" value={draft.triage_note || ""} onChange={(event) => setDraft({ ...draft, triage_note: event.target.value })} /></label></div>
    <div className="risk-evidence-sections">{sections.length ? sections.map((section) => <section key={section.key}><div><span>{section.label}</span><button type="button" className="icon-button" title={`复制${section.label}`} aria-label={`复制${section.label}`} onClick={() => onCopy(section.value, section.label)}><Copy size={14} /></button></div><pre>{section.value}</pre></section>) : <EmptyState text="该风险尚未记录描述、Payload 或验证证明" />}</div>
    <div className="editor-actions"><button type="button" className="ghost-button" onClick={onClose}>关闭</button><button type="submit" className="ghost-button">保存研判</button><button type="button" className="primary-button" onClick={() => onCopy(formatVulnerabilityEvidence(draft), "完整证据")}><Copy size={15} />复制全部证据</button></div>
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

  async function saveGroup(event) { event.preventDefault(); try { await api(`/asset-groups${groupEditor.id ? `/${groupEditor.id}` : ""}`, { method: groupEditor.id ? "PUT" : "POST", body: JSON.stringify(groupEditor) }); setGroupEditor(null); setMessage("资产分组已保存"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`保存失败：${error.message}`); } }
  async function removeGroup(group) { if (!window.confirm(`删除分组“${group.name}”及其成员关系？`)) return; try { await api(`/asset-groups/${group.id}`, { method: "DELETE" }); setMessage("资产分组已删除"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`删除失败：${error.message}`); } }
  async function openGroup(group) { try { const result = await api(`/asset-groups/${group.id}/items`); setGroupDetail({ ...group, items: result.items || [] }); } catch (error) { setMessage(`加载成员失败：${error.message}`); } }
  async function removeGroupMember(item) { try { await api(`/asset-groups/${groupDetail.id}/items/${item.id}`, { method: "DELETE" }); setGroupDetail({ ...groupDetail, items: groupDetail.items.filter((member) => member.id !== item.id) }); setMessage("分组成员已移除"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`移除失败：${error.message}`); } }
  async function assignGroup(event) { event.preventDefault(); try { await api(`/asset-groups/${assigning.group_id}/items`, { method: "POST", body: JSON.stringify({ asset_type: assigning.asset_type, asset_ids: [assigning.asset_id] }) }); setAssigning(null); setMessage("资产已加入分组"); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`加入分组失败：${error.message}`); } }
  async function assignSelectedGroup() { const groupID = batchGroupID || groupOptions?.groups?.[0]?.id; if (!selectedIDs.length || !groupID) return; try { const result = await api(`/asset-groups/${groupID}/items`, { method: "POST", body: JSON.stringify({ asset_type: "canonical", asset_ids: selectedIDs }) }); setMessage(`已将 ${result.created_count || 0} 个全局资产加入分组${result.skipped?.length ? `，跳过 ${result.skipped.length} 个` : ""}`); setSelectedIDs([]); setGroupRefresh((x) => x + 1); } catch (error) { setMessage(`批量加入失败：${error.message}`); } }
  async function openCatalogAssetByID(assetID, asset = null) { try { setCatalogDetailTab("leads"); setLeadRuns({}); setWorkbenchMessage(""); setCatalogDetail({ asset: asset || { id: assetID, display_value: "加载资产..." }, loading: true }); const result = await api(`/assets/inventory/${assetID}`); setCatalogDetail({ ...result, loading: false }); } catch (error) { setCatalogDetail(null); setMessage(`资产详情加载失败：${error.message}`); } }
  async function openCatalogAsset(asset) { return openCatalogAssetByID(asset.id, asset); }
  async function copyWorkbenchValue(value) { try { await navigator.clipboard.writeText(value); setWorkbenchMessage("目标已复制"); } catch { setWorkbenchMessage("复制失败，请手动选择目标"); } }
  function openWorkbenchURL(url) { window.open(url, "_blank", "noopener,noreferrer"); }
  function pivotToAsset(asset) { const pivot = assetPivot(asset); setCatalogDetail(null); setTab(pivot.tab); setSearches((current) => ({ ...current, [pivot.tab]: pivot.search })); setPage(1); setSelectedIDs([]); }
  function openSourceTask(taskID) { if (!taskID) return; setCatalogDetail(null); navigate(`task:${taskID}`); }
  function openCatalogOrigin(originID, originType) { if (!originID) return; setCatalogDetail(null); navigate(originType === "enterprise_query" ? "enterprise" : `task:${originID}`); }
  async function updateLeadTriage(lead, status, note = lead.triage_note || "") {
    try {
      const result = await api("/assets/leads/triage", { method: "PUT", body: JSON.stringify({ asset_id: lead.asset_id || catalogDetail.asset.id, lead_id: lead.id, status, note }) });
      setCatalogDetail((current) => ({ ...current, leads: current.leads.map((item) => item.id === lead.id ? { ...item, triage_status: result.triage.status, triage_note: result.triage.note, triage_updated_at: result.triage.updated_at } : item) }));
      setWorkbenchMessage(`线索已更新为${leadStatusLabel(status)}`);
      setTriageEditor(null);
    } catch (error) { setWorkbenchMessage(`更新失败：${error.message}`); }
  }
  async function executeLeadPoC(lead) {
    if (!lead.poc || !window.confirm(`使用“${lead.poc.name}”验证目标 ${lead.target}？`)) return;
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
      setWorkbenchMessage(result.result === "vulnerable" ? `验证命中，${result.finding_created ? "已固化" : "已更新"}可提交漏洞证据` : result.finding ? `复测完成：${verificationLabel(result.result)}，漏洞证据已保留并更新复测状态` : `验证完成：${verificationLabel(result.result)}，记录已写入审计链`);
    } catch (error) {
      const execution = error.payload?.execution_log;
      if (execution) setCatalogDetail((current) => ({ ...current, executions: [execution, ...(current.executions || []).filter((item) => item.id !== execution.id)] }));
      setLeadRuns((current) => ({ ...current, [lead.id]: { state: "error", details: error.payload?.details || error.message } }));
      setWorkbenchMessage(`验证失败：${error.message}`);
    }
  }

  async function updateFindingTriage(finding, status, note = finding.triage_note || "") {
    try {
      await api(`/assets/vulnerabilities/${finding.vulnerability_id}/triage`, { method: "PUT", body: JSON.stringify({ status, note }) });
      const refreshed = await api(`/assets/inventory/${catalogDetail.asset.id}`);
      setCatalogDetail({ ...refreshed, loading: false });
      setGroupRefresh((value) => value + 1);
      setWorkbenchMessage(`漏洞已更新为${findingStatusLabel(status)}${["resolved", "false_positive"].includes(status) ? "，资产风险已重新计算" : ""}`);
      setFindingEditor(null);
    } catch (error) { setWorkbenchMessage(`更新失败：${error.message}`); }
  }

  async function saveGlobalFindingTriage(status, note) {
    if (!globalFindingDetail) return;
    try {
      const result = await api(`/assets/vulnerabilities/${globalFindingDetail.id}/triage`, { method: "PUT", body: JSON.stringify({ status, note }) });
      setGlobalFindingDetail(result.finding || { ...globalFindingDetail, status, triage_note: note });
      setMessage(`漏洞已更新为${findingStatusLabel(status)}`);
      setGroupRefresh((value) => value + 1);
    } catch (error) { setMessage(`更新失败：${error.message}`); }
  }

  async function copyFindingValue(value, label) {
    if (!value) return;
    try { await navigator.clipboard.writeText(value); setMessage(`已复制${label}`); }
    catch { setMessage("复制失败：浏览器未授予剪贴板权限"); }
  }

  const inventoryAssets = data?.assets || [];
  const visibleInventoryIDs = inventoryAssets.map((asset) => asset.id);
  const inventorySelection = (asset) => <input key="select" className="row-check" type="checkbox" aria-label={`选择 ${asset.display_value}`} checked={selectedIDs.includes(asset.id)} onChange={() => setSelectedIDs((current) => current.includes(asset.id) ? current.filter((id) => id !== asset.id) : [...current, asset.id])} />;
  const rows = {
    inventory: inventoryAssets.map((x) => [inventorySelection(x), <Badge key="kind" tone={x.kind === "site" ? "ok" : x.kind === "port" ? "warn" : "muted"}>{x.kind}</Badge>, <button key="value" className="link-button" onClick={() => openCatalogAsset(x)}>{x.display_value}</button>, <Badge key="risk" tone={riskTone(x.risk_score)}>{riskLabel(x.risk_score)} · {x.risk_score}</Badge>, compactNumber(x.vulnerability_count), compactNumber(x.change_count), compactNumber(x.observation_count), formatDate(x.last_seen_at)]),
    domains: (data?.domains || []).map((x) => [x.domain, x.ip_address || "-", x.source || "-", formatDate(x.created_at), <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "domain", asset_id: x.id, label: x.domain, group_id: groupOptions.groups[0]?.id || "" })}>加入分组</button>]),
    ips: (data?.ips || []).map((x) => [x.ip_address, x.domain || "-", x.location || "-", formatDate(x.created_at), <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "ip", asset_id: x.id, label: x.ip_address, group_id: groupOptions.groups[0]?.id || "" })}>加入分组</button>]),
    ports: (data?.ports || []).map((x) => [x.ip_address, x.port, x.service || "-", x.banner || "-"]),
    sites: (data?.sites || []).map((x) => [x.url, x.status_code, x.title || "-", x.fingerprint || "-", <button key="group" className="ghost-button compact" disabled={!groupOptions?.groups?.length} onClick={() => setAssigning({ asset_type: "site", asset_id: x.id, label: x.url, group_id: groupOptions.groups[0]?.id || "" })}>加入分组</button>]),
    urls: (data?.urls || []).map((x) => [x.method || "GET", x.url, x.status_code, x.content_length]),
    vulnerabilities: (data?.vulnerabilities || []).map((x) => [<Badge key="sev" tone={severityClass[x.severity] || "muted"}>{x.severity}</Badge>, <Badge key="status" tone={findingStatusTone(x.status)}>{findingStatusLabel(x.status)}</Badge>, x.title, x.url, x.type, <button key="view" type="button" className="ghost-button compact" onClick={() => setGlobalFindingDetail(x)}><FileText size={13} />查看</button>]),
    groups: (data?.groups || []).map((x) => [<button key="name" className="link-button" onClick={() => openGroup(x)}>{x.name}</button>, x.description || "-", x.member_count || 0, formatDate(x.updated_at), <div className="row-actions" key="actions"><button className="icon-button" title="编辑" onClick={() => setGroupEditor({ id: x.id, name: x.name, description: x.description || "" })}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" onClick={() => removeGroup(x)}><Trash2 size={14} /></button></div>]),
  }[tab];
  const columns = {
    inventory: ["选择", "类型", "资产", "风险", "漏洞", "变化", "观测", "最后发现"],
    domains: ["域名", "IP", "来源", "时间", "分组"],
    ips: ["IP", "域名", "位置", "时间", "分组"],
    ports: ["IP", "端口", "服务", "Banner"],
    sites: ["URL", "状态", "标题", "指纹", "分组"],
    urls: ["方法", "URL", "状态", "长度"],
    vulnerabilities: ["级别", "状态", "标题", "URL", "类型", "操作"],
    groups: ["分组名称", "说明", "成员数", "更新时间", "操作"],
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
    <Panel title="资产浏览" icon={<Network size={17} />}>
      <div className="toolbar">
        <Tabs value={tab} setValue={(v) => { setTab(v); setPage(1); setMessage(""); setSelectedIDs([]); }} items={["inventory", "domains", "ips", "ports", "sites", "urls", "vulnerabilities", "groups"]} labels={{ inventory: "全局资产", domains: "域名", ips: "IP", ports: "端口", sites: "站点", urls: "URL", vulnerabilities: "漏洞", groups: "分组" }} />
        <AdvancedSearch key={tab} value={search} fields={searchFields} placeholder="检索资产，支持 &&、||、! 和字段限定" onApply={(value) => { setSearches((current) => ({ ...current, [tab]: value })); setPage(1); }} />
        {tab === "groups" && <button className="primary-button" onClick={() => setGroupEditor({ id: "", name: "", description: "" })}><Plus size={15} />新建分组</button>}
      </div>
      {error && <div className="error-box">加载失败：{error}</div>}{message && <div className={message.includes("失败") ? "error-box" : "success-box"}>{message}</div>}
      {tab === "inventory" && <div className="asset-catalog-strip">{[["全局实体", "total"], ["域名", "domains"], ["IP", "ips"], ["端口", "ports"], ["站点", "sites"], ["URL", "urls"], ["风险资产", "at_risk"], ["变化事件", "changes"], ["漏洞关联", "vulnerability_links"], ["资产关系", "relations"]].map(([label, key]) => <div key={key}><span>{label}</span><strong>{compactNumber(catalogStats?.[key])}</strong></div>)}</div>}
      {tab === "inventory" && <div className="task-toolbar"><div className="row-actions task-batch-actions"><select name="batch_group_id" aria-label="目标资产分组" value={batchGroupID || groupOptions?.groups?.[0]?.id || ""} disabled={!groupOptions?.groups?.length} onChange={(event) => setBatchGroupID(event.target.value)}>{(groupOptions?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="primary-button" disabled={!selectedIDs.length || !groupOptions?.groups?.length} onClick={assignSelectedGroup}>加入分组{selectedIDs.length ? ` (${selectedIDs.length})` : ""}</button></div></div>}
      <DataTable storageKey={`assets-${tab}`} loading={loading} columns={columns} rows={rows} filterKeys={tableFilterKeys} filters={columnFilters[tab] || {}} filterOptions={{ severity: ["critical", "high", "medium", "low", "info"], kind: ["domain", "ip", "port", "site", "url"] }} onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [tab]: { ...(current[tab] || {}), [key]: value } })); setPage(1); }} headerCells={tab === "inventory" ? { 0: <SelectAllCheckbox ids={visibleInventoryIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="本页全局资产" /> } : {}} selectionColumn={tab === "inventory"} empty={tab === "groups" ? "暂无资产分组" : "暂无资产"} />
      <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPage} />
      <Modal open={Boolean(groupEditor)}>{groupEditor && <form className="library-editor proxy-editor" onSubmit={saveGroup}><div className="editor-head"><div><span className="eyebrow">Asset scope</span><h3>{groupEditor.id ? "编辑分组" : "新建分组"}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setGroupEditor(null)}><X size={16} /></button></div><label>分组名称<input required value={groupEditor.name} onChange={(e) => setGroupEditor({ ...groupEditor, name: e.target.value })} /></label><label>说明<textarea rows="4" value={groupEditor.description} onChange={(e) => setGroupEditor({ ...groupEditor, description: e.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setGroupEditor(null)}>取消</button><button className="primary-button">保存分组</button></div></form>}</Modal>
      <Modal open={Boolean(groupDetail)}>{groupDetail && <div className="library-editor automation-detail"><div className="editor-head"><div><span className="eyebrow">Group members</span><h3>{groupDetail.name}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setGroupDetail(null)}><X size={16} /></button></div>{groupDetail.items.length ? groupDetail.items.map((item) => <div className="history-row member-row" key={item.id}><Badge>{item.asset_source === "catalog" ? "全局" : "任务"} · {item.kind || item.asset_type}</Badge><span title={item.asset_id}>{item.label || item.asset_id}</span><time>{formatDate(item.created_at)}</time><button className="icon-button danger" title="移出分组" onClick={() => removeGroupMember(item)}><Trash2 size={14} /></button></div>) : <EmptyState text="分组内暂无资产" />}</div>}</Modal>
      <Modal open={Boolean(assigning)}>{assigning && <form className="library-editor proxy-editor" onSubmit={assignGroup}><div className="editor-head"><div><span className="eyebrow">Assign asset</span><h3>加入资产分组</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setAssigning(null)}><X size={16} /></button></div><div className="hint">{assigning.label}</div><label>目标分组<select value={assigning.group_id} onChange={(e) => setAssigning({ ...assigning, group_id: e.target.value })}>{(groupOptions?.groups || []).map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setAssigning(null)}>取消</button><button className="primary-button">确认加入</button></div></form>}</Modal>
      <Modal open={Boolean(catalogDetail)}>{catalogDetail && <div className="library-editor catalog-detail">
        <div className="editor-head catalog-workbench-head"><div><span className="eyebrow"><Database size={14} /> Attack surface workbench</span><h3>{catalogDetail.asset?.display_value}</h3></div><div className="row-actions"><button type="button" className="icon-button" title="复制当前资产" onClick={() => copyWorkbenchValue(catalogDetail.asset?.display_value)}><Copy size={16} /></button>{assetTargetURL(catalogDetail.asset) && <button type="button" className="icon-button" title="打开当前资产" onClick={() => openWorkbenchURL(assetTargetURL(catalogDetail.asset))}><ExternalLink size={16} /></button>}<button type="button" className="icon-button" title="定位到分类资产" onClick={() => pivotToAsset(catalogDetail.asset)}><Crosshair size={16} /></button><button type="button" className="icon-button" title="关闭" onClick={() => setCatalogDetail(null)}><X size={16} /></button></div></div>
        {catalogDetail.loading ? <div className="route-loading"><span className="status-dot" />正在推导攻击面线索...</div> : <>
          <div className="catalog-detail-metrics"><div><span>类型</span><strong>{catalogDetail.asset?.kind}</strong></div><div><span>风险</span><strong><Badge tone={riskTone(catalogDetail.asset?.risk_score)}>{riskLabel(catalogDetail.asset?.risk_score)} · {catalogDetail.asset?.risk_score}</Badge></strong></div><div><span>漏洞</span><strong>{compactNumber(catalogDetail.asset?.vulnerability_count)}</strong></div><div><span>变化</span><strong>{compactNumber(catalogDetail.asset?.change_count)}</strong></div><div><span>观测</span><strong>{compactNumber(catalogDetail.asset?.observation_count)}</strong></div><div><span>最后发现</span><strong>{formatDate(catalogDetail.asset?.last_seen_at)}</strong></div></div>
          {workbenchMessage && <div className={workbenchMessage.includes("失败") ? "error-box workbench-message" : "success-box workbench-message"}>{workbenchMessage}</div>}
          <div className="catalog-workbench-tabs"><Tabs value={catalogDetailTab} setValue={setCatalogDetailTab} items={["leads", "evidence", "executions", "relations", "changes", "observations"]} labels={{ leads: `线索 ${catalogDetail.leads?.length || 0}`, evidence: `证据 ${catalogDetail.findings?.length || 0}`, executions: `验证 ${catalogDetail.executions?.length || 0}`, relations: `关系 ${catalogDetail.relations?.length || 0}`, changes: `变化 ${catalogDetail.changes?.length || 0}`, observations: `观测 ${catalogDetail.observations?.length || 0}` }} /></div>
          {catalogDetailTab === "leads" && <CatalogLeadPanel detail={catalogDetail} runs={leadRuns} onCopy={copyWorkbenchValue} onOpen={openWorkbenchURL} onTask={openSourceTask} onExecute={executeLeadPoC} onTriage={updateLeadTriage} onNote={(lead) => setTriageEditor({ lead, status: lead.triage_status || "new", note: lead.triage_note || "" })} />}
          {catalogDetailTab === "evidence" && <CatalogEvidencePanel detail={catalogDetail} onTask={openSourceTask} onTriage={updateFindingTriage} onNote={(finding) => setFindingEditor({ finding, status: finding.status || "new", note: finding.triage_note || "" })} />}
          {catalogDetailTab === "executions" && <CatalogExecutionsPanel detail={catalogDetail} onTask={openSourceTask} />}
          {catalogDetailTab === "relations" && <CatalogRelationsPanel detail={catalogDetail} onPivot={pivotToAsset} onOpen={openWorkbenchURL} />}
          {catalogDetailTab === "changes" && <CatalogChangesPanel detail={catalogDetail} onOrigin={openCatalogOrigin} />}
          {catalogDetailTab === "observations" && <CatalogObservationsPanel detail={catalogDetail} onOrigin={openCatalogOrigin} />}
        </>}
      </div>}</Modal>
      <Modal open={Boolean(triageEditor)}>{triageEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); const formData = new FormData(event.currentTarget); updateLeadTriage(triageEditor.lead, String(formData.get("lead_status") || "new"), String(formData.get("lead_note") || "")); }}><div className="editor-head"><div><span className="eyebrow">Hunter note</span><h3>{triageEditor.lead.title}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setTriageEditor(null)}><X size={16} /></button></div><label>研判状态<select name="lead_status" value={triageEditor.status} onChange={(event) => setTriageEditor({ ...triageEditor, status: event.target.value })}>{leadStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>个人笔记<textarea name="lead_note" autoFocus rows="8" maxLength="5000" value={triageEditor.note} onChange={(event) => setTriageEditor({ ...triageEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setTriageEditor(null)}>取消</button><button className="primary-button">保存研判</button></div></form>}</Modal>
      <Modal open={Boolean(findingEditor)}>{findingEditor && <form className="library-editor lead-note-editor" onSubmit={(event) => { event.preventDefault(); const formData = new FormData(event.currentTarget); updateFindingTriage(findingEditor.finding, String(formData.get("finding_status") || "new"), String(formData.get("finding_note") || "")); }}><div className="editor-head"><div><span className="eyebrow">Finding workflow</span><h3>{findingEditor.finding.title}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setFindingEditor(null)}><X size={16} /></button></div><label>漏洞状态<select name="finding_status" value={findingEditor.status} onChange={(event) => setFindingEditor({ ...findingEditor, status: event.target.value })}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>研判笔记<textarea name="finding_note" autoFocus rows="8" maxLength="5000" value={findingEditor.note} onChange={(event) => setFindingEditor({ ...findingEditor, note: event.target.value })} /></label><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setFindingEditor(null)}>取消</button><button className="primary-button">保存漏洞研判</button></div></form>}</Modal>
      <Modal open={Boolean(globalFindingDetail)}>{globalFindingDetail && <VulnerabilityEvidenceEditor finding={globalFindingDetail} onClose={() => setGlobalFindingDetail(null)} onSave={saveGlobalFindingTriage} onCopy={copyFindingValue} />}</Modal>
    </Panel>
  );
}
