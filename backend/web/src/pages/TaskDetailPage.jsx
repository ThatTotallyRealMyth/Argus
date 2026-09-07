import React, { useEffect, useMemo, useState } from "react";
import { ArrowLeft, CheckCircle2, Clock3, Copy, Download, FileText, FileWarning, Gauge, Pause, Play, RefreshCw, Server, ShieldAlert, TerminalSquare, X } from "lucide-react";
import { Badge, DataTable, EmptyState, Metric, Modal, Pager, Panel, SelectAllCheckbox, Tabs } from "../components/ui.jsx";
import AdvancedSearch from "../components/AdvancedSearch.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, compactNumber, formatDate, severityClass } from "../lib/api.js";
import { formatVulnerabilityEvidence, vulnerabilityEvidenceSections } from "../lib/vulnerabilityEvidence.js";
import { findingStatusLabel, findingStatusOptions, findingStatusTone, verificationResultLabel, verificationResultTone } from "../lib/findingWorkflow.js";

const stageDefinitions = [
  ["解析目标", "resolve", 15], ["域名发现", "discover", 30], ["端口扫描", "ports", 55],
  ["服务识别", "services", 70], ["站点探测", "sites", 82], ["风险检测", "risks", 100],
];

const dataTabs = ["domains", "ips", "ports", "sites", "urls", "http", "risks", "logs"];
const tabMeta = {
  domains: { endpoint: "/assets/domains", key: "domains", count: "domains", label: "子域名", exportType: "domains", fields: ["domain", "ip", "source", "takeover"] },
  ips: { endpoint: "/assets/ips", key: "ips", count: "ips", label: "IP", exportType: "ips", fields: ["ip", "domain", "source", "os", "location"] },
  ports: { endpoint: "/assets/ports", key: "ports", count: "ports", label: "端口", exportType: "ports", fields: ["ip", "port", "protocol", "service", "version", "banner"] },
  sites: { endpoint: "/assets/sites", key: "sites", count: "sites", label: "站点", exportType: "sites", fields: ["url", "title", "status", "ip", "type", "server", "fingerprint"] },
  urls: { endpoint: "/assets/urls", key: "urls", count: "urls", label: "URL", exportType: "urls", fields: ["url", "method", "status", "type", "source"] },
  http: { endpoint: "/assets/http-transactions", key: "items", count: "http_transactions", label: "HTTP", exportType: "http", fields: ["url", "method", "status", "type", "source", "body", "request"] },
  risks: { endpoint: "/assets/vulnerabilities", key: "vulnerabilities", count: "vulnerabilities", label: "风险", exportType: "vulnerabilities", fields: ["severity", "status", "title", "url", "type", "source", "description"] },
  logs: { endpoint: "logs", key: "logs", label: "任务日志", fields: ["level", "message"] },
};

function stageState(task, threshold) {
  const progress = Number(task?.progress || 0);
  if (task?.status === "completed" || progress >= threshold) return "completed";
  if (task?.status === "running" && progress < threshold && progress >= threshold - 15) return "running";
  if (task?.status === "failed" && progress >= threshold - 15) return "failed";
  return task?.status === "queued" ? "queued" : "pending";
}

function resultID(item, index) { return item.id || `${item.url || item.domain || item.ip_address || "row"}-${index}`; }
function copyValue(tab, item) {
  if (tab === "domains") return item.domain;
  if (tab === "ips") return item.ip_address;
  if (tab === "ports") return `${item.ip_address}:${item.port}`;
  if (tab === "sites" || tab === "urls" || tab === "http" || tab === "risks") return item.url;
  return item.message || "";
}

export default function TaskDetailPage({ taskId, setPage }) {
  const [tab, setTab] = useState("overview");
  const [assetPage, setAssetPage] = useState(1);
  const [assetSearch, setAssetSearch] = useState("");
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [refresh, setRefresh] = useState(0);
  const [message, setMessage] = useState("");
  const [liveProgress, setLiveProgress] = useState(null);
  const [liveState, setLiveState] = useState("snapshot");
  const [evidenceDetail, setEvidenceDetail] = useState(null);
  const { data: task, loading, error } = useQuery(`task-detail-${taskId}-${refresh}`, () => api(`/tasks/${encodeURIComponent(taskId)}`), { ttl: 5000 });
  const { data: stats } = useQuery(`task-detail-stats-${taskId}-${refresh}`, () => api(`/assets/stats?task_id=${encodeURIComponent(taskId)}`), { ttl: 5000 });
  const { data: scopeData } = useQuery("task-detail-scan-scopes", () => api("/scan-scopes"));
  const activeMeta = tabMeta[tab];
  const queryURL = useMemo(() => {
    if (!activeMeta) return "";
    const query = new URLSearchParams({ page: assetPage, page_size: 50 });
    if (tab === "logs") {
      if (assetSearch) query.set("q", assetSearch);
      return `/tasks/${encodeURIComponent(taskId)}/logs?${query}`;
    }
    query.set("task_id", taskId);
    if (assetSearch) query.set("q", assetSearch);
    return `${activeMeta.endpoint}?${query}`;
  }, [activeMeta, assetPage, assetSearch, tab, taskId]);
  const { data: assetData, loading: assetLoading, error: assetError } = useQuery(
    `task-workbench-${tab}-${taskId}-${assetPage}-${assetSearch}-${refresh}`,
    () => queryURL ? api(queryURL) : Promise.resolve(null),
    { ttl: ["queued", "running"].includes(task?.status) ? 3000 : 30000 },
  );

  const displayedProgress = liveProgress?.progress ?? Number(task?.progress || 0);
  const displayedTask = task ? { ...task, progress: displayedProgress } : null;
  const stages = useMemo(() => stageDefinitions.map(([label, key, threshold]) => ({ label, key, threshold, state: stageState(displayedTask, threshold) })), [task, displayedProgress]);
  const canStart = task?.status === "pending";
  const canCancel = ["queued", "running"].includes(task?.status);
  const taskScopeName = task?.scope_id ? (scopeData?.scopes || []).find((scope) => scope.id === task.scope_id)?.name || task.scope_id.slice(0, 8) : "兼容模式";
  const records = activeMeta ? (assetData?.[activeMeta.key] || []) : [];
  const recordIDs = records.map(resultID);

  useEffect(() => {
    if (!["queued", "running"].includes(task?.status)) { setLiveState("snapshot"); return undefined; }
    const token = localStorage.getItem("eclipse_token");
    if (!token) return undefined;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/progress?task_id=${encodeURIComponent(taskId)}&token=${encodeURIComponent(token)}`);
    setLiveState("connecting");
    socket.onopen = () => setLiveState("online");
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "progress") setLiveProgress((current) => ({ ...current, ...payload }));
        else if (payload.type === "task_complete") { setLiveState("snapshot"); setRefresh((value) => value + 1); }
      } catch { /* Ignore malformed progress messages. */ }
    };
    socket.onerror = () => setLiveState("offline");
    socket.onclose = () => setLiveState((current) => current === "snapshot" ? current : "offline");
    return () => socket.close();
  }, [taskId, task?.status]);

  async function updateTask(action, success) {
    try { await api(`/tasks/${encodeURIComponent(taskId)}/${action}`, { method: "POST", body: "{}" }); setMessage(success); setRefresh((value) => value + 1); }
    catch (requestError) { setMessage(`操作失败：${requestError.message}`); }
  }

  async function downloadExport(format, exportType = "") {
    setMessage("正在生成导出文件...");
    try {
      const suffix = exportType ? `&type=${encodeURIComponent(exportType)}` : "";
      const result = await api(`/export/task/${encodeURIComponent(taskId)}?format=${format}${suffix}`);
      const token = localStorage.getItem("eclipse_token");
      const response = await fetch(`/api/v1/export/download?file=${encodeURIComponent(result.filename)}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!response.ok) throw new Error("下载导出文件失败");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = result.filename; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
      setMessage("导出完成");
    } catch (requestError) { setMessage(`导出失败：${requestError.message}`); }
  }

  async function copySelected() {
    const values = records.filter((item, index) => selectedIDs.includes(resultID(item, index))).map((item) => copyValue(tab, item)).filter(Boolean);
    if (!values.length) return;
    try { await navigator.clipboard.writeText(values.join("\n")); setMessage(`已复制 ${values.length} 条记录`); }
    catch { setMessage("复制失败：浏览器未授予剪贴板权限"); }
  }

  async function copyEvidence(value, label) {
    if (!value) return;
    try { await navigator.clipboard.writeText(value); setMessage(`已复制${label}`); }
    catch { setMessage("复制失败：浏览器未授予剪贴板权限"); }
  }

  async function saveEvidenceTriage(status, note) {
    try {
      const result = await api(`/assets/vulnerabilities/${evidenceDetail.id}/triage`, { method: "PUT", body: JSON.stringify({ status: status || evidenceDetail.status || "new", note: note ?? evidenceDetail.triage_note ?? "" }) });
      setEvidenceDetail(result.finding);
      setMessage(`漏洞已更新为${findingStatusLabel(result.finding.status)}`);
      setRefresh((value) => value + 1);
    } catch (requestError) { setMessage(`更新失败：${requestError.message}`); }
  }

  function changeTab(value) { setTab(value); setAssetPage(1); setAssetSearch(""); setSelectedIDs([]); setMessage(""); }

  if (loading && !task) return <div className="route-loading"><span className="status-dot" />加载任务详情...</div>;
  if (error && !task) return <div className="error-box">任务详情加载失败：{error}</div>;
  if (!task) return <EmptyState text="任务不存在或已被删除" />;

  const statusTone = task.status === "completed" ? "ok" : task.status === "failed" ? "danger" : task.status === "running" ? "accent" : "warn";
  const tabItems = ["overview", "pipeline", ...dataTabs];
  const tabLabels = { overview: "概览", pipeline: "进度", logs: "任务日志" };
  Object.entries(tabMeta).forEach(([key, meta]) => { if (meta.count) tabLabels[key] = `${meta.label} ${compactNumber(stats?.[meta.count])}`; });
  const selection = (item, index) => <input key="select" className="row-check" type="checkbox" aria-label={`选择 ${copyValue(tab, item)}`} checked={selectedIDs.includes(resultID(item, index))} onChange={() => setSelectedIDs((current) => current.includes(resultID(item, index)) ? current.filter((id) => id !== resultID(item, index)) : [...current, resultID(item, index)])} />;
  const table = buildAssetTable(tab, records, selection, setEvidenceDetail);

  return <div className="stack task-detail-workspace">
    <div className="detail-toolbar"><button className="ghost-button" onClick={() => setPage("tasks")}><ArrowLeft size={16} />返回任务</button><div className="detail-toolbar-actions"><button className="icon-button" title="刷新详情" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={16} /></button>{canStart && <button className="primary-button" onClick={() => updateTask("start", "任务已进入队列")}><Play size={15} />启动任务</button>}{canCancel && <button className="ghost-button danger" onClick={() => updateTask("cancel", "任务已取消")}><Pause size={15} />取消任务</button>}</div></div>
    {message && <div className={message.includes("失败") ? "error-box" : "success-box"}>{message}</div>}
    <section className="detail-hero"><div><span className="eyebrow"><TerminalSquare size={14} /> Task Run / {taskId.slice(0, 8)}</span><h2>{task.name}</h2><p>{task.target}</p></div><div className="detail-hero-status"><Badge tone={statusTone}>{task.status}</Badge><strong>{displayedProgress}%</strong><span className={`live-state live-${liveState}`}>{liveState === "online" ? "实时连接" : liveState === "connecting" ? "正在连接" : liveState === "offline" ? "实时连接已断开" : `最后更新 ${formatDate(task.updated_at)}`}</span></div></section>
    <section className="metric-grid detail-metrics task-detail-metrics"><Metric label="域名" value={stats?.domains} icon={<Server size={18} />} /><Metric label="IP" value={stats?.ips} icon={<Gauge size={18} />} /><Metric label="端口" value={stats?.ports} icon={<TerminalSquare size={18} />} /><Metric label="站点" value={stats?.sites} icon={<CheckCircle2 size={18} />} /><Metric label="URL" value={stats?.urls} icon={<Clock3 size={18} />} /><Metric label="有效风险" value={stats?.active_vulnerabilities ?? stats?.vulnerabilities} icon={<ShieldAlert size={18} />} /></section>
    <Panel title="侦察结果" icon={<Clock3 size={17} />}>
      <div className="task-detail-tabs"><Tabs value={tab} setValue={changeTab} items={tabItems} labels={tabLabels} /></div>
      {tab === "overview" && <div className="detail-overview-grid"><div className="detail-info-list"><div><span>目标</span><strong>{task.target}</strong></div><div><span>授权范围</span><strong>{taskScopeName}</strong></div><div><span>配置</span><strong>{task.options?.port_scan_type || "top100"} / {task.options?.enable_site_detect ? "站点识别" : "基础探测"}</strong></div><div><span>创建时间</span><strong>{formatDate(task.created_at)}</strong></div><div><span>开始时间</span><strong>{formatDate(task.started_at)}</strong></div><div><span>结束时间</span><strong>{formatDate(task.ended_at)}</strong></div><div><span>HTTP 记录</span><strong>{compactNumber(stats?.http_transactions)}</strong></div></div><div className="detail-callout"><FileWarning size={18} /><div><strong>{task.error_msg ? "执行异常" : task.status === "completed" ? "执行完成" : "执行状态"}</strong><p>{task.error_msg || (task.status === "queued" ? "任务已持久化，等待 Worker 领取。" : "所有资产结果、HTTP 记录和日志都可在本页继续检索与导出。")}</p></div></div></div>}
      {tab === "pipeline" && <div className="pipeline-list">{stages.map((stage) => <div className={`pipeline-row pipeline-${stage.state}`} key={stage.key}><span className="pipeline-marker" /><div><strong>{stage.label}</strong><small>{stage.state === "completed" ? "已完成" : stage.state === "running" ? "执行中" : stage.state === "queued" ? "等待队列" : stage.state === "failed" ? "失败" : "待执行"}</small></div><code>{stage.threshold}%</code></div>)}</div>}
      {activeMeta && <div className="task-result-workbench">
        <div className="task-result-toolbar">
          <AdvancedSearch compact key={tab} value={assetSearch} fields={activeMeta.fields} placeholder={`检索${activeMeta.label}`} onApply={(value) => { setAssetSearch(value); setAssetPage(1); setSelectedIDs([]); }} />
          <div className="row-actions task-batch-actions">{tab !== "logs" && <button className="ghost-button" disabled={!selectedIDs.length} onClick={copySelected}><Copy size={14} />复制选中{selectedIDs.length ? ` (${selectedIDs.length})` : ""}</button>}{activeMeta.exportType && <button className="ghost-button" onClick={() => downloadExport("csv", activeMeta.exportType)}><Download size={14} />导出{activeMeta.label}</button>}</div>
        </div>
        {assetError && <div className="error-box">加载失败：{assetError}</div>}
        {tab === "logs" ? <TaskLogConsole logs={records} loading={assetLoading} /> : <DataTable storageKey={`task-detail-${tab}`} loading={assetLoading} columns={table.columns} rows={table.rows} headerCells={{ 0: <SelectAllCheckbox ids={recordIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label={`本页${activeMeta.label}`} /> }} selectionColumn empty={`该任务暂无${activeMeta.label}数据`} />}
        <Pager page={assetPage} totalPages={assetData?.total_pages || 1} setPage={(value) => { setAssetPage(value); setSelectedIDs([]); }} />
      </div>}
    </Panel>
    <Modal open={Boolean(evidenceDetail)}>{evidenceDetail && <form className="library-editor risk-evidence-editor" onSubmit={(event) => { event.preventDefault(); const formData = new FormData(event.currentTarget); saveEvidenceTriage(String(formData.get("finding_status") || "new"), String(formData.get("finding_note") || "")); }}>
      <div className="editor-head"><div><span className="eyebrow"><ShieldAlert size={14} /> Confirmed evidence</span><h3>{evidenceDetail.title || "未命名风险"}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setEvidenceDetail(null)}><X size={16} /></button></div>
      <div className="risk-evidence-meta"><Badge tone={severityClass[evidenceDetail.severity] || "muted"}>{evidenceDetail.severity || "info"}</Badge><Badge tone={findingStatusTone(evidenceDetail.status)}>{findingStatusLabel(evidenceDetail.status)}</Badge><Badge tone={verificationResultTone(evidenceDetail.last_verification_result)}>{verificationResultLabel(evidenceDetail.last_verification_result)}</Badge><time>{evidenceDetail.last_verified_at ? formatDate(evidenceDetail.last_verified_at) : formatDate(evidenceDetail.created_at)}</time></div>
      <div className="risk-evidence-target"><div><span>目标</span><strong>{evidenceDetail.url || "-"}</strong></div>{evidenceDetail.url && <button type="button" className="icon-button" title="复制目标" onClick={() => copyEvidence(evidenceDetail.url, "目标")}><Copy size={15} /></button>}</div>
      <div className="risk-evidence-triage"><label>漏洞状态<select name="finding_status" value={evidenceDetail.status || "new"} onChange={(event) => setEvidenceDetail({ ...evidenceDetail, status: event.target.value })}>{findingStatusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label>研判笔记<textarea name="finding_note" rows="4" maxLength="5000" value={evidenceDetail.triage_note || ""} onChange={(event) => setEvidenceDetail({ ...evidenceDetail, triage_note: event.target.value })} /></label></div>
      <div className="risk-evidence-sections">{vulnerabilityEvidenceSections(evidenceDetail).length ? vulnerabilityEvidenceSections(evidenceDetail).map((section) => <section key={section.key}><div><span>{section.label}</span><button type="button" className="icon-button" title={`复制${section.label}`} aria-label={`复制${section.label}`} onClick={() => copyEvidence(section.value, section.label)}><Copy size={14} /></button></div><pre>{section.value}</pre></section>) : <EmptyState text="该风险尚未记录描述、Payload 或验证证明" />}</div>
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEvidenceDetail(null)}>关闭</button><button type="submit" className="ghost-button">保存研判</button><button type="button" className="primary-button" onClick={() => copyEvidence(formatVulnerabilityEvidence(evidenceDetail), "完整证据")}><Copy size={15} />复制全部证据</button></div>
    </form>}</Modal>
    <div className="detail-footer"><span>任务结果按资产类型独立检索，日志来自真实扫描输出</span><div className="row-actions"><button className="ghost-button" onClick={() => downloadExport("html")}><FileText size={15} />导出安全报告</button><button className="ghost-button" onClick={() => downloadExport("json")}><Download size={15} />导出完整结果</button><button className="ghost-button" onClick={() => setPage("tasks")}><X size={15} />关闭详情</button></div></div>
  </div>;
}

function buildAssetTable(tab, records, selection, onEvidence) {
  const selectRows = (mapper) => records.map((item, index) => [selection(item, index), ...mapper(item)]);
  if (tab === "domains") return { columns: ["选择", "域名", "IP", "来源", "接管风险", "发现时间"], rows: selectRows((item) => [item.domain, item.ip_address || "-", item.source || "-", item.takeover_vulnerable ? <Badge key="risk" tone="danger">可疑</Badge> : "-", formatDate(item.created_at)]) };
  if (tab === "ips") return { columns: ["选择", "IP", "关联域名", "操作系统", "位置", "来源", "发现时间"], rows: selectRows((item) => [item.ip_address, item.domain || "-", item.os || "-", item.location || "-", item.source || "-", formatDate(item.created_at)]) };
  if (tab === "ports") return { columns: ["选择", "地址", "协议", "服务", "版本", "Banner"], rows: selectRows((item) => [`${item.ip_address}:${item.port}`, item.protocol || "tcp", item.service || "-", item.version || "-", item.banner || "-"]) };
  if (tab === "sites") return { columns: ["选择", "站点", "状态", "标题", "Server", "指纹", "截图"], rows: selectRows((item) => [<a key="url" className="table-link" href={item.url} target="_blank" rel="noreferrer">{item.url}</a>, item.status_code || "-", item.title || "-", item.server || "-", item.fingerprints?.length ? item.fingerprints.join(", ") : item.fingerprint || "-", item.screenshot ? <span key="shot" title={item.screenshot}>已保存</span> : "-"]) };
  if (tab === "urls") return { columns: ["选择", "方法", "状态", "URL", "类型", "长度", "来源"], rows: selectRows((item) => [item.method || "GET", item.status_code || "-", <a key="url" className="table-link" href={item.url} target="_blank" rel="noreferrer">{item.url}</a>, item.content_type || "-", compactNumber(item.content_length), item.source || "-"]) };
  if (tab === "http") return { columns: ["选择", "状态", "长度", "耗时", "方法", "类型", "URL", "来源"], rows: selectRows((item) => [item.response_status_code || "-", compactNumber(item.response_content_length), `${item.response_time_ms || 0} ms`, item.method || "GET", item.response_content_type || "-", item.url, item.source || "-"]) };
  if (tab === "risks") return { columns: ["选择", "级别", "状态", "标题", "目标", "类型", "来源", "证据"], rows: selectRows((item) => [<Badge key="severity" tone={severityClass[item.severity] || "muted"}>{item.severity || "info"}</Badge>, <Badge key="status" tone={findingStatusTone(item.status)}>{findingStatusLabel(item.status)}</Badge>, item.title || "未命名风险", item.url || "-", item.type || "-", item.source || "-", <button type="button" key="evidence" className="ghost-button compact risk-evidence-button" onClick={() => onEvidence(item)}><FileText size={13} />查看</button>]) };
  return { columns: ["选择", "记录"], rows: [] };
}

function TaskLogConsole({ logs, loading }) {
  if (loading) return <div className="route-loading"><span className="status-dot" />加载任务日志...</div>;
  if (!logs.length) return <EmptyState text="该任务暂无持久化日志，新执行任务会自动记录" />;
  return <div className="task-log-console">{[...logs].reverse().map((entry) => <div className={`task-log-line log-${entry.level}`} key={entry.id}><time>{formatDate(entry.created_at)}</time><Badge tone={entry.level === "error" ? "danger" : entry.level === "warning" ? "warn" : "ok"}>{entry.level}</Badge><span>{entry.message}</span></div>)}</div>;
}
