import React from "react";
import { Activity, Boxes, Globe2, Network, Plus, Search, ShieldCheck, TerminalSquare, Zap } from "lucide-react";
import NetworkCanvas from "../components/NetworkCanvas.jsx";
import AmbientCode from "../components/AmbientCode.jsx";
import { Badge, DataTable, Metric, Panel } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, cls, compactNumber, formatDate } from "../lib/api.js";

export default function DashboardPage({ setPage }) {
  const { data: taskStats } = useQuery("task-stats", () => api("/tasks/stats"));
  const { data: assetStats } = useQuery("asset-stats", () => api("/assets/stats"));
  const { data: tasks } = useQuery("recent-tasks", () => api("/tasks?page=1&page_size=6"));
  const { data: health } = useQuery("health", () => fetch("/health").then((response) => response.json()));
  const cards = [
    { label: "任务总数", value: taskStats?.total, icon: Activity }, { label: "运行中", value: taskStats?.running, icon: Zap },
    { label: "域名", value: assetStats?.domains, icon: Globe2 }, { label: "IP", value: assetStats?.ips, icon: Network },
    { label: "站点", value: assetStats?.sites, icon: Boxes }, { label: "有效风险", value: assetStats?.active_vulnerabilities ?? assetStats?.vulnerabilities, icon: ShieldCheck },
  ];
  const signalChips = [{ label: "任务队列", value: compactNumber(taskStats?.queued) }, { label: "HTTP 记录", value: compactNumber(assetStats?.urls) }, { label: "漏洞记录", value: compactNumber(assetStats?.vulnerabilities) }, { label: "MCP", value: health?.mcp_enabled ? "在线" : "未启用" }];
  const telemetry = [{ label: "实时任务", value: compactNumber(taskStats?.running), tone: "ok" }, { label: "站点命中", value: compactNumber(assetStats?.sites), tone: "accent" }, { label: "有效风险", value: compactNumber(assetStats?.active_vulnerabilities ?? assetStats?.vulnerabilities), tone: "danger" }];
  return <div className="stack dashboard-home">
    <section className="hero-panel hero-cyber"><div className="hero-cyber-bg"><NetworkCanvas compact /><AmbientCode /><span className="hero-grid" /><span className="hero-scanline" /></div><div className="hero-cyber-content"><div className="hero-copy"><span className="eyebrow cyber"><ShieldCheck size={14} /> Realtime Recon Grid</span><h2>NODE 01 <span className="title-slash">/</span> ACTIVE SURFACE</h2><p>资产图谱、指纹、HTTP 与 PoC 信号正在同一张侦察面上汇聚。</p><div className="hero-actions"><button className="primary-button" onClick={() => setPage("tasks")}><Plus size={16} />新建扫描</button><button className="ghost-button" onClick={() => setPage("traffic")}><Search size={16} />查看响应</button></div><div className="hero-chips">{signalChips.map((chip) => <div key={chip.label} className="hero-chip"><span>{chip.label}</span><strong>{chip.value}</strong></div>)}</div></div><div className="hero-telemetry"><div className="telemetry-panel"><div className="telemetry-head"><span className="telemetry-title">LIVE SIGNAL</span><span className="telemetry-dot" /></div>{telemetry.map((item) => <div key={item.label} className="telemetry-row"><span>{item.label}</span><strong className={cls(item.tone)}>{item.value}</strong></div>)}<div className="telemetry-bars" aria-hidden="true">{Array.from({ length: 6 }, (_, index) => <span key={index} />)}</div></div><div className="orbit-panel" aria-hidden="true"><div className="orbit-ring orbit-ring-one" /><div className="orbit-ring orbit-ring-two" /><div className="orbit-ring orbit-ring-three" /><div className="orbit-core"><span>CORE</span><strong>{compactNumber(assetStats?.sites)}</strong></div></div></div></div><div className="hero-footer"><div className="hero-footline"><span>Signal routing</span><span>AI / MCP / HTTP / Fingerprint / PoC</span></div><div className="hero-footline"><span>Current mode</span><span>ctOS tactical interface / armed</span></div></div></section>
    <section className="metric-grid">{cards.map((card) => { const Icon = card.icon; return <Metric key={card.label} label={card.label} value={card.value} icon={<Icon size={18} />} />; })}</section>
    <Panel title="最近任务" icon={<TerminalSquare size={17} />}><DataTable storageKey="dashboard-recent-tasks" columns={["名称", "目标", "状态", "进度", "创建时间"]} rows={(tasks?.tasks || []).map((task) => [task.name, task.target, <Badge key="status" tone={task.status === "completed" ? "ok" : task.status === "failed" ? "danger" : "warn"}>{task.status}</Badge>, `${task.progress || 0}%`, formatDate(task.created_at)])} empty="暂无任务" /></Panel>
  </div>;
}
