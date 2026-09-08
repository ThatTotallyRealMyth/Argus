import React, { Suspense, useCallback, useEffect, useState } from "react";
import { Clock3, Cpu, LayoutDashboard, LogOut, PanelLeftClose, PanelLeftOpen, PlugZap, RefreshCw, Server, TerminalSquare } from "lucide-react";
import { motion } from "motion/react";
import { api, cls } from "../lib/api.js";
import { BRAND } from "../lib/constants.js";
import RouteErrorBoundary from "../components/RouteErrorBoundary.jsx";
import AmbientCode from "../components/AmbientCode.jsx";
import CustomCursor from "../components/CustomCursor.jsx";
import LoginPage from "../pages/LoginPage.jsx";
import { routes } from "./routes.jsx";
import TaskDetailPage from "../pages/TaskDetailPage.jsx";

function readLocation() {
  const match = window.location.pathname.match(/^\/tasks\/([^/]+)$/);
  if (match) return { key: "task-detail", taskId: decodeURIComponent(match[1]) };
  return { key: routes.find((route) => route.path === window.location.pathname)?.key || "dashboard" };
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("eclipse_token") || "");
  const [user, setUser] = useState(null);
  const [location, setLocation] = useState(readLocation);
  const [clock, setClock] = useState(new Date());
  const [health, setHealth] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem("eclipse_sidebar_collapsed") === "1");
  const loadHealth = useCallback(async () => {
    try {
      const response = await fetch("/health", { cache: "no-store" });
      if (!response.ok) throw new Error(response.statusText);
      setHealth({ online: true, ...await response.json() });
    } catch {
      setHealth({ online: false, mcp_enabled: false, task_workers: 0 });
    }
  }, []);
  useEffect(() => { document.documentElement.dataset.theme = "dark"; const timer = window.setInterval(() => setClock(new Date()), 1000); return () => window.clearInterval(timer); }, []);
  useEffect(() => {
    if (!token) return undefined;
    loadHealth();
    const timer = window.setInterval(loadHealth, 15000);
    return () => window.clearInterval(timer);
  }, [loadHealth, token]);
  useEffect(() => { const handlePopState = () => setLocation(readLocation()); window.addEventListener("popstate", handlePopState); return () => window.removeEventListener("popstate", handlePopState); }, []);
  useEffect(() => { const expire = () => { localStorage.removeItem("eclipse_token"); setUser(null); setToken(""); }; window.addEventListener("auth-expired", expire); return () => window.removeEventListener("auth-expired", expire); }, []);
  useEffect(() => { if (!token) return; api("/users/me").then(setUser).catch(() => { localStorage.removeItem("eclipse_token"); setToken(""); }); }, [token]);
  if (!token) return <LoginPage onLogin={(nextToken, nextUser) => { localStorage.setItem("eclipse_token", nextToken); setToken(nextToken); setUser(nextUser); }} />;
  function navigate(page) {
    let path = routes.find((route) => route.key === page)?.path || "/";
    if (typeof page === "string" && page.startsWith("task:")) path = `/tasks/${encodeURIComponent(page.slice(5))}`;
    if (window.location.pathname !== path) window.history.pushState({}, "", path);
    setLocation(readLocation());
  }
  function toggleSidebar() {
    setSidebarCollapsed((current) => {
      const next = !current;
      localStorage.setItem("eclipse_sidebar_collapsed", next ? "1" : "0");
      return next;
    });
  }
  async function logout() {
    try { await api("/users/logout", { method: "POST", body: "{}" }); }
    catch { /* Always clear local credentials even if the server is unavailable. */ }
    localStorage.removeItem("eclipse_token");
    setUser(null);
    setToken("");
  }
  const activeRoute = location.key === "task-detail"
    ? { key: "task-detail", label: "Task details", icon: TerminalSquare }
    : routes.find((route) => route.key === location.key) || routes[0];
  const ActiveIcon = activeRoute.icon || LayoutDashboard;
  const RouteComponent = location.key === "task-detail" ? TaskDetailPage : activeRoute.component;
  return <div className={cls("app-shell", sidebarCollapsed && "sidebar-collapsed")}>
    <CustomCursor />
    <div className="ambient-stage" aria-hidden="true"><span className="ambient-wave wave-one" /><span className="ambient-wave wave-two" /><span className="ambient-wave wave-three" /><AmbientCode /></div>
    <div className="scan-overlay" aria-hidden="true" />
    <aside className="sidebar"><button type="button" className="sidebar-toggle" title={sidebarCollapsed ? "Expand Sidebar" : "Close Sidebar"} aria-label={sidebarCollapsed ? "Expand Sidebar" : "Close Sidebar"} aria-expanded={!sidebarCollapsed} onClick={toggleSidebar}>{sidebarCollapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}</button><div className="brand"><div className="brand-mark">{BRAND.mark}</div><div className="brand-copy"><div className="brand-name">{BRAND.name}</div><div className="brand-subtitle">{BRAND.subtitle}</div></div></div><nav className="nav-list">{routes.map((route) => { const Icon = route.icon; const active = location.key === route.key || (location.key === "task-detail" && route.key === "tasks"); return <motion.button key={route.key} title={sidebarCollapsed ? route.label : undefined} aria-label={route.label} whileHover={sidebarCollapsed ? { scale: 1.04 } : { x: 3 }} whileTap={{ scale: 0.98 }} className={cls("nav-item", active && "active")} onClick={() => navigate(route.key)}><Icon size={18} /><span>{route.label}</span></motion.button>; })}</nav><div className="sidebar-foot"><div className="operator" title={sidebarCollapsed ? (user?.username || "operator") : undefined}><span className="status-dot" /><div><strong>{user?.username || "operator"}</strong><small>{user?.role || "single-user"}</small></div></div></div></aside>
    <main className="main"><header className="topbar"><div className="topbar-title"><div className="eyebrow"><ActiveIcon size={14} /> Control Surface</div><h1>{activeRoute.label}</h1></div><div className="top-actions"><div className="runtime-strip" aria-label="System active"><div className={cls("runtime-chip", health?.online ? "online" : "offline")} title="Backend API Status"><Server size={14} /><span><small>API</small><strong>{health === null ? "Checking" : health.online ? "Online" : "Offline"}</strong></span></div><div className={cls("runtime-chip", health?.mcp_enabled ? "online" : "inactive")} title="Model Context Protocol Status"><PlugZap size={14} /><span><small>MCP</small><strong>{health === null ? "Checking" : health.mcp_enabled ? "Enabled" : "Not enabled"}</strong></span></div><div className="runtime-chip" title="Mission implementation thread"><Cpu size={14} /><span><small>WORKERS</small><strong>{health?.task_workers ?? "-"}</strong></span></div><div className="runtime-chip system-clock" title="Local Time"><Clock3 size={14} /><span><small>LOCAL</small><strong>{clock.toLocaleTimeString("en-AU", { hour12: false })}</strong></span></div></div><div className="topbar-command-group"><button className="icon-button topbar-icon-button" title="Refresh Pages and Active Status" aria-label="Refresh Pages and Active Status" onClick={() => { loadHealth(); window.location.reload(); }}><RefreshCw size={16} /></button><button className="icon-button topbar-icon-button" title="Exit Login" aria-label="Exit Login" onClick={logout}><LogOut size={16} /></button></div></div></header><RouteErrorBoundary routeKey={location.key}><Suspense fallback={<div className="route-loading"><span className="status-dot" />LOADING MODULE...</div>}><RouteComponent setPage={navigate} taskId={location.taskId} /></Suspense></RouteErrorBoundary></main>
  </div>;
}
