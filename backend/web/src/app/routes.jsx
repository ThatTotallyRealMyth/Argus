import { lazy } from "react";
import { Activity, Braces, Building2, FileSearch, LayoutDashboard, Library, Network, Radar, ScanSearch, Settings, Shuffle, TerminalSquare } from "lucide-react";

export const routes = [
  { key: "dashboard", path: "/", label: "总览", icon: LayoutDashboard, component: lazy(() => import("../pages/DashboardPage.jsx")) },
  { key: "tasks", path: "/tasks", label: "任务", icon: TerminalSquare, component: lazy(() => import("../pages/TasksPage.jsx")) },
  { key: "assets", path: "/assets", label: "资产", icon: Network, component: lazy(() => import("../pages/AssetsPage.jsx")) },
  { key: "enterprise", path: "/enterprise", label: "企业", icon: Building2, component: lazy(() => import("../pages/EnterprisePage.jsx")) },
  { key: "leads", path: "/leads", label: "线索", icon: Radar, component: lazy(() => import("../pages/LeadsPage.jsx")) },
  { key: "traffic", path: "/traffic", label: "HTTP", icon: FileSearch, component: lazy(() => import("../pages/TrafficPage.jsx")) },
  { key: "library", path: "/library", label: "库管理", icon: Library, component: lazy(() => import("../pages/LibraryPage.jsx")) },
  { key: "policies", path: "/policies", label: "策略", icon: Braces, component: lazy(() => import("../pages/PoliciesPage.jsx")) },
  { key: "automation", path: "/automation", label: "自动化", icon: Activity, component: lazy(() => import("../pages/AutomationPage.jsx")) },
  { key: "proxies", path: "/proxies", label: "代理池", icon: Shuffle, component: lazy(() => import("../pages/ProxyPoolPage.jsx")) },
  { key: "mapping", path: "/mapping", label: "测绘", icon: ScanSearch, component: lazy(() => import("../pages/SpaceSettingsPage.jsx").then((module) => ({ default: module.MappingPage }))) },
  { key: "settings", path: "/settings", label: "设置", icon: Settings, component: lazy(() => import("../pages/SpaceSettingsPage.jsx").then((module) => ({ default: module.SystemSettingsPage }))) },
];
