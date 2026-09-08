import { lazy } from "react";
import { Activity, Braces, Building2, FileSearch, LayoutDashboard, Library, Network, Radar, ScanSearch, Settings, Shuffle, TerminalSquare } from "lucide-react";

export const routes = [
  { key: "dashboard", path: "/", label: "Overview", icon: LayoutDashboard, component: lazy(() => import("../pages/DashboardPage.jsx")) },
  { key: "tasks", path: "/tasks", label: "Tasks", icon: TerminalSquare, component: lazy(() => import("../pages/TasksPage.jsx")) },
  { key: "assets", path: "/assets", label: "Assets", icon: Network, component: lazy(() => import("../pages/AssetsPage.jsx")) },
  { key: "enterprise", path: "/enterprise", label: "Enterprise", icon: Building2, component: lazy(() => import("../pages/EnterprisePage.jsx")) },
  { key: "leads", path: "/leads", label: "Hunting leads", icon: Radar, component: lazy(() => import("../pages/LeadsPage.jsx")) },
  { key: "traffic", path: "/traffic", label: "HTTP", icon: FileSearch, component: lazy(() => import("../pages/TrafficPage.jsx")) },
  { key: "library", path: "/library", label: "Library management", icon: Library, component: lazy(() => import("../pages/LibraryPage.jsx")) },
  { key: "policies", path: "/policies", label: "Policies", icon: Braces, component: lazy(() => import("../pages/PoliciesPage.jsx")) },
  { key: "automation", path: "/automation", label: "Automation", icon: Activity, component: lazy(() => import("../pages/AutomationPage.jsx")) },
  { key: "proxies", path: "/proxies", label: "Proxy pool", icon: Shuffle, component: lazy(() => import("../pages/ProxyPoolPage.jsx")) },
  { key: "mapping", path: "/mapping", label: "Intelligence", icon: ScanSearch, component: lazy(() => import("../pages/SpaceSettingsPage.jsx").then((module) => ({ default: module.MappingPage }))) },
  { key: "settings", path: "/settings", label: "Settings", icon: Settings, component: lazy(() => import("../pages/SpaceSettingsPage.jsx").then((module) => ({ default: module.SystemSettingsPage }))) },
];
