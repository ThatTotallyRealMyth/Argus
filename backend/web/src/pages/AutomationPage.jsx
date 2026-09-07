import React, { useState } from "react";
import { Activity, Edit3, ExternalLink, Plus, Trash2, X } from "lucide-react";
import {
  Badge,
  DataTable,
  EmptyState,
  Modal,
  Panel,
  SelectAllCheckbox,
  Tabs,
} from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate, parseJSON } from "../lib/api.js";

function MonitorHistoryItem({ item }) {
  const snapshot = parseJSON(item.data, {});
  const findings = Array.isArray(snapshot.findings) ? snapshot.findings : [];
  return <div className="monitor-history-entry">
    <div className="history-row">
      <Badge tone={item.change_type === "error" ? "danger" : item.change_type === "new" || item.change_type === "modified" ? "warn" : "ok"}>{item.status || item.change_type}</Badge>
      <span>{item.message || item.description || "-"}</span>
      <time>{formatDate(item.created_at || item.start_time)}</time>
    </div>
    {findings.length > 0 && <details className="monitor-evidence"><summary>确认凭据泄露证据 {findings.length}</summary><div className="monitor-evidence-list">{findings.map((finding) => <div className="monitor-evidence-row" key={finding.fingerprint || `${finding.repository}:${finding.path}`}><Badge tone={finding.severity === "critical" ? "danger" : "warn"}>{finding.severity || "high"}</Badge><div><strong>{finding.repository || "未知仓库"}</strong><code>{finding.path || "-"}</code><span>{finding.evidence || "confirmed"}</span></div>{finding.url ? <a className="icon-button" title="在 GitHub 查看证据" aria-label={`查看 ${finding.repository || "GitHub"} 证据`} href={finding.url} target="_blank" rel="noreferrer"><ExternalLink size={14} /></a> : <span className="selection-placeholder">-</span>}</div>)}</div></details>}
  </div>;
}

export default function AutomationPage() {
  const [tab, setTab] = useState("monitors");
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState(null);
  const [detail, setDetail] = useState(null);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedIDs, setSelectedIDs] = useState([]);
  const endpoint =
    tab === "monitors"
      ? "/monitors?page=1&page_size=100"
      : "/scheduled-tasks?page=1&page_size=100";
  const { data, loading, error } = useQuery(
    `automation-${tab}-${refresh}`,
    () => api(endpoint),
  );
  const { data: policyData } = useQuery("automation-policies", () =>
    api("/policies?page=1&page_size=100"),
  );
  const { data: scopeData } = useQuery("automation-scan-scopes", () =>
    api("/scan-scopes"),
  );
  const { data: groupData } = useQuery("automation-asset-groups", () =>
    api("/asset-groups"),
  );
  const groupsForType = (type) =>
    (groupData?.groups || []).filter(
      (group) => (group.asset_counts?.[type] || 0) > 0,
    );
  const scopedMonitorTypes = ["domain", "ip", "site", "wih"];
  const monitorTargetPlaceholder = (type) =>
    ({
      domain: "例如：example.com",
      ip: "例如：192.168.1.10",
      site: "例如：https://example.com",
      github: "例如：org/repo 或敏感关键词",
      wih: "例如：https://example.com",
      cve: "例如：nginx, grafana, apache http server",
    })[type] || "请输入监控目标";
  function blankMonitor() {
    return {
      kind: "monitor",
      name: "",
      type: "domain",
      source: "target",
      target: "",
      asset_group_id: "",
      scope_id: "",
      interval: 24,
      options: {
        enable_domain_brute: true,
        enable_port_scan: true,
        enable_site_detect: true,
        enable_screenshot: true,
        enable_poc_scan: false,
      },
      notification_config: {
        enable_webhook: false,
        enable_dingding: false,
        enable_feishu: false,
      },
    };
  }
  function blankSchedule() {
    return {
      kind: "schedule",
      name: "",
      description: "",
      target: "",
      cron_type: "daily",
      cron_expr: "0 0 2 * * *",
      policy_id: "",
      scope_id: "",
      options: {
        enable_crawler: true,
        enable_file_leak: true,
        enable_poc_detection: false,
      },
    };
  }
  async function save(event) {
    event.preventDefault();
    setSaving(true);
    setMessage("");
    try {
      if (editor.kind === "monitor")
        await api(`/monitors${editor.id ? `/${editor.id}` : ""}`, {
          method: editor.id ? "PUT" : "POST",
          body: JSON.stringify({
            name: editor.name,
            type: editor.type,
            target: editor.source === "target" ? editor.target : "",
            asset_group_id:
              editor.source === "group" ? editor.asset_group_id : "",
            scope_id: scopedMonitorTypes.includes(editor.type) ? editor.scope_id : "",
            interval: Number(editor.interval),
            options: editor.options,
            notification_config: editor.notification_config,
          }),
        });
      else
        await api(`/scheduled-tasks${editor.id ? `/${editor.id}` : ""}`, {
          method: editor.id ? "PUT" : "POST",
          body: JSON.stringify({
            name: editor.name,
            description: editor.description,
            cron_type: editor.cron_type,
            cron_expr: editor.cron_type === "custom" ? editor.cron_expr : "",
            policy_id: editor.policy_id,
            scope_id: editor.scope_id,
            task_options: {
              target: editor.target,
              enable_port_scan: true,
              port_scan_type: "top100",
              enable_service_detect: true,
              enable_site_detect: true,
              enable_crawler: editor.options.enable_crawler,
              enable_file_leak: editor.options.enable_file_leak,
              enable_poc_detection: editor.options.enable_poc_detection,
              enable_screenshot: true,
            },
          }),
        });
      setEditor(null);
      setMessage("自动化配置已保存");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`保存失败：${error.message}`);
    } finally {
      setSaving(false);
    }
  }
  async function remove(item) {
    if (!window.confirm(`确认删除“${item.name}”？`)) return;
    const base = tab === "monitors" ? "/monitors" : "/scheduled-tasks";
    try {
      await api(`${base}/${item.id}`, { method: "DELETE" });
      setMessage("记录已删除");
      setSelectedIDs((current) => current.filter((id) => id !== item.id));
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`删除失败：${error.message}`);
    }
  }
  async function toggle(item) {
    try {
      if (tab === "monitors")
        await api(`/monitors/${item.id}/status`, {
          method: "PATCH",
          body: JSON.stringify({
            status: item.status === "active" ? "paused" : "active",
          }),
        });
      else
        await api(`/scheduled-tasks/${item.id}/toggle`, {
          method: "POST",
          body: "{}",
        });
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`状态更新失败：${error.message}`);
    }
  }
  async function batchDelete() {
    if (
      !selectedIDs.length ||
      !window.confirm(`确认删除选中的 ${selectedIDs.length} 条记录？`)
    )
      return;
    const endpoint =
      tab === "monitors"
        ? "/monitors/batch/delete"
        : "/scheduled-tasks/batch/delete";
    const payload =
      tab === "monitors" ? { monitor_ids: selectedIDs } : { ids: selectedIDs };
    try {
      await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
      setMessage(`已删除 ${selectedIDs.length} 条记录`);
      setSelectedIDs([]);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`批量删除失败：${error.message}`);
    }
  }
  async function batchToggle(isEnabled) {
    if (!selectedIDs.length) return;
    try {
      await api("/scheduled-tasks/batch/toggle", {
        method: "POST",
        body: JSON.stringify({ ids: selectedIDs, is_enabled: isEnabled }),
      });
      setMessage(
        `已${isEnabled ? "启用" : "停用"} ${selectedIDs.length} 条计划任务`,
      );
      setSelectedIDs([]);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`批量更新失败：${error.message}`);
    }
  }
  async function runNow(item) {
    try {
      await api(tab === "monitors" ? `/monitors/${item.id}/run` : `/scheduled-tasks/${item.id}/run`, {
        method: "POST",
        body: "{}",
      });
      setMessage(tab === "monitors" ? "监控已进入执行队列" : "已创建一次扫描任务");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`执行失败：${error.message}`);
    }
  }
  async function openDetail(item) {
    try {
      const result = await api(
        tab === "monitors"
          ? `/monitors/${item.id}/results`
          : `/scheduled-tasks/${item.id}/logs`,
      );
      setDetail({
        title: item.name,
        items: result.results || result.logs || [],
      });
    } catch (error) {
      setMessage(`加载记录失败：${error.message}`);
    }
  }
  const groupName = (id) =>
    (groupData?.groups || []).find((group) => group.id === id)?.name || id;
  const editMonitor = (item) =>
    setEditor({
      ...blankMonitor(),
      ...item,
      source: item.asset_group_id ? "group" : "target",
      interval: Math.max(1, Math.round(item.interval / 3600)),
      options: { ...blankMonitor().options, ...parseJSON(item.options, {}) },
      notification_config: {
        ...blankMonitor().notification_config,
        ...parseJSON(item.notification_config, {}),
      },
    });
  const editSchedule = (item) =>
    setEditor({
      ...blankSchedule(),
      ...item,
      target: item.task_options?.target || "",
      options: {
        ...blankSchedule().options,
        enable_crawler: item.task_options?.enable_crawler ?? true,
        enable_file_leak: item.task_options?.enable_file_leak ?? true,
        enable_poc_detection: Boolean(item.task_options?.enable_poc_detection),
      },
    });
  const scanScopes = scopeData?.scopes || [];
  const defaultScope = scanScopes.find((scope) => scope.is_default);
  const scopeName = (id) => scanScopes.find((scope) => scope.id === id)?.name || (id ? id.slice(0, 8) : "兼容模式");
  const monitorTypeLabels = { domain: "域名", ip: "IP", site: "站点", github: "GitHub 泄露", wih: "WIH", cve: "CVE 情报" };
  const records =
    tab === "monitors" ? data?.monitors || [] : data?.scheduled_tasks || [];
  const visibleIDs = records.map((item) => item.id);
  const rowSelection = (item) => (
    <input
      key="select"
      className="row-check"
      type="checkbox"
      aria-label={`选择 ${item.name}`}
      checked={selectedIDs.includes(item.id)}
      onChange={() =>
        setSelectedIDs((current) =>
          current.includes(item.id)
            ? current.filter((id) => id !== item.id)
            : [...current, item.id],
        )
      }
    />
  );
  const monitorRows = (data?.monitors || []).map((item) => [
    rowSelection(item),
    item.name,
    monitorTypeLabels[item.type] || item.type,
    item.asset_group_id
      ? `分组：${groupName(item.asset_group_id)}`
      : item.target,
    scopedMonitorTypes.includes(item.type) ? (item.scope_id ? <Badge key="scope" tone="ok">{scopeName(item.scope_id)}</Badge> : <Badge key="scope">兼容模式</Badge>) : <span key="scope" className="muted">外部情报</span>,
    `${Math.round(item.interval / 3600)} 小时`,
    <Badge key="status" tone={item.status === "active" ? "ok" : "muted"}>
      {item.status}
    </Badge>,
    item.run_count || 0,
    <div className="row-actions" key="actions">
      <button className="ghost-button compact" onClick={() => runNow(item)}>
        执行
      </button>
      <button className="ghost-button compact" onClick={() => openDetail(item)}>
        记录
      </button>
      <button className="ghost-button compact" onClick={() => toggle(item)}>
        {item.status === "active" ? "暂停" : "恢复"}
      </button>
      <button
        className="icon-button"
        title="编辑"
        onClick={() => editMonitor(item)}
      >
        <Edit3 size={14} />
      </button>
      <button
        className="icon-button danger"
        title="删除"
        onClick={() => remove(item)}
      >
        <Trash2 size={14} />
      </button>
    </div>,
  ]);
  const scheduleRows = (data?.scheduled_tasks || []).map((item) => [
    rowSelection(item),
    item.name,
    item.cron_type,
    item.task_options?.target || "-",
    item.scope_id ? <Badge key="scope" tone="ok">{scopeName(item.scope_id)}</Badge> : <Badge key="scope">兼容模式</Badge>,
    formatDate(item.next_run_at),
    item.is_enabled ? (
      <Badge key="on" tone="ok">
        启用
      </Badge>
    ) : (
      <Badge key="off">停用</Badge>
    ),
    `${item.run_count || 0} / ${item.fail_count || 0}`,
    <div className="row-actions" key="actions">
      <button className="ghost-button compact" onClick={() => runNow(item)}>
        立即运行
      </button>
      <button className="ghost-button compact" onClick={() => openDetail(item)}>
        日志
      </button>
      <button className="ghost-button compact" onClick={() => toggle(item)}>
        {item.is_enabled ? "停用" : "启用"}
      </button>
      <button className="icon-button" title="编辑" onClick={() => editSchedule(item)}>
        <Edit3 size={14} />
      </button>
      <button
        className="icon-button danger"
        title="删除"
        onClick={() => remove(item)}
      >
        <Trash2 size={14} />
      </button>
    </div>,
  ]);
  return (
    <Panel
      title="自动化任务"
      icon={<Activity size={17} />}
      action={
        <button
          className="primary-button"
          onClick={() =>
            setEditor(tab === "monitors" ? blankMonitor() : blankSchedule())
          }
        >
          <Plus size={15} />
          新增{tab === "monitors" ? "监控" : "计划"}
        </button>
      }
    >
      <div className="task-toolbar">
        <Tabs
          value={tab}
          setValue={(value) => {
            setTab(value);
            setMessage("");
            setSelectedIDs([]);
          }}
          items={["monitors", "schedules"]}
          labels={{ monitors: "资产监控", schedules: "计划任务" }}
        />
        <div className="row-actions task-batch-actions">
          {tab === "schedules" && (
            <>
              <button
                className="ghost-button"
                disabled={!selectedIDs.length}
                onClick={() => batchToggle(true)}
              >
                批量启用
              </button>
              <button
                className="ghost-button"
                disabled={!selectedIDs.length}
                onClick={() => batchToggle(false)}
              >
                批量停用
              </button>
            </>
          )}
          <button
            className="ghost-button danger"
            disabled={!selectedIDs.length}
            onClick={batchDelete}
          >
            批量删除
          </button>
        </div>
      </div>
      {error && <div className="error-box">加载失败：{error}</div>}
      {message && (
        <div className={message.includes("失败") ? "error-box" : "success-box"}>
          {message}
        </div>
      )}
      <DataTable
        storageKey={`automation-${tab}`}
        loading={loading}
        columns={
          tab === "monitors"
            ? [
                "选择",
                "名称",
                "类型",
                "目标",
                "授权范围",
                "周期",
                "状态",
                "运行次数",
                "操作",
              ]
            : [
                "选择",
                "名称",
                "周期",
                "目标",
                "授权范围",
                "下次运行",
                "状态",
                "成功 / 失败",
                "操作",
              ]
        }
        rows={tab === "monitors" ? monitorRows : scheduleRows}
        headerCells={{
          0: (
            <SelectAllCheckbox
              ids={visibleIDs}
              selectedIDs={selectedIDs}
              setSelectedIDs={setSelectedIDs}
              label={tab === "monitors" ? "全部资产监控" : "全部计划任务"}
            />
          ),
        }}
        selectionColumn
        empty={tab === "monitors" ? "暂无资产监控" : "暂无计划任务"}
      />
      <Modal open={Boolean(editor)}>
        {editor && (
          <form className="library-editor automation-editor" onSubmit={save}>
            <div className="editor-head">
              <div>
                <span className="eyebrow">Automation profile</span>
                <h3>
                  {editor.kind === "monitor"
                    ? editor.id
                      ? "编辑资产监控"
                      : "新增资产监控"
                    : editor.id
                      ? "编辑计划任务"
                      : "新增计划任务"}
                </h3>
              </div>
              <button
                type="button"
                className="icon-button"
                title="关闭"
                onClick={() => setEditor(null)}
              >
                <X size={16} />
              </button>
            </div>
            {editor.kind === "monitor" ? (
              <>
                <div className="editor-grid">
                  <label>
                    名称
                    <input
                      name="monitor_name"
                      required
                      value={editor.name}
                      placeholder="例如：生产域名巡检"
                      onChange={(e) =>
                        setEditor({ ...editor, name: e.target.value })
                      }
                    />
                  </label>
                  <label>
                    监控类型
                    <select
                      name="monitor_type"
                      value={editor.type}
                      onChange={(e) =>
                        setEditor({
                          ...editor,
                          type: e.target.value,
                          source: ["github", "wih", "cve"].includes(e.target.value)
                            ? "target"
                            : editor.source,
                          asset_group_id: "",
                          scope_id: scopedMonitorTypes.includes(e.target.value) ? editor.scope_id : "",
                        })
                      }
                    >
                      <option value="domain">域名</option>
                      <option value="ip">IP</option>
                      <option value="site">站点</option>
                      <option value="github">GitHub</option>
                      <option value="wih">WIH</option>
                      <option value="cve">CVE</option>
                    </select>
                  </label>
                  <label>
                    目标来源
                    <select
                      name="monitor_source"
                      value={editor.source}
                      onChange={(e) =>
                        setEditor({ ...editor, source: e.target.value })
                      }
                    >
                      <option value="target">单个目标</option>
                      {!["github", "wih", "cve"].includes(editor.type) && (
                        <option
                          value="group"
                          disabled={!groupsForType(editor.type).length}
                        >
                          资产分组
                          {groupsForType(editor.type).length
                            ? ""
                            : "（暂无匹配资产）"}
                        </option>
                      )}
                    </select>
                  </label>
                  {scopedMonitorTypes.includes(editor.type) && <label>
                    授权范围
                    <select
                      name="monitor_scope"
                      value={editor.scope_id}
                      onChange={(e) => setEditor({ ...editor, scope_id: e.target.value })}
                    >
                      <option value="">{defaultScope ? `默认：${defaultScope.name}` : "兼容模式（未配置默认范围）"}</option>
                      {scanScopes.filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}
                    </select>
                  </label>}
                  <label>
                    运行间隔（小时）
                    <input
                      name="monitor_interval"
                      type="number"
                      min="1"
                      required
                      value={editor.interval}
                      onChange={(e) =>
                        setEditor({ ...editor, interval: e.target.value })
                      }
                    />
                  </label>
                  {editor.source === "group" ? (
                    <label className="field-span-2">
                      资产分组
                      <select
                        name="asset_group_id"
                        required
                        value={editor.asset_group_id}
                        onChange={(e) =>
                          setEditor({
                            ...editor,
                            asset_group_id: e.target.value,
                          })
                        }
                      >
                        <option value="">选择包含对应资产类型的分组</option>
                        {groupsForType(editor.type).map((group) => (
                          <option key={group.id} value={group.id}>
                            {group.name}（
                            {group.asset_counts?.[editor.type] || 0} 个
                            {editor.type}资产）
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <label className="field-span-2">
                      目标
                      <textarea
                        name="monitor_target"
                        required
                        rows="4"
                        value={editor.target}
                        placeholder={monitorTargetPlaceholder(editor.type)}
                        onChange={(e) =>
                          setEditor({ ...editor, target: e.target.value })
                        }
                      />
                    </label>
                  )}
                </div>
                {!["github", "wih", "cve"].includes(editor.type) && <div className="plugin-grid automation-flags">
                  {Object.entries({
                    enable_domain_brute: "域名爆破",
                    enable_port_scan: "端口扫描",
                    enable_site_detect: "站点识别",
                    enable_screenshot: "站点截图",
                    enable_poc_scan: "PoC 检测",
                  }).map(([key, label]) => (
                    <label className="feature-toggle" key={key}>
                      <input
                        name={key}
                        type="checkbox"
                        checked={editor.options[key]}
                        onChange={() =>
                          setEditor({
                            ...editor,
                            options: {
                              ...editor.options,
                              [key]: !editor.options[key],
                            },
                          })
                        }
                      />
                      <span>{label}</span>
                    </label>
                  ))}
                </div>}
                <section className="editor-section monitor-notification-section">
                  <div className="editor-section-head">
                    <span>02</span>
                    <strong>通知通道</strong>
                  </div>
                  <div className="plugin-grid automation-flags">
                    {Object.entries({
                      enable_webhook: "通用 Webhook",
                      enable_dingding: "钉钉",
                      enable_feishu: "飞书",
                    }).map(([key, label]) => (
                      <label className="feature-toggle" key={key}>
                        <input
                          name={key}
                          type="checkbox"
                          checked={Boolean(editor.notification_config[key])}
                          onChange={() =>
                            setEditor({
                              ...editor,
                              notification_config: {
                                ...editor.notification_config,
                                [key]: !editor.notification_config[key],
                              },
                            })
                          }
                        />
                        <span>{label}</span>
                      </label>
                    ))}
                  </div>
                </section>
              </>
            ) : (<>
              <div className="editor-grid">
                <label>
                  名称
                  <input
                    name="schedule_name"
                    required
                    value={editor.name}
                    placeholder="例如：每日外网资产巡检"
                    onChange={(e) =>
                      setEditor({ ...editor, name: e.target.value })
                    }
                  />
                </label>
                <label>
                  扫描策略
                  <select
                    name="schedule_policy"
                    value={editor.policy_id}
                    onChange={(e) =>
                      setEditor({ ...editor, policy_id: e.target.value })
                    }
                  >
                    <option value="">基础扫描</option>
                    {(policyData?.policies || []).map((policy) => (
                      <option key={policy.id} value={policy.id}>
                        {policy.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  授权范围
                  <select
                    name="schedule_scope"
                    value={editor.scope_id}
                    onChange={(e) =>
                      setEditor({ ...editor, scope_id: e.target.value })
                    }
                  >
                    <option value="">{defaultScope ? `默认：${defaultScope.name}` : "兼容模式（未配置默认范围）"}</option>
                    {scanScopes.filter((scope) => !scope.is_default).map((scope) => (
                      <option key={scope.id} value={scope.id}>{scope.name}</option>
                    ))}
                  </select>
                </label>
                <label className="field-span-2">
                  目标
                  <textarea
                    name="schedule_target"
                    required
                    rows="4"
                    value={editor.target}
                    placeholder="例如：example.com, 192.168.1.10/24（多个目标用逗号分隔）"
                    onChange={(e) =>
                      setEditor({ ...editor, target: e.target.value })
                    }
                  />
                </label>
                <label>
                  运行周期
                  <select
                    name="schedule_cron_type"
                    value={editor.cron_type}
                    onChange={(e) =>
                      setEditor({ ...editor, cron_type: e.target.value })
                    }
                  >
                    <option value="once">一次</option>
                    <option value="daily">每天 02:00</option>
                    <option value="weekly">每周一 02:00</option>
                    <option value="monthly">每月 1 日 02:00</option>
                    <option value="custom">自定义 Cron</option>
                  </select>
                </label>
                {editor.cron_type === "custom" && (
                  <label>
                    Cron（秒 分 时 日 月 周）
                    <input
                      name="schedule_cron_expr"
                      required
                      value={editor.cron_expr}
                      onChange={(e) =>
                        setEditor({ ...editor, cron_expr: e.target.value })
                      }
                    />
                  </label>
                )}
                <label className="field-span-2">
                  说明
                  <input
                    name="schedule_description"
                    value={editor.description}
                    placeholder="例如：工作日凌晨执行"
                    onChange={(e) =>
                      setEditor({ ...editor, description: e.target.value })
                    }
                  />
                </label>
              </div>
              <div className="plugin-grid automation-flags">
                {Object.entries({
                  enable_crawler: "站点路径爬取",
                  enable_file_leak: "敏感路径探测",
                  enable_poc_detection: "PoC 漏洞验证",
                }).map(([key, label]) => <label className="feature-toggle" key={key}><input name={`schedule_${key}`} type="checkbox" checked={Boolean(editor.options[key])} onChange={() => setEditor({ ...editor, options: { ...editor.options, [key]: !editor.options[key] } })} /><span>{label}</span></label>)}
              </div>
            </>)}
            <div className="editor-actions">
              <button
                type="button"
                className="ghost-button"
                onClick={() => setEditor(null)}
              >
                取消
              </button>
              <button className="primary-button" disabled={saving}>
                {saving ? "保存中..." : "保存"}
              </button>
            </div>
          </form>
        )}
      </Modal>
      <Modal open={Boolean(detail)}>
        {detail && (
          <div className="library-editor automation-detail">
            <div className="editor-head">
              <div>
                <span className="eyebrow">Execution history</span>
                <h3>{detail.title}</h3>
              </div>
              <button
                type="button"
                className="icon-button"
                title="关闭"
                onClick={() => setDetail(null)}
              >
                <X size={16} />
              </button>
            </div>
            {detail.items.length ? (
              detail.items.map((item) => <MonitorHistoryItem item={item} key={item.id} />)
            ) : (
              <EmptyState text="暂无执行记录" />
            )}
          </div>
        )}
      </Modal>
    </Panel>
  );
}
