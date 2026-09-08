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
    {findings.length > 0 && <details className="monitor-evidence"><summary>Confirm evidence leaking. {findings.length}</summary><div className="monitor-evidence-list">{findings.map((finding) => <div className="monitor-evidence-row" key={finding.fingerprint || `${finding.repository}:${finding.path}`}><Badge tone={finding.severity === "critical" ? "danger" : "warn"}>{finding.severity || "high"}</Badge><div><strong>{finding.repository || "Unknown repository"}</strong><code>{finding.path || "-"}</code><span>{finding.evidence || "confirmed"}</span></div>{finding.url ? <a className="icon-button" title="Yes. GitHub View Evidence" aria-label={`View ${finding.repository || "GitHub"} Evidence`} href={finding.url} target="_blank" rel="noreferrer"><ExternalLink size={14} /></a> : <span className="selection-placeholder">-</span>}</div>)}</div></details>}
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
      domain: "For example: example.com",
      ip: "For example: 192.168.1.10",
      site: "For example: https://example.com",
      github: "For example: org/repo Or sensitive keywords.",
      wih: "For example: https://example.com",
      cve: "For example: nginx, grafana, apache http server",
    })[type] || "Please enter the surveillance target.";
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
      setMessage("Automation Configuration Saved");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Save failed: ${error.message}`);
    } finally {
      setSaving(false);
    }
  }
  async function remove(item) {
    if (!window.confirm(`Confirm Delete"${item.name}"?`)) return;
    const base = tab === "monitors" ? "/monitors" : "/scheduled-tasks";
    try {
      await api(`${base}/${item.id}`, { method: "DELETE" });
      setMessage("Record deleted");
      setSelectedIDs((current) => current.filter((id) => id !== item.id));
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Delete failed: ${error.message}`);
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
      setMessage(`State update failed: ${error.message}`);
    }
  }
  async function batchDelete() {
    if (
      !selectedIDs.length ||
      !window.confirm(`Delete the ${selectedIDs.length} selected records?`)
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
      setMessage(`Deleted ${selectedIDs.length} Record`);
      setSelectedIDs([]);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Batch deletion failed: ${error.message}`);
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
        `Already${isEnabled ? "Enable" : "Disable"} ${selectedIDs.length} Planned tasks`,
      );
      setSelectedIDs([]);
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Batch update failed: ${error.message}`);
    }
  }
  async function runNow(item) {
    try {
      await api(tab === "monitors" ? `/monitors/${item.id}/run` : `/scheduled-tasks/${item.id}/run`, {
        method: "POST",
        body: "{}",
      });
      setMessage(tab === "monitors" ? "Control's in the execution queue." : "Created a scan task");
      setRefresh((x) => x + 1);
    } catch (error) {
      setMessage(`Execution failed: ${error.message}`);
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
      setMessage(`Failed to load records: ${error.message}`);
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
  const scopeName = (id) => scanScopes.find((scope) => scope.id === id)?.name || (id ? id.slice(0, 8) : "Compatibility Mode");
  const monitorTypeLabels = { domain: "Domain name", ip: "IP", site: "Site", github: "GitHub Leak", wih: "WIH", cve: "CVE Intelligence" };
  const records =
    tab === "monitors" ? data?.monitors || [] : data?.scheduled_tasks || [];
  const visibleIDs = records.map((item) => item.id);
  const rowSelect = (item) => (
    <input
      key="select"
      className="row-check"
      type="checkbox"
      aria-label={`Select ${item.name}`}
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
      ? `Group: ${groupName(item.asset_group_id)}`
      : item.target,
    scopedMonitorTypes.includes(item.type) ? (item.scope_id ? <Badge key="scope" tone="ok">{scopeName(item.scope_id)}</Badge> : <Badge key="scope">Compatibility Mode</Badge>) : <span key="scope" className="muted">External information</span>,
    `${Math.round(item.interval / 3600)} Hours`,
    <Badge key="status" tone={item.status === "active" ? "ok" : "muted"}>
      {item.status}
    </Badge>,
    item.run_count || 0,
    <div className="row-actions" key="actions">
      <button className="ghost-button compact" onClick={() => runNow(item)}>
        Implementation
      </button>
      <button className="ghost-button compact" onClick={() => openDetail(item)}>
        Records
      </button>
      <button className="ghost-button compact" onClick={() => toggle(item)}>
        {item.status === "active" ? "Pause" : "Restore"}
      </button>
      <button
        className="icon-button"
        title="Edit"
        onClick={() => editMonitor(item)}
      >
        <Edit3 size={14} />
      </button>
      <button
        className="icon-button danger"
        title="Delete"
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
    item.scope_id ? <Badge key="scope" tone="ok">{scopeName(item.scope_id)}</Badge> : <Badge key="scope">Compatibility Mode</Badge>,
    formatDate(item.next_run_at),
    item.is_enabled ? (
      <Badge key="on" tone="ok">
        Enable
      </Badge>
    ) : (
      <Badge key="off">Disable</Badge>
    ),
    `${item.run_count || 0} / ${item.fail_count || 0}`,
    <div className="row-actions" key="actions">
      <button className="ghost-button compact" onClick={() => runNow(item)}>
        Run now.
      </button>
      <button className="ghost-button compact" onClick={() => openDetail(item)}>
        Log
      </button>
      <button className="ghost-button compact" onClick={() => toggle(item)}>
        {item.is_enabled ? "Disable" : "Enable"}
      </button>
      <button className="icon-button" title="Edit" onClick={() => editSchedule(item)}>
        <Edit3 size={14} />
      </button>
      <button
        className="icon-button danger"
        title="Delete"
        onClick={() => remove(item)}
      >
        <Trash2 size={14} />
      </button>
    </div>,
  ]);
  return (
    <Panel
      title="Automate tasks"
      icon={<Activity size={17} />}
      action={
        <button
          className="primary-button"
          onClick={() =>
            setEditor(tab === "monitors" ? blankMonitor() : blankSchedule())
          }
        >
          <Plus size={15} />
          Add{tab === "monitors" ? "Surveillance" : "Planned"}
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
          labels={{ monitors: "Asset monitoring", schedules: "Planned tasks" }}
        />
        <div className="row-actions task-batch-actions">
          {tab === "schedules" && (
            <>
              <button
                className="ghost-button"
                disabled={!selectedIDs.length}
                onClick={() => batchToggle(true)}
              >
                Batch Enable
              </button>
              <button
                className="ghost-button"
                disabled={!selectedIDs.length}
                onClick={() => batchToggle(false)}
              >
                Bulk Disable
              </button>
            </>
          )}
          <button
            className="ghost-button danger"
            disabled={!selectedIDs.length}
            onClick={batchDelete}
          >
            Batch Delete
          </button>
        </div>
      </div>
      {error && <div className="error-box">Failed to load: {error}</div>}
      {message && (
        <div className={message.includes("Failed") ? "error-box" : "success-box"}>
          {message}
        </div>
      )}
      <DataTable
        storageKey={`automation-${tab}`}
        loading={loading}
        columns={
          tab === "monitors"
            ? [
                "Selection",
                "Name",
                "Type",
                "Objective",
                "Authorization scope",
                "Cycle",
                "Status",
                "Runs",
                "Operation",
              ]
            : [
                "Selection",
                "Name",
                "Cycle",
                "Objective",
                "Authorization scope",
                "Next run",
                "Status",
                "Success / Failed",
                "Operation",
              ]
        }
        rows={tab === "monitors" ? monitorRows : scheduleRows}
        headerCells={{
          0: (
            <SelectAllCheckbox
              ids={visibleIDs}
              selectedIDs={selectedIDs}
              setSelectedIDs={setSelectedIDs}
              label={tab === "monitors" ? "All asset monitoring" : "All planned tasks"}
            />
          ),
        }}
        selectionColumn
        empty={tab === "monitors" ? "No asset monitoring for the moment." : "Unscheduled task"}
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
                      ? "Edit asset monitoring"
                      : "Add asset monitoring"
                    : editor.id
                      ? "Edit Schedule Tasks"
                      : "Add Planned Tasks"}
                </h3>
              </div>
              <button
                type="button"
                className="icon-button"
                title="Close"
                onClick={() => setEditor(null)}
              >
                <X size={16} />
              </button>
            </div>
            {editor.kind === "monitor" ? (
              <>
                <div className="editor-grid">
                  <label>
                    Name
                    <input
                      name="monitor_name"
                      required
                      value={editor.name}
                      placeholder="For example: Production domain name inspection"
                      onChange={(e) =>
                        setEditor({ ...editor, name: e.target.value })
                      }
                    />
                  </label>
                  <label>
                    Type of monitoring
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
                      <option value="domain">Domain name</option>
                      <option value="ip">IP</option>
                      <option value="site">Site</option>
                      <option value="github">GitHub</option>
                      <option value="wih">WIH</option>
                      <option value="cve">CVE</option>
                    </select>
                  </label>
                  <label>
                    Target source
                    <select
                      name="monitor_source"
                      value={editor.source}
                      onChange={(e) =>
                        setEditor({ ...editor, source: e.target.value })
                      }
                    >
                      <option value="target">Single objectives</option>
                      {!["github", "wih", "cve"].includes(editor.type) && (
                        <option
                          value="group"
                          disabled={!groupsForType(editor.type).length}
                        >
                          Asset group
                          {groupsForType(editor.type).length
                            ? ""
                            : " (No matching assets yet)"}
                        </option>
                      )}
                    </select>
                  </label>
                  {scopedMonitorTypes.includes(editor.type) && <label>
                    Authorization scope
                    <select
                      name="monitor_scope"
                      value={editor.scope_id}
                      onChange={(e) => setEditor({ ...editor, scope_id: e.target.value })}
                    >
                      <option value="">{defaultScope ? `Default: ${defaultScope.name}` : "Compatibility Mode (No default scope configured)"}</option>
                      {scanScopes.filter((scope) => !scope.is_default).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}
                    </select>
                  </label>}
                  <label>
                    Run interval (Hours)
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
                      Asset group
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
                        <option value="">Select a group that contains the asset type</option>
                        {groupsForType(editor.type).map((group) => (
                          <option key={group.id} value={group.id}>
                            {group.name} (
                            {group.asset_counts?.[editor.type] || 0} One.
                            {editor.type}Assets)
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <label className="field-span-2">
                      Objective
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
                    enable_domain_brute: "Subdomain brute force",
                    enable_port_scan: "Port Scan",
                    enable_site_detect: "Site detection",
                    enable_screenshot: "Site Screenshot",
                    enable_poc_scan: "PoC validation",
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
                    <strong>Call Channel</strong>
                  </div>
                  <div className="plugin-grid automation-flags">
                    {Object.entries({
                      enable_webhook: "Universal Webhook",
                      enable_dingding: "Nails.",
                      enable_feishu: "Flying books.",
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
                  Name
                  <input
                    name="schedule_name"
                    required
                    value={editor.name}
                    placeholder="For example: Daily outnet asset inspection"
                    onChange={(e) =>
                      setEditor({ ...editor, name: e.target.value })
                    }
                  />
                </label>
                <label>
                  Scan Policy
                  <select
                    name="schedule_policy"
                    value={editor.policy_id}
                    onChange={(e) =>
                      setEditor({ ...editor, policy_id: e.target.value })
                    }
                  >
                    <option value="">Basic Scan</option>
                    {(policyData?.policies || []).map((policy) => (
                      <option key={policy.id} value={policy.id}>
                        {policy.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Authorization scope
                  <select
                    name="schedule_scope"
                    value={editor.scope_id}
                    onChange={(e) =>
                      setEditor({ ...editor, scope_id: e.target.value })
                    }
                  >
                    <option value="">{defaultScope ? `Default: ${defaultScope.name}` : "Compatibility Mode (No default scope configured)"}</option>
                    {scanScopes.filter((scope) => !scope.is_default).map((scope) => (
                      <option key={scope.id} value={scope.id}>{scope.name}</option>
                    ))}
                  </select>
                </label>
                <label className="field-span-2">
                  Objective
                  <textarea
                    name="schedule_target"
                    required
                    rows="4"
                    value={editor.target}
                    placeholder="For example: example.com, 192.168.1.10/24 (Multiple targets separated by commas)"
                    onChange={(e) =>
                      setEditor({ ...editor, target: e.target.value })
                    }
                  />
                </label>
                <label>
                  Run cycle
                  <select
                    name="schedule_cron_type"
                    value={editor.cron_type}
                    onChange={(e) =>
                      setEditor({ ...editor, cron_type: e.target.value })
                    }
                  >
                    <option value="once">Once.</option>
                    <option value="daily">Every day 02:00</option>
                    <option value="weekly">Monday 02:00</option>
                    <option value="monthly">Monthly 1 Day 02:00</option>
                    <option value="custom">Custom Cron</option>
                  </select>
                </label>
                {editor.cron_type === "custom" && (
                  <label>
                    Cron (sec min Hour Day Month Week)
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
                  Description
                  <input
                    name="schedule_description"
                    value={editor.description}
                    placeholder="For example: Execution during dawn of working day"
                    onChange={(e) =>
                      setEditor({ ...editor, description: e.target.value })
                    }
                  />
                </label>
              </div>
              <div className="plugin-grid automation-flags">
                {Object.entries({
                  enable_crawler: "Site Path Crawling",
                  enable_file_leak: "Sensitive path detection",
                  enable_poc_detection: "PoC Label Validation",
                }).map(([key, label]) => <label className="feature-toggle" key={key}><input name={`schedule_${key}`} type="checkbox" checked={Boolean(editor.options[key])} onChange={() => setEditor({ ...editor, options: { ...editor.options, [key]: !editor.options[key] } })} /><span>{label}</span></label>)}
              </div>
            </>)}
            <div className="editor-actions">
              <button
                type="button"
                className="ghost-button"
                onClick={() => setEditor(null)}
              >
                Cancel
              </button>
              <button className="primary-button" disabled={saving}>
                {saving ? "Saving..." : "Save"}
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
                title="Close"
                onClick={() => setDetail(null)}
              >
                <X size={16} />
              </button>
            </div>
            {detail.items.length ? (
              detail.items.map((item) => <MonitorHistoryItem item={item} key={item.id} />)
            ) : (
              <EmptyState text="No record of execution at present" />
            )}
          </div>
        )}
      </Modal>
    </Panel>
  );
}
