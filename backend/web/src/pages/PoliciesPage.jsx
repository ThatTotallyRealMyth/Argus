import React, { useState } from "react";
import { Braces, CheckCircle2, Edit3, Plus, ShieldCheck, Trash2, X } from "lucide-react";
import { Badge, DataTable, Modal, Panel, SelectAllCheckbox, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, formatDate } from "../lib/api.js";

function splitRules(value) {
  return String(value || "").split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

export default function PoliciesPage() {
  const [tab, setTab] = useState("policies");
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState(null);
  const [scopeEditor, setScopeEditor] = useState(null);
  const [scopeCheck, setScopeCheck] = useState(null);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const [selectedIDs, setSelectedIDs] = useState([]);
  const { data, loading, error } = useQuery(`policies-${refresh}`, () => api("/policies?page=1&page_size=100"));
  const { data: scopeData, loading: scopeLoading, error: scopeError } = useQuery(`scan-scopes-${refresh}`, () => api("/scan-scopes"));
  const groups = [
    { title: "Domain discovery", items: [["enable_domain_brute", "Subdomain brute force"], ["smart_dict_gen", "Smart Dictionary"], ["enable_domain_plugins", "Intelligence providers"], ["enable_arl_history", "Historical assets"]] },
    { title: "Network discovery", items: [["enable_service_detect", "Service detection"], ["enable_os_detect", "Operating system"], ["enable_ssl_cert", "SSL Certificate"], ["skip_cdn", "Skip CDN"]] },
    { title: "Sites and risks", items: [["enable_site_detect", "Site detection"], ["enable_search_engine", "Search engine"], ["enable_crawler", "Web crawler"], ["enable_screenshot", "Site Screenshot"], ["enable_file_leak", "Exposed-file checks"], ["enable_host_collision", "Host Collision"], ["enable_poc_detection", "PoC validation"], ["enable_wih", "WIH"]] },
  ];

  function blank() {
    return { id: "", name: "", description: "", config: { domain_brute_type: "big", port_scan_type: "top100", domain_plugins: ["crtsh", "hackertarget"], enable_domain_brute: true, smart_dict_gen: true, enable_domain_plugins: true, enable_service_detect: true, enable_ssl_cert: true, enable_site_detect: true, enable_crawler: true, enable_screenshot: true, enable_file_leak: true } };
  }

  function blankScope() {
    const firstScope = !(scopeData?.scopes || []).length;
    return { id: "", name: "", description: "", allowText: "", denyText: "", is_default: firstScope, defaultLocked: firstScope, testTarget: "" };
  }

  function toggle(key) {
    setEditor((current) => ({ ...current, config: { ...current.config, [key]: !current.config[key] } }));
  }

  async function save(event) {
    event.preventDefault(); setSaving(true); setMessage("");
    try {
      await api(`/policies${editor.id ? `/${editor.id}` : ""}`, { method: editor.id ? "PUT" : "POST", body: JSON.stringify(editor) });
      setEditor(null); setMessage("Policy saved"); setRefresh((value) => value + 1);
    } catch (saveError) { setMessage(`Save failed: ${saveError.message}`); } finally { setSaving(false); }
  }

  async function remove(policy) {
    if (!window.confirm(`Confirm removal policy"${policy.name}"?`)) return;
    try { await api(`/policies/${policy.id}`, { method: "DELETE" }); setMessage("Policy deleted"); setSelectedIDs((current) => current.filter((id) => id !== policy.id)); setRefresh((value) => value + 1); }
    catch (removeError) { setMessage(`Delete failed: ${removeError.message}`); }
  }

  async function setDefault(policy) {
    try { await api(`/policies/${policy.id}/set-default`, { method: "POST", body: "{}" }); setMessage(`Already"${policy.name}"Set as Default Policy`); setSelectedIDs((current) => current.filter((id) => id !== policy.id)); setRefresh((value) => value + 1); }
    catch (defaultError) { setMessage(`Settings failed: ${defaultError.message}`); }
  }

  async function batchDelete() {
    if (!selectedIDs.length || !window.confirm(`Delete the ${selectedIDs.length} selected policies?`)) return;
    try { await api("/policies/batch/delete", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) }); setMessage(`Deleted ${selectedIDs.length} policies`); setSelectedIDs([]); setRefresh((value) => value + 1); }
    catch (batchError) { setMessage(`Batch deletion failed: ${batchError.message}`); }
  }

  function editScope(scope) {
    setScopeCheck(null);
    setScopeEditor({ ...scope, allowText: (scope.allow_rules || []).join("\n"), denyText: (scope.deny_rules || []).join("\n"), defaultLocked: scope.is_default, testTarget: "" });
  }

  async function saveScope(event) {
    event.preventDefault(); setSaving(true); setMessage("");
    const payload = { name: scopeEditor.name, description: scopeEditor.description, allow_rules: splitRules(scopeEditor.allowText), deny_rules: splitRules(scopeEditor.denyText), is_default: scopeEditor.is_default };
    try {
      await api(`/scan-scopes${scopeEditor.id ? `/${scopeEditor.id}` : ""}`, { method: scopeEditor.id ? "PUT" : "POST", body: JSON.stringify(payload) });
      setScopeEditor(null); setScopeCheck(null); setMessage("Authorization scope saved"); setRefresh((value) => value + 1);
    } catch (saveError) { setMessage(`Save failed: ${saveError.message}`); } finally { setSaving(false); }
  }

  async function validateScope() {
    if (!scopeEditor.testTarget.trim()) return;
    setScopeCheck({ loading: true });
    try {
      const result = await api("/scan-scopes/validate", { method: "POST", body: JSON.stringify({ name: scopeEditor.name, allow_rules: splitRules(scopeEditor.allowText), deny_rules: splitRules(scopeEditor.denyText), target: scopeEditor.testTarget }) });
      setScopeCheck(result);
    } catch (checkError) { setScopeCheck({ allowed: false, error: checkError.message }); }
  }

  async function setDefaultScope(scope) {
    try { await api(`/scan-scopes/${scope.id}/set-default`, { method: "POST", body: "{}" }); setMessage(`"${scope.name}"It's a default authorization.`); setRefresh((value) => value + 1); }
    catch (defaultError) { setMessage(`Settings failed: ${defaultError.message}`); }
  }

  async function removeScope(scope) {
    if (!window.confirm(`Confirm deletion of the authorization scope"${scope.name}"?The range that has been quoted by the task will not be deleted.`)) return;
    try { await api(`/scan-scopes/${scope.id}`, { method: "DELETE" }); setMessage("Delegation of authority deleted"); setRefresh((value) => value + 1); }
    catch (removeError) { setMessage(`Delete failed: ${removeError.message}`); }
  }

  const policies = data?.policies || [];
  const scopes = scopeData?.scopes || [];
  const selectableIDs = policies.filter((policy) => !policy.is_default).map((policy) => policy.id);
  const rowSelect = (policy) => <input key="select" className="row-check" type="checkbox" disabled={policy.is_default} aria-label={policy.is_default ? `${policy.name}Cannot be deleted` : `Select ${policy.name}`} checked={selectedIDs.includes(policy.id)} onChange={() => setSelectedIDs((current) => current.includes(policy.id) ? current.filter((id) => id !== policy.id) : [...current, policy.id])} />;

  return <Panel title="Strategy and authorization" icon={tab === "policies" ? <Braces size={17} /> : <ShieldCheck size={17} />} action={<button className="primary-button" onClick={() => { setMessage(""); if (tab === "policies") setEditor(blank()); else { setScopeCheck(null); setScopeEditor(blankScope()); } }}><Plus size={15} />{tab === "policies" ? "New Policy" : "New Scope"}</button>}>
    <div className="task-toolbar"><Tabs value={tab} setValue={(value) => { setTab(value); setMessage(""); setSelectedIDs([]); }} items={["policies", "scopes"]} labels={{ policies: "Scan Policy", scopes: "Authorization scope" }} />{tab === "policies" && <div className="row-actions task-batch-actions"><button className="ghost-button danger" disabled={!selectedIDs.length} onClick={batchDelete}>Batch Delete</button></div>}</div>
    {(error || scopeError) && <div className="error-box">Failed to load: {error || scopeError}</div>}
    {message && <div className={message.includes("Failed") ? "error-box" : "success-box"}>{message}</div>}
    {tab === "policies" ? <>
      <DataTable storageKey="policies-list" loading={loading} columns={["Selection", "Name", "Description", "Default", "Updated", "Actions"]} rows={policies.map((policy) => [rowSelection(policy), policy.name, policy.description || "-", policy.is_default ? <Badge key="default" tone="ok">Default</Badge> : "-", formatDate(policy.updated_at), <div className="row-actions" key="actions"><button className="ghost-button compact" disabled={policy.is_default} onClick={() => setDefault(policy)}>Set as Default</button><button className="icon-button" title="Edit" onClick={() => setEditor({ ...policy, config: { ...blank().config, ...(policy.config || {}) } })}><Edit3 size={14} /></button><button className="icon-button danger" title="Delete" onClick={() => remove(policy)}><Trash2 size={14} /></button></div>])} headerCells={{ 0: <SelectAllCheckbox ids={selectableIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="All Removed Policies" /> }} selectionColumn empty="No scan policies found." />
    </> : <>
      <DataTable storageKey="scan-scopes-list" loading={scopeLoading} columns={["Name", "Allow rules", "Exclude rules", "Enforcement", "Updated", "Actions"]} rows={scopes.map((scope) => [<div className="enterprise-primary" key="name"><strong>{scope.name}</strong><span>{scope.description || "-"}</span></div>, (scope.allow_rules || []).length, (scope.deny_rules || []).length, scope.is_default ? <Badge key="default" tone="ok">Default</Badge> : <Badge key="optional">Optional</Badge>, formatDate(scope.updated_at), <div className="row-actions" key="actions"><button className="ghost-button compact" disabled={scope.is_default} onClick={() => setDefaultScope(scope)}>Set as Default</button><button className="icon-button" title="Edit" onClick={() => editScope(scope)}><Edit3 size={14} /></button><button className="icon-button danger" title="Delete" disabled={scope.is_default} onClick={() => removeScope(scope)}><Trash2 size={14} /></button></div>])} empty="No authorization scopes configured" />
      {!scopes.length && !scopeLoading && <div className="scope-compat-notice"><ShieldCheck size={16} /><span>Compatibility mode is active. Creating the first scope will make it the default boundary.</span></div>}
    </>}

    <Modal open={Boolean(editor)}>{editor && <form className="library-editor policy-editor" onSubmit={save}><div className="editor-head"><div><span className="eyebrow">Scan policy</span><h3>{editor.id ? "Edit Policy" : "New Policy"}</h3></div><button type="button" className="icon-button" title="Close" onClick={() => setEditor(null)}><X size={16} /></button></div><div className="editor-grid"><label className="field-span-2">Policy name<input required value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} /></label><label className="field-span-2">Description<input value={editor.description || ""} onChange={(event) => setEditor({ ...editor, description: event.target.value })} /></label><label>Subdomain brute force<select value={editor.config.domain_brute_type || "big"} onChange={(event) => setEditor({ ...editor, config: { ...editor.config, domain_brute_type: event.target.value } })}><option value="big">Big Dictionary</option><option value="test">Test Dictionary</option></select></label><label>Port Scan<select value={editor.config.port_scan_type || "top100"} onChange={(event) => setEditor({ ...editor, config: { ...editor.config, port_scan_type: event.target.value } })}><option value="test">Test Port</option><option value="top100">TOP 100</option><option value="top1000">TOP 1000</option><option value="all">Full Port</option></select></label></div><div className="policy-feature-grid">{groups.map((group) => <section className="task-feature-group" key={group.title}><div className="editor-section-head"><strong>{group.title}</strong></div>{group.items.map(([key, label]) => <label className="feature-toggle" key={key}><input type="checkbox" checked={Boolean(editor.config[key])} onChange={() => toggle(key)} /><span>{label}</span></label>)}</section>)}</div><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditor(null)}>Cancel</button><button className="primary-button" disabled={saving}>{saving ? "Saving..." : "Save Policy"}</button></div></form>}</Modal>

    <Modal open={Boolean(scopeEditor)}>{scopeEditor && <form className="library-editor scope-editor" onSubmit={saveScope}><div className="editor-head"><div><span className="eyebrow">Engagement boundary</span><h3>{scopeEditor.id ? "Edit permissions" : "New Mandate"}</h3></div><button type="button" className="icon-button" title="Close" aria-label="Close Mandate Scope" onClick={() => setScopeEditor(null)}><X size={16} /></button></div>
      <div className="editor-grid"><label className="field-span-2">Scope name<input autoFocus required maxLength="255" value={scopeEditor.name} onChange={(event) => setScopeEditor({ ...scopeEditor, name: event.target.value })} /></label><label className="field-span-2">Description<input maxLength="2000" value={scopeEditor.description || ""} onChange={(event) => setScopeEditor({ ...scopeEditor, description: event.target.value })} /></label></div>
      <div className="scope-rule-grid"><label>Allow rules<textarea required rows="8" value={scopeEditor.allowText} onChange={(event) => { setScopeEditor({ ...scopeEditor, allowText: event.target.value }); setScopeCheck(null); }} placeholder={"example.com\n*.example.com\n203.0.113.0/24"} /></label><label>Exclude rules<textarea rows="8" value={scopeEditor.denyText} onChange={(event) => { setScopeEditor({ ...scopeEditor, denyText: event.target.value }); setScopeCheck(null); }} placeholder={"admin.example.com\n203.0.113.50"} /></label></div>
      <label className="feature-toggle scope-default-toggle" title={scopeEditor.defaultLocked ? "Set another scope as default first." : "Tasks without an explicit scope use this boundary"}><input type="checkbox" checked={scopeEditor.is_default} disabled={scopeEditor.defaultLocked} onChange={(event) => setScopeEditor({ ...scopeEditor, is_default: event.target.checked })} /><span>{scopeEditor.defaultLocked ? "Default authorization scope (set another scope as default first)" : "Set as Default Authorization Scope"}</span></label>
      <div className="scope-validator"><label>Target preflight<input value={scopeEditor.testTarget} onChange={(event) => { setScopeEditor({ ...scopeEditor, testTarget: event.target.value }); setScopeCheck(null); }} placeholder="api.example.com, 203.0.113.10" /></label><button type="button" className="ghost-button" disabled={!scopeEditor.testTarget.trim() || scopeCheck?.loading} onClick={validateScope}><CheckCircle2 size={14} />{scopeCheck?.loading ? "Checking" : "Check"}</button></div>
      {scopeCheck && !scopeCheck.loading && <div className={scopeCheck.allowed ? "scope-check-result allowed" : "scope-check-result blocked"}><strong>{scopeCheck.allowed ? "All targets are in scope" : "Some targets are out of scope"}</strong><span>{scopeCheck.error || (scopeCheck.targets || []).map((item) => `${item.normalized || item.input}: ${item.reason}${item.matched_rule ? ` (${item.matched_rule})` : ""}`).join("; ")}</span></div>}
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setScopeEditor(null)}>Cancel</button><button className="primary-button" disabled={saving || !scopeEditor.name.trim() || !splitRules(scopeEditor.allowText).length}>{saving ? "Saving..." : "Save scope"}</button></div>
    </form>}</Modal>
  </Panel>;
}
