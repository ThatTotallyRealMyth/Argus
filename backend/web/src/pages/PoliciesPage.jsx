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
    { title: "域名发现", items: [["enable_domain_brute", "域名爆破"], ["smart_dict_gen", "智能字典"], ["enable_domain_plugins", "测绘数据源"], ["enable_arl_history", "历史资产"]] },
    { title: "网络识别", items: [["enable_service_detect", "服务识别"], ["enable_os_detect", "操作系统"], ["enable_ssl_cert", "SSL 证书"], ["skip_cdn", "跳过 CDN"]] },
    { title: "站点与风险", items: [["enable_site_detect", "站点识别"], ["enable_search_engine", "搜索引擎"], ["enable_crawler", "站点爬虫"], ["enable_screenshot", "站点截图"], ["enable_file_leak", "文件泄露"], ["enable_host_collision", "Host 碰撞"], ["enable_poc_detection", "PoC 检测"], ["enable_wih", "WIH"]] },
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
      setEditor(null); setMessage("策略已保存"); setRefresh((value) => value + 1);
    } catch (saveError) { setMessage(`保存失败：${saveError.message}`); } finally { setSaving(false); }
  }

  async function remove(policy) {
    if (!window.confirm(`确认删除策略“${policy.name}”？`)) return;
    try { await api(`/policies/${policy.id}`, { method: "DELETE" }); setMessage("策略已删除"); setSelectedIDs((current) => current.filter((id) => id !== policy.id)); setRefresh((value) => value + 1); }
    catch (removeError) { setMessage(`删除失败：${removeError.message}`); }
  }

  async function setDefault(policy) {
    try { await api(`/policies/${policy.id}/set-default`, { method: "POST", body: "{}" }); setMessage(`已将“${policy.name}”设为默认策略`); setSelectedIDs((current) => current.filter((id) => id !== policy.id)); setRefresh((value) => value + 1); }
    catch (defaultError) { setMessage(`设置失败：${defaultError.message}`); }
  }

  async function batchDelete() {
    if (!selectedIDs.length || !window.confirm(`确认删除选中的 ${selectedIDs.length} 条策略？`)) return;
    try { await api("/policies/batch/delete", { method: "POST", body: JSON.stringify({ ids: selectedIDs }) }); setMessage(`已删除 ${selectedIDs.length} 条策略`); setSelectedIDs([]); setRefresh((value) => value + 1); }
    catch (batchError) { setMessage(`批量删除失败：${batchError.message}`); }
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
      setScopeEditor(null); setScopeCheck(null); setMessage("授权范围已保存"); setRefresh((value) => value + 1);
    } catch (saveError) { setMessage(`保存失败：${saveError.message}`); } finally { setSaving(false); }
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
    try { await api(`/scan-scopes/${scope.id}/set-default`, { method: "POST", body: "{}" }); setMessage(`“${scope.name}”已成为默认授权范围`); setRefresh((value) => value + 1); }
    catch (defaultError) { setMessage(`设置失败：${defaultError.message}`); }
  }

  async function removeScope(scope) {
    if (!window.confirm(`确认删除授权范围“${scope.name}”？已被任务引用的范围不会被删除。`)) return;
    try { await api(`/scan-scopes/${scope.id}`, { method: "DELETE" }); setMessage("授权范围已删除"); setRefresh((value) => value + 1); }
    catch (removeError) { setMessage(`删除失败：${removeError.message}`); }
  }

  const policies = data?.policies || [];
  const scopes = scopeData?.scopes || [];
  const selectableIDs = policies.filter((policy) => !policy.is_default).map((policy) => policy.id);
  const rowSelection = (policy) => <input key="select" className="row-check" type="checkbox" disabled={policy.is_default} aria-label={policy.is_default ? `${policy.name}不可删除` : `选择 ${policy.name}`} checked={selectedIDs.includes(policy.id)} onChange={() => setSelectedIDs((current) => current.includes(policy.id) ? current.filter((id) => id !== policy.id) : [...current, policy.id])} />;

  return <Panel title="策略与授权" icon={tab === "policies" ? <Braces size={17} /> : <ShieldCheck size={17} />} action={<button className="primary-button" onClick={() => { setMessage(""); if (tab === "policies") setEditor(blank()); else { setScopeCheck(null); setScopeEditor(blankScope()); } }}><Plus size={15} />{tab === "policies" ? "新建策略" : "新建范围"}</button>}>
    <div className="task-toolbar"><Tabs value={tab} setValue={(value) => { setTab(value); setMessage(""); setSelectedIDs([]); }} items={["policies", "scopes"]} labels={{ policies: "扫描策略", scopes: "授权范围" }} />{tab === "policies" && <div className="row-actions task-batch-actions"><button className="ghost-button danger" disabled={!selectedIDs.length} onClick={batchDelete}>批量删除</button></div>}</div>
    {(error || scopeError) && <div className="error-box">加载失败：{error || scopeError}</div>}
    {message && <div className={message.includes("失败") ? "error-box" : "success-box"}>{message}</div>}
    {tab === "policies" ? <>
      <DataTable storageKey="policies-list" loading={loading} columns={["选择", "名称", "说明", "默认", "更新时间", "操作"]} rows={policies.map((policy) => [rowSelection(policy), policy.name, policy.description || "-", policy.is_default ? <Badge key="default" tone="ok">默认</Badge> : "-", formatDate(policy.updated_at), <div className="row-actions" key="actions"><button className="ghost-button compact" disabled={policy.is_default} onClick={() => setDefault(policy)}>设为默认</button><button className="icon-button" title="编辑" onClick={() => setEditor({ ...policy, config: { ...blank().config, ...(policy.config || {}) } })}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" onClick={() => remove(policy)}><Trash2 size={14} /></button></div>])} headerCells={{ 0: <SelectAllCheckbox ids={selectableIDs} selectedIDs={selectedIDs} setSelectedIDs={setSelectedIDs} label="全部可删除策略" /> }} selectionColumn empty="暂无策略" />
    </> : <>
      <DataTable storageKey="scan-scopes-list" loading={scopeLoading} columns={["名称", "允许规则", "排除规则", "执行边界", "更新时间", "操作"]} rows={scopes.map((scope) => [<div className="enterprise-primary" key="name"><strong>{scope.name}</strong><span>{scope.description || "-"}</span></div>, (scope.allow_rules || []).length, (scope.deny_rules || []).length, scope.is_default ? <Badge key="default" tone="ok">默认强制</Badge> : <Badge key="optional">可选</Badge>, formatDate(scope.updated_at), <div className="row-actions" key="actions"><button className="ghost-button compact" disabled={scope.is_default} onClick={() => setDefaultScope(scope)}>设为默认</button><button className="icon-button" title="编辑" onClick={() => editScope(scope)}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" disabled={scope.is_default} onClick={() => removeScope(scope)}><Trash2 size={14} /></button></div>])} empty="尚未配置授权范围" />
      {!scopes.length && !scopeLoading && <div className="scope-compat-notice"><ShieldCheck size={16} /><span>当前为兼容模式；创建首个范围后会自动设为默认边界。</span></div>}
    </>}

    <Modal open={Boolean(editor)}>{editor && <form className="library-editor policy-editor" onSubmit={save}><div className="editor-head"><div><span className="eyebrow">Scan policy</span><h3>{editor.id ? "编辑策略" : "新建策略"}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setEditor(null)}><X size={16} /></button></div><div className="editor-grid"><label className="field-span-2">策略名称<input required value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} /></label><label className="field-span-2">说明<input value={editor.description || ""} onChange={(event) => setEditor({ ...editor, description: event.target.value })} /></label><label>域名爆破<select value={editor.config.domain_brute_type || "big"} onChange={(event) => setEditor({ ...editor, config: { ...editor.config, domain_brute_type: event.target.value } })}><option value="big">大字典</option><option value="test">测试字典</option></select></label><label>端口扫描<select value={editor.config.port_scan_type || "top100"} onChange={(event) => setEditor({ ...editor, config: { ...editor.config, port_scan_type: event.target.value } })}><option value="test">测试端口</option><option value="top100">TOP 100</option><option value="top1000">TOP 1000</option><option value="all">全端口</option></select></label></div><div className="policy-feature-grid">{groups.map((group) => <section className="task-feature-group" key={group.title}><div className="editor-section-head"><strong>{group.title}</strong></div>{group.items.map(([key, label]) => <label className="feature-toggle" key={key}><input type="checkbox" checked={Boolean(editor.config[key])} onChange={() => toggle(key)} /><span>{label}</span></label>)}</section>)}</div><div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditor(null)}>取消</button><button className="primary-button" disabled={saving}>{saving ? "保存中..." : "保存策略"}</button></div></form>}</Modal>

    <Modal open={Boolean(scopeEditor)}>{scopeEditor && <form className="library-editor scope-editor" onSubmit={saveScope}><div className="editor-head"><div><span className="eyebrow">Engagement boundary</span><h3>{scopeEditor.id ? "编辑授权范围" : "新建授权范围"}</h3></div><button type="button" className="icon-button" title="关闭" aria-label="关闭授权范围" onClick={() => setScopeEditor(null)}><X size={16} /></button></div>
      <div className="editor-grid"><label className="field-span-2">范围名称<input autoFocus required maxLength="255" value={scopeEditor.name} onChange={(event) => setScopeEditor({ ...scopeEditor, name: event.target.value })} /></label><label className="field-span-2">说明<input maxLength="2000" value={scopeEditor.description || ""} onChange={(event) => setScopeEditor({ ...scopeEditor, description: event.target.value })} /></label></div>
      <div className="scope-rule-grid"><label>允许规则<textarea required rows="8" value={scopeEditor.allowText} onChange={(event) => { setScopeEditor({ ...scopeEditor, allowText: event.target.value }); setScopeCheck(null); }} placeholder={"example.com\n*.example.com\n203.0.113.0/24"} /></label><label>排除规则<textarea rows="8" value={scopeEditor.denyText} onChange={(event) => { setScopeEditor({ ...scopeEditor, denyText: event.target.value }); setScopeCheck(null); }} placeholder={"admin.example.com\n203.0.113.50"} /></label></div>
      <label className="feature-toggle scope-default-toggle" title={scopeEditor.defaultLocked ? "请先将另一个范围设为默认" : "未指定范围的任务将使用该边界"}><input type="checkbox" checked={scopeEditor.is_default} disabled={scopeEditor.defaultLocked} onChange={(event) => setScopeEditor({ ...scopeEditor, is_default: event.target.checked })} /><span>{scopeEditor.defaultLocked ? "默认授权范围（需从其他范围切换）" : "设为默认授权范围"}</span></label>
      <div className="scope-validator"><label>目标预检<input value={scopeEditor.testTarget} onChange={(event) => { setScopeEditor({ ...scopeEditor, testTarget: event.target.value }); setScopeCheck(null); }} placeholder="api.example.com, 203.0.113.10" /></label><button type="button" className="ghost-button" disabled={!scopeEditor.testTarget.trim() || scopeCheck?.loading} onClick={validateScope}><CheckCircle2 size={14} />{scopeCheck?.loading ? "检查中" : "检查"}</button></div>
      {scopeCheck && !scopeCheck.loading && <div className={scopeCheck.allowed ? "scope-check-result allowed" : "scope-check-result blocked"}><strong>{scopeCheck.allowed ? "全部位于授权范围" : "存在越界目标"}</strong><span>{scopeCheck.error || (scopeCheck.targets || []).map((item) => `${item.normalized || item.input}：${item.reason}${item.matched_rule ? ` (${item.matched_rule})` : ""}`).join("；")}</span></div>}
      <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setScopeEditor(null)}>取消</button><button className="primary-button" disabled={saving || !scopeEditor.name.trim() || !splitRules(scopeEditor.allowText).length}>{saving ? "保存中..." : "保存范围"}</button></div>
    </form>}</Modal>
  </Panel>;
}
