import React, { useState } from "react";
import { Database, Edit3, Plus, Trash2, X } from "lucide-react";
import { Badge, DataTable, Modal, Pager, Panel, Tabs } from "../components/ui.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, cls, severityClass } from "../lib/api.js";
import AdvancedSearch from "../components/AdvancedSearch.jsx";
import { filtersToExpression } from "../lib/searchSyntax.js";

const customPoCTemplate = `requests:
  - method: GET
    path: /
    matchers_condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: [replace-with-response-marker]
`;

const nucleiPoCTemplate = `id: eclipse-recon-check
info:
  name: Eclipse Recon check
  author: operator
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`;

function templateForPoCType(type) {
  return type === "nuclei" ? nucleiPoCTemplate : customPoCTemplate;
}

export default function LibraryPage() {
  const [tab, setTab] = useState("fingerprints");
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [editor, setEditor] = useState(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [search, setSearch] = useState("");
  const [columnFilters, setColumnFilters] = useState({});
  const params = new URLSearchParams({ page, page_size: 20 });
  const combinedSearch = [search, filtersToExpression(columnFilters)].filter(Boolean).join(" && ");
  if (combinedSearch) params.set("q", combinedSearch);
  const endpoint = tab === "fingerprints" ? `/fingerprints?${params}` : `/pocs?${params}`;
  const { data, loading, error } = useQuery(`library-${tab}-${page}-${search}-${JSON.stringify(columnFilters)}-${refresh}`, () => api(endpoint));

  function blank(kind = tab) {
    return kind === "fingerprints"
      ? { name: "", category: "web", dsl: "", description: "" }
      : { name: "", category: "web", severity: "medium", cve: "", product: "", affected_versions: "", author: "", description: "", reference: "", poc_type: "custom", poc_content: customPoCTemplate, tags: "", fingerprints: "", app_names: "", match_mode: "fuzzy" };
  }

  function openCreate() { setMessage(""); setEditor({ kind: tab, id: "", values: blank(tab) }); }
  async function openEdit(item) {
    setMessage("");
    try {
      const detail = await api(`/${tab}/${item.id}`);
      setEditor({ kind: tab, id: item.id, values: { ...blank(tab), ...detail, dsl: (detail.dsl || []).join("\n") } });
    } catch (error) { setMessage(`加载记录失败：${error.message}`); }
  }
  async function save(event) {
    event.preventDefault();
    setSaving(true); setMessage("");
    try {
      const values = editor.values;
      const body = editor.kind === "fingerprints"
        ? { name: values.name, category: values.category, dsl: values.dsl.split("\n").map((x) => x.trim()).filter(Boolean), description: values.description }
        : values;
      await api(`/${editor.kind}${editor.id ? `/${editor.id}` : ""}`, { method: editor.id ? "PUT" : "POST", body: JSON.stringify(body) });
      setEditor(null); setMessage(editor.id ? "记录已更新" : "记录已创建"); setPage(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(error.message); } finally { setSaving(false); }
  }
  async function remove(item) {
    if (!window.confirm(`确认删除 ${item.name}？`)) return;
    try {
      await api(`/${tab}/${item.id}`, { method: "DELETE" });
      setMessage("记录已删除"); setPage(1); setRefresh((x) => x + 1);
    } catch (error) { setMessage(`删除失败：${error.message}`); }
  }
  function updateField(key, value) { setEditor((current) => ({ ...current, values: { ...current.values, [key]: value } })); }
  function updatePoCType(value) {
    setEditor((current) => {
      const previousTemplate = templateForPoCType(current.values.poc_type);
      const shouldReplace = !current.values.poc_content.trim() || current.values.poc_content === previousTemplate;
      return { ...current, values: { ...current.values, poc_type: value, poc_content: shouldReplace ? templateForPoCType(value) : current.values.poc_content } };
    });
  }

  const rows = tab === "fingerprints"
    ? (data?.fingerprints || []).map((x) => [x.name, x.category, x.is_enabled ? <Badge key="on" tone="ok">启用</Badge> : <Badge key="off">停用</Badge>, (x.dsl || []).slice(0, 2).join(" | "), <div className="row-actions" key="actions"><button className="icon-button" title="编辑" onClick={() => openEdit(x)}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" onClick={() => remove(x)}><Trash2 size={14} /></button></div>])
    : (data?.pocs || []).map((x) => [x.name, <Badge key="sev" tone={severityClass[x.severity] || "muted"}>{x.severity}</Badge>, x.product || "-", x.poc_type, <div className="row-actions" key="actions"><button className="icon-button" title="编辑" onClick={() => openEdit(x)}><Edit3 size={14} /></button><button className="icon-button danger" title="删除" onClick={() => remove(x)}><Trash2 size={14} /></button></div>]);
  const columns = tab === "fingerprints" ? ["名称", "分类", "状态", "规则摘要", "操作"] : ["名称", "级别", "产品", "类型", "操作"];

  return (
    <Panel title="指纹与 PoC 库" icon={<Database size={17} />}>
      <div className="toolbar">
        <Tabs value={tab} setValue={(v) => { setTab(v); setPage(1); setSearch(""); setColumnFilters({}); }} items={["fingerprints", "pocs"]} labels={{ fingerprints: "指纹", pocs: "PoC" }} />
        <AdvancedSearch value={search} fields={tab === "fingerprints" ? ["name", "category", "description", "dsl"] : ["name", "category", "severity", "type", "cve", "product", "tags", "description"]} placeholder="检索库记录，支持字段与组合条件" onApply={(value) => { setSearch(value); setPage(1); }} />
        <button className="primary-button library-add" onClick={openCreate}><Plus size={15} />新增{tab === "fingerprints" ? "指纹" : "PoC"}</button>
      </div>
      {error && <div className="error-box">加载失败：{error}</div>}
      {message && <div className="success-box library-message">{message}</div>}
      <DataTable storageKey={`library-${tab}`} loading={loading} columns={columns} rows={rows} filterKeys={tab === "fingerprints" ? ["name", "category", "status", "dsl", ""] : ["name", "severity", "product", "type", ""]} filters={columnFilters} filterOptions={{ severity: ["critical", "high", "medium", "low", "info"], status: ["true", "false"] }} onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [key]: value })); setPage(1); }} empty="暂无数据" />
      <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPage} />
      <Modal open={Boolean(editor)}>{editor && <form className={cls("library-editor", editor.kind === "pocs" && "poc-editor")} onSubmit={save}>
        <div className="editor-head"><div><span className="eyebrow">Library record</span><h3>{editor.id ? "编辑" : "新增"}{editor.kind === "fingerprints" ? "指纹" : " PoC"}</h3></div><button type="button" className="icon-button" title="关闭" onClick={() => setEditor(null)}><X size={16} /></button></div>
        {editor.kind === "fingerprints" ? <>
          <div className="editor-grid"><label>名称<input name="fingerprint-name" required value={editor.values.name} onChange={(e) => updateField("name", e.target.value)} /></label><label>分类<input name="fingerprint-category" required value={editor.values.category} onChange={(e) => updateField("category", e.target.value)} /></label></div>
          <label>DSL 规则（每行一条）<textarea name="fingerprint-dsl" required rows="7" value={editor.values.dsl} onChange={(e) => updateField("dsl", e.target.value)} /></label><label>描述<textarea name="fingerprint-description" rows="3" value={editor.values.description} onChange={(e) => updateField("description", e.target.value)} /></label>
        </> : <div className="poc-editor-body">
          <section className="editor-section">
            <div className="editor-section-head"><span>01</span><strong>基础信息</strong></div>
            <div className="editor-grid editor-grid-4">
              <label className="field-span-2">名称<input name="poc-name" required value={editor.values.name} onChange={(e) => updateField("name", e.target.value)} /></label>
              <label>产品<input name="poc-product" value={editor.values.product} onChange={(e) => updateField("product", e.target.value)} /></label>
              <label>CVE<input name="poc-cve" value={editor.values.cve} onChange={(e) => updateField("cve", e.target.value)} placeholder="CVE-2026-0000" /></label>
              <label>分类<input name="poc-category" required value={editor.values.category} onChange={(e) => updateField("category", e.target.value)} /></label>
              <label>严重级别<select name="poc-severity" value={editor.values.severity} onChange={(e) => updateField("severity", e.target.value)}>{["critical", "high", "medium", "low", "info"].map((x) => <option key={x}>{x}</option>)}</select></label>
              <label>PoC 类型<select name="poc-type" value={editor.values.poc_type} onChange={(e) => updatePoCType(e.target.value)}><option value="custom">custom</option><option value="nuclei">nuclei</option>{editor.values.poc_type === "xray" && <option value="xray" disabled>xray</option>}</select></label>
              <label>作者<input name="poc-author" value={editor.values.author} onChange={(e) => updateField("author", e.target.value)} /></label>
              <label className="field-span-2">影响版本<input name="poc-versions" value={editor.values.affected_versions} onChange={(e) => updateField("affected_versions", e.target.value)} /></label>
              <label className="field-span-2">参考链接<input name="poc-reference" type="url" value={editor.values.reference} onChange={(e) => updateField("reference", e.target.value)} /></label>
              <label className="field-span-4">描述<textarea name="poc-description" rows="3" value={editor.values.description} onChange={(e) => updateField("description", e.target.value)} /></label>
            </div>
          </section>
          <section className="editor-section">
            <div className="editor-section-head"><span>02</span><strong>匹配范围</strong></div>
            <div className="editor-grid editor-grid-4">
              <label>匹配模式<select name="poc-match-mode" value={editor.values.match_mode} onChange={(e) => updateField("match_mode", e.target.value)}><option value="fuzzy">模糊匹配</option><option value="exact">精确匹配</option><option value="keyword">关键词匹配</option></select></label>
              <label className="field-span-3">应用名称<input name="poc-app-names" value={editor.values.app_names} onChange={(e) => updateField("app_names", e.target.value)} placeholder="逗号分隔" /></label>
              <label className="field-span-2">关联指纹<input name="poc-fingerprints" value={editor.values.fingerprints} onChange={(e) => updateField("fingerprints", e.target.value)} placeholder="逗号分隔" /></label>
              <label className="field-span-2">标签<input name="poc-tags" value={editor.values.tags} onChange={(e) => updateField("tags", e.target.value)} placeholder="逗号分隔" /></label>
            </div>
          </section>
          <section className="editor-section poc-content-section">
            <div className="editor-section-head"><span>03</span><strong>检测内容</strong><Badge tone={severityClass[editor.values.severity] || "muted"}>{editor.values.poc_type}</Badge></div>
            <label>PoC 内容<textarea className="poc-code" name="poc-content" required spellCheck="false" value={editor.values.poc_content} onChange={(e) => updateField("poc_content", e.target.value)} /></label>
          </section>
        </div>}
        <div className="editor-actions"><button type="button" className="ghost-button" onClick={() => setEditor(null)}>取消</button><button className="primary-button" disabled={saving}>{saving ? "保存中..." : "保存记录"}</button></div>
      </form>}</Modal>
    </Panel>
  );
}
