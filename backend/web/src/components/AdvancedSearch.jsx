import React, { useEffect, useRef, useState } from "react";
import { CircleHelp, Search, X } from "lucide-react";
import { validateSearchSyntax } from "../lib/searchSyntax.js";

export default function AdvancedSearch({ value, onApply, fields = [], placeholder = "输入检索表达式", compact = false }) {
  const [draft, setDraft] = useState(value || "");
  const [panelOpen, setPanelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [error, setError] = useState("");
  const searchRef = useRef(null);
  const examples = [
    { label: "同时包含", value: "nginx && admin" },
    { label: "排除内容", value: "nginx && !test" },
    { label: "任一条件", value: fields.length ? `${fields[0]}:核心 || ${fields[0]}:后台` : "核心 || 后台" },
    { label: "组合条件", value: fields.length > 1 ? `(${fields[0]}:核心 || ${fields[0]}:后台) && !test` : "(核心 || 后台) && !test" },
  ];

  useEffect(() => { setDraft(value || ""); setError(""); }, [value]);

  useEffect(() => {
    if (!helpOpen && !panelOpen) return undefined;
    function handlePointerDown(event) {
      if (!searchRef.current?.contains(event.target)) {
        setHelpOpen(false);
        setPanelOpen(false);
      }
    }
    function handleKeyDown(event) {
      if (event.key === "Escape") {
        setHelpOpen(false);
        setPanelOpen(false);
      }
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [helpOpen, panelOpen]);

  function apply(next = draft) {
    const validation = validateSearchSyntax(next, fields);
    setError(validation);
    if (!validation) {
      onApply(next.trim());
      if (compact) {
        setHelpOpen(false);
        setPanelOpen(false);
      }
    }
  }

  function clear() {
    setDraft("");
    setError("");
    onApply("");
    if (compact) {
      setHelpOpen(false);
      setPanelOpen(false);
    }
  }

  const editor = <>
    <div className="advanced-search-bar">
      <Search size={16} />
      <input name="advanced-search" aria-label="高级检索" autoFocus={compact && panelOpen} placeholder={placeholder} value={draft} onChange={(event) => { setDraft(event.target.value); setError(""); }} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); apply(); } }} />
      {draft && <button type="button" className="search-icon-button" title="清空检索" onClick={clear}><X size={14} /></button>}
      <button type="button" className="search-icon-button" title="打开检索语法提示" aria-label="打开检索语法提示" aria-controls="search-syntax-help" aria-expanded={helpOpen} aria-pressed={helpOpen} onClick={() => setHelpOpen((current) => !current)}><CircleHelp size={15} /></button>
      <button type="button" className="search-submit" onClick={() => apply()}>检索</button>
    </div>
    {error && <div className="search-syntax-error">{error}</div>}
    {helpOpen && <div id="search-syntax-help" className="search-syntax-help" role="dialog" aria-label="检索语法提示">
      <div><strong>检索语法提示</strong><span>空格等同于 &&，优先级：! → && → ||，支持括号与双引号。点击示例会填入输入框。</span></div>
      <div className="syntax-examples">{examples.map((example) => <button type="button" key={example.label} onClick={() => { setDraft(example.value); setError(validateSearchSyntax(example.value, fields)); }}><span>{example.label}</span><code>{example.value}</code></button>)}</div>
      <div className="syntax-fields"><span>当前字段</span><code>{fields.join("  ") || "全文"}</code></div>
    </div>}
  </>;

  return <div className={`advanced-search ${compact ? "compact" : ""}`} ref={searchRef}>
    {compact && <div className="advanced-search-compact-actions">
      <button type="button" className={`advanced-search-trigger ${value ? "active" : ""}`} aria-expanded={panelOpen} onClick={() => { setPanelOpen((current) => !current); setHelpOpen(false); }}><Search size={15} /><span>高级检索</span>{value && <code>{value}</code>}</button>
      {value && <button type="button" className="advanced-search-clear" title="清除高级检索" aria-label="清除高级检索" onClick={clear}><X size={13} /></button>}
    </div>}
    {compact ? panelOpen && <div className="advanced-search-panel">{editor}</div> : editor}
  </div>;
}
