import React, { useEffect, useRef, useState } from "react";
import { CircleHelp, Search, X } from "lucide-react";
import { validateSearchSyntax } from "../lib/searchSyntax.js";

export default function AdvancedSearch({ value, onApply, fields = [], placeholder = "Enter a search expression", compact = false }) {
  const [draft, setDraft] = useState(value || "");
  const [panelOpen, setPanelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [error, setError] = useState("");
  const searchRef = useRef(null);
  const examples = [
    { label: "Include", value: "nginx && admin" },
    { label: "Exclude", value: "nginx && !test" },
    { label: "Either term", value: fields.length ? `${fields[0]}:portal || ${fields[0]}:admin` : "portal || admin" },
    { label: "Grouped expression", value: fields.length > 1 ? `(${fields[0]}:portal || ${fields[1]}:admin) && !test` : "(portal || admin) && !test" },
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
      <input name="advanced-search" aria-label="Advanced search" autoFocus={compact && panelOpen} placeholder={placeholder} value={draft} onChange={(event) => { setDraft(event.target.value); setError(""); }} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); apply(); } }} />
      {draft && <button type="button" className="search-icon-button" title="Clear search" onClick={clear}><X size={14} /></button>}
      <button type="button" className="search-icon-button" title="Search syntax help" aria-label="Search syntax help" aria-controls="search-syntax-help" aria-expanded={helpOpen} aria-pressed={helpOpen} onClick={() => setHelpOpen((current) => !current)}><CircleHelp size={15} /></button>
      <button type="button" className="search-submit" onClick={() => apply()}>Search</button>
    </div>
    {error && <div className="search-syntax-error">{error}</div>}
    {helpOpen && <div id="search-syntax-help" className="search-syntax-help" role="dialog" aria-label="Search syntax help">
      <div><strong>Search syntax</strong><span>Spaces mean AND. Precedence is NOT, AND, then OR. Parentheses and quoted phrases are supported. Select an example to use it.</span></div>
      <div className="syntax-examples">{examples.map((example) => <button type="button" key={example.label} onClick={() => { setDraft(example.value); setError(validateSearchSyntax(example.value, fields)); }}><span>{example.label}</span><code>{example.value}</code></button>)}</div>
      <div className="syntax-fields"><span>Available fields</span><code>{fields.join("  ") || "Full text"}</code></div>
    </div>}
  </>;

  return <div className={`advanced-search ${compact ? "compact" : ""}`} ref={searchRef}>
    {compact && <div className="advanced-search-compact-actions">
      <button type="button" className={`advanced-search-trigger ${value ? "active" : ""}`} aria-expanded={panelOpen} onClick={() => { setPanelOpen((current) => !current); setHelpOpen(false); }}><Search size={15} /><span>Advanced search</span>{value && <code>{value}</code>}</button>
      {value && <button type="button" className="advanced-search-clear" title="Clear Advanced Search" aria-label="Clear Advanced Search" onClick={clear}><X size={13} /></button>}
    </div>}
    {compact ? panelOpen && <div className="advanced-search-panel">{editor}</div> : editor}
  </div>;
}
