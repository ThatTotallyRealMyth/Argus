import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Plus, Search, Trash2, X } from "lucide-react";

const POPOVER_WIDTH = 432;
const VIEWPORT_GAP = 12;

function clamp(value, minimum, maximum) {
  return Math.min(Math.max(value, minimum), maximum);
}

export function ColumnFilterPopover({ anchor, column, editor, options, operatorOptions, onChange, onCommit, onClear, onClose }) {
  const popoverRef = useRef(null);
  const [position, setPosition] = useState({ top: anchor.bottom + 8, left: anchor.left, maxHeight: window.innerHeight - VIEWPORT_GAP * 2, ready: false });

  const updatePosition = useCallback(() => {
    const popover = popoverRef.current;
    if (!popover) return;

    const height = popover.offsetHeight;
    const width = Math.min(POPOVER_WIDTH, window.innerWidth - VIEWPORT_GAP * 2);
    const preferredLeft = anchor.left + width <= window.innerWidth - VIEWPORT_GAP ? anchor.left : anchor.right - width;
    const left = clamp(preferredLeft, VIEWPORT_GAP, window.innerWidth - width - VIEWPORT_GAP);
    const spaceBelow = window.innerHeight - anchor.bottom - 8 - VIEWPORT_GAP;
    const spaceAbove = anchor.top - 8 - VIEWPORT_GAP;
    const openAbove = height > spaceBelow && spaceAbove > spaceBelow;
    const maxHeight = Math.max(180, openAbove ? spaceAbove : spaceBelow);
    const renderedHeight = Math.min(height, maxHeight);
    const top = openAbove ? anchor.top - renderedHeight - 8 : anchor.bottom + 8;

    setPosition({ top, left, maxHeight, ready: true });
  }, [anchor]);

  useLayoutEffect(() => {
    updatePosition();
    const resizeObserver = new ResizeObserver(updatePosition);
    resizeObserver.observe(popoverRef.current);
    const handlePointerDown = (event) => {
      if (!popoverRef.current?.contains(event.target) && !anchor.element?.contains(event.target)) onClose();
    };
    const handleKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };
    const handleScroll = (event) => {
      if (!popoverRef.current?.contains(event.target)) onClose();
    };

    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", handleScroll, true);
    document.addEventListener("pointerdown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", handleScroll, true);
      document.removeEventListener("pointerdown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [anchor, onClose, updatePosition]);

  function updateRule(index, patch, commit = false) {
    const nextEditor = { ...editor, rules: editor.rules.map((rule, ruleIndex) => ruleIndex === index ? { ...rule, ...patch } : rule) };
    onChange(nextEditor);
    if (commit) onCommit(nextEditor);
  }
  function toggleRule(index) {
    const rule = editor.rules[index];
    if (!rule.enabled && !rule.value.trim()) return;
    const nextEditor = { ...editor, rules: editor.rules.map((item, ruleIndex) => ruleIndex === index ? { ...item, enabled: !item.enabled } : item) };
    onChange(nextEditor);
    onCommit(nextEditor);
  }
  function addRule() {
    onChange({ ...editor, rules: [...editor.rules, { operator: "contains", value: "", enabled: false, joiner: "and" }] });
  }
  function removeRule(index) {
    const rules = editor.rules.filter((_, ruleIndex) => ruleIndex !== index);
    const nextEditor = { ...editor, rules: rules.length ? rules : [{ operator: "contains", value: "", enabled: false, joiner: "and" }] };
    onChange(nextEditor);
    onCommit(nextEditor);
  }

  return createPortal(
    <div
      ref={popoverRef}
      className="column-filter-popover"
      role="dialog"
      aria-modal="false"
      aria-label={`筛选${column}`}
      style={{ top: position.top, left: position.left, maxHeight: position.maxHeight, visibility: position.ready ? "visible" : "hidden" }}
    >
      <div className="column-filter-title">
        <div><Search size={14} /><span>列筛选</span><strong>{column}</strong></div>
        <button type="button" aria-label="关闭筛选" title="关闭" onClick={onClose}><X size={14} /></button>
      </div>
      <div className="column-filter-rules">
        {editor.rules.map((rule, index) => <div key={index}>
          {index > 0 && <div className="column-filter-joiner" role="radiogroup" aria-label={`条件 ${index} 与上一条的连接方式`}>
            <span>连接条件</span>
            <button type="button" role="radio" aria-checked={rule.joiner !== "or"} className={rule.joiner !== "or" ? "active" : ""} onClick={() => updateRule(index, { joiner: "and" }, true)}>并且 <small>AND</small></button>
            <button type="button" role="radio" aria-checked={rule.joiner === "or"} className={rule.joiner === "or" ? "active" : ""} onClick={() => updateRule(index, { joiner: "or" }, true)}>或者 <small>OR</small></button>
          </div>}
          <div className="column-filter-rule">
          <div className="column-filter-rule-head">
            <span>条件 {String(index + 1).padStart(2, "0")}</span>
            <div className="column-filter-rule-actions">
              <button type="button" role="switch" aria-checked={Boolean(rule.enabled)} className={`column-filter-toggle ${rule.enabled ? "active" : ""}`} disabled={!rule.value.trim()} title={rule.enabled ? "停用条件" : "启用条件"} onClick={() => toggleRule(index)}>
                <span className="column-filter-toggle-track" aria-hidden="true"><span /></span>
                <span className="column-filter-toggle-label">{rule.enabled ? "已启用" : "未启用"}</span>
              </button>
              {editor.rules.length > 1 && <button type="button" className="column-filter-remove" aria-label={`删除条件 ${index + 1}`} title="删除条件" onClick={() => removeRule(index)}><Trash2 size={13} /></button>}
            </div>
          </div>
          <div className="column-filter-operators" role="radiogroup" aria-label={`${column}条件${index + 1}匹配关系`}>
            {operatorOptions.map((option) => (
              <button
                type="button"
                role="radio"
                aria-checked={rule.operator === option.value}
                className={rule.operator === option.value ? "active" : ""}
                key={option.value}
                onClick={() => updateRule(index, { operator: option.value }, true)}
              >{option.label}</button>
            ))}
          </div>
          <label className="column-filter-field">
            <span>条件值</span>
            {options.length ? (
              <select name={`${editor.key}-filter-value-${index}`} autoFocus={index === 0} aria-label={`${column}条件${index + 1}筛选值`} value={rule.value} onChange={(event) => updateRule(index, { value: event.target.value }, !rule.enabled)} onBlur={(event) => updateRule(index, { value: event.currentTarget.value }, true)}>
                <option value="">选择条件</option>
                {options.map((option) => <option key={typeof option === "string" ? option : option.value} value={typeof option === "string" ? option : option.value}>{typeof option === "string" ? option : option.label}</option>)}
              </select>
            ) : (
              <input
                name={`${editor.key}-filter-value-${index}`}
                autoFocus={index === 0}
                aria-label={`${column}条件${index + 1}筛选值`}
                placeholder="输入条件值"
                value={rule.value}
                onChange={(event) => updateRule(index, { value: event.target.value }, !rule.enabled)}
                onBlur={(event) => updateRule(index, { value: event.currentTarget.value }, true)}
              />
            )}
          </label>
          </div>
        </div>)}
        <button type="button" className="column-filter-add" onClick={addRule}><Plus size={14} />添加条件</button>
      </div>
      <div className="column-filter-actions">
        <button type="button" onClick={onClear}>重置此列</button>
      </div>
    </div>,
    document.body,
  );
}
