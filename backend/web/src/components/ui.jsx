import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ArrowDown, ArrowUp, ArrowUpDown, Fingerprint, Search, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { cls, compactNumber } from "../lib/api.js";
import { hasFilterRules, normalizeFilterGroup } from "../lib/searchSyntax.js";
import { ColumnFilterPopover } from "./ColumnFilterPopover.jsx";

const tableSortCache = new Map();

function readTableSort(signature) {
  if (tableSortCache.has(signature)) return tableSortCache.get(signature);
  try {
    const stored = sessionStorage.getItem(`table-sort:${signature}`);
    if (stored) { const value = JSON.parse(stored); tableSortCache.set(signature, value); return value; }
  } catch { /* session storage may be unavailable in restricted browsers */ }
  return { index: -1, direction: "asc" };
}

function writeTableSort(signature, value) {
  tableSortCache.set(signature, value);
  try { sessionStorage.setItem(`table-sort:${signature}`, JSON.stringify(value)); } catch { /* best effort */ }
}

function readTableFilters(signature) {
  try {
    const stored = localStorage.getItem(`table-filters:${signature}`);
    const value = stored ? JSON.parse(stored) : {};
    return value && typeof value === "object" ? value : {};
  } catch { return {}; }
}

function writeTableFilters(signature, value) {
  try { localStorage.setItem(`table-filters:${signature}`, JSON.stringify(value)); } catch { /* best effort */ }
}

function readTableWidths(signature, columnCount) {
  try {
    const stored = JSON.parse(localStorage.getItem(`table-widths:${signature}`) || "null");
    return Array.isArray(stored) && stored.length === columnCount && stored.every((width) => Number.isFinite(width) && width > 0) ? stored : null;
  } catch { return null; }
}

function writeTableWidths(signature, widths) {
  try {
    if (widths) localStorage.setItem(`table-widths:${signature}`, JSON.stringify(widths));
    else localStorage.removeItem(`table-widths:${signature}`);
  } catch { /* best effort */ }
}

export function Metric({ label, value, icon }) {
  return <motion.div className="metric" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}><div className="metric-icon">{icon}</div><span>{label}</span><strong>{compactNumber(value)}</strong></motion.div>;
}

export function Panel({ title, icon, action, children }) {
  return <section className="panel"><div className="panel-head"><h2>{icon}{title}</h2>{action}</div>{children}</section>;
}

export function Modal({ children, open = true }) {
  const reduceMotion = useReducedMotion();
  const surfaceMotion = reduceMotion
    ? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }
    : { initial: { opacity: 0, y: 8, scale: .985 }, animate: { opacity: 1, y: 0, scale: 1 }, exit: { opacity: 0, y: 6, scale: .99 } };
  return createPortal(<AnimatePresence>{open && <motion.div className="modal-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? .1 : .18, ease: "easeOut" }}>
    <motion.div className="modal-motion-shell" role="dialog" aria-modal="true" {...surfaceMotion} transition={{ duration: reduceMotion ? .1 : .2, ease: [.22, 1, .36, 1] }}>{children}</motion.div>
  </motion.div>}</AnimatePresence>, document.body);
}

export function DataTable({ columns, rows, loading, empty, sortKeys = [], sortState, onSortChange, storageKey, filterKeys = [], filters = {}, filterOptions = {}, onFilterChange, headerCells = {}, selectionColumn = false }) {
  const signature = storageKey || columns.join("|");
  const [sort, setSort] = useState(() => readTableSort(signature));
  const [filterEditor, setFilterEditor] = useState(null);
  const [columnWidths, setColumnWidths] = useState(() => readTableWidths(signature, columns.length));
  const columnResize = useRef(null);
  useEffect(() => {
    const stored = readTableSort(signature);
    setSort(stored);
    if (onSortChange && stored.index >= 0 && sortKeys[stored.index] && (sortState?.index !== stored.index || sortState?.direction !== stored.direction)) {
      onSortChange(sortKeys[stored.index], stored.direction);
    }
  }, [signature]);
  useEffect(() => {
    if (!onFilterChange) return;
    const stored = readTableFilters(signature);
    Object.entries(stored).forEach(([key, value]) => onFilterChange(key, value));
  }, [signature]);
  useEffect(() => {
    setColumnWidths(readTableWidths(signature, columns.length));
  }, [signature, columns.length]);
  useEffect(() => () => document.body.classList.remove("resizing-columns"), []);
  const sortedRows = useMemo(() => {
    if (onSortChange) return rows;
    if (sort.index < 0) return rows;
    return rows.map((row, index) => ({ row, index })).sort((left, right) => {
      const a = sortValue(left.row[sort.index]);
      const b = sortValue(right.row[sort.index]);
      const comparison = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), "zh-CN", { numeric: true, sensitivity: "base" });
      return (comparison || left.index - right.index) * (sort.direction === "asc" ? 1 : -1);
    }).map((item) => item.row);
  }, [rows, sort]);
  function toggleSort(index) {
    if (onSortChange) {
      const next = { index, direction: sortState?.index === index && sortState?.direction === "asc" ? "desc" : "asc" };
      writeTableSort(signature, next);
      onSortChange(sortKeys[index] || "", next.direction);
      return;
    }
    setSort((current) => {
      const next = { index, direction: current.index === index && current.direction === "asc" ? "desc" : "asc" };
      writeTableSort(signature, next);
      return next;
    });
  }
  const activeIndex = onSortChange ? (sortState?.index ?? -1) : sort.index;
  const activeDirection = onSortChange ? (sortState?.direction || "asc") : sort.direction;
  const operatorOptions = [{ value: "contains", label: "包含" }, { value: "not-contains", label: "不包含" }, { value: "equals", label: "等于" }, { value: "not-equals", label: "不等于" }];
  const activeFilters = Object.entries(filters).filter(([, filter]) => hasFilterRules(filter));
  const closeFilter = useCallback(() => setFilterEditor(null), []);
  function openFilter(event, index, key) {
    const anchorElement = event.currentTarget.closest(".active-filter-chip") || event.currentTarget;
    if (filterEditor?.index === index && filterEditor.anchor.element === anchorElement) {
      closeFilter();
      return;
    }
    const current = filters[key];
    const group = normalizeFilterGroup(current);
    const rect = event.currentTarget.getBoundingClientRect();
    const rules = group.rules.length ? group.rules : [{ operator: "contains", value: "", enabled: false }];
    setFilterEditor({ index, key, rules: rules.map((rule, ruleIndex) => ({ ...rule, enabled: rule.enabled !== false && Boolean(rule.value.trim()), joiner: ruleIndex === 0 ? "and" : rule.joiner || group.combinator })), anchor: { top: rect.top, right: rect.right, bottom: rect.bottom, left: rect.left, element: anchorElement } });
  }
  function commitFilter(editor = filterEditor) {
    if (!editor) return;
    const rules = editor.rules.map((rule) => ({ operator: rule.operator, value: rule.value.trim(), joiner: rule.joiner, enabled: Boolean(rule.enabled && rule.value.trim()) })).filter((rule) => rule.value);
    const value = rules.length ? { rules } : null;
    writeTableFilters(signature, { ...filters, [editor.key]: value });
    onFilterChange?.(editor.key, value);
  }
  function clearFilter(key) {
    writeTableFilters(signature, { ...filters, [key]: null });
    onFilterChange?.(key, null);
    closeFilter();
  }
  function startColumnResize(event, index) {
    event.preventDefault();
    event.stopPropagation();
    const table = event.currentTarget.closest("table");
    const headers = [...table.querySelectorAll("thead th")];
    if (!headers[index] || !headers[index + 1]) return;
    const widths = headers.map((header) => header.getBoundingClientRect().width);
    columnResize.current = { index, pointerId: event.pointerId, startX: event.clientX, widths };
    event.currentTarget.setPointerCapture(event.pointerId);
    document.body.classList.add("resizing-columns");
  }
  function resizeColumn(event) {
    const state = columnResize.current;
    if (!state || state.pointerId !== event.pointerId) return;
    const currentMin = 72;
    const nextMin = 72;
    const rawDelta = event.clientX - state.startX;
    const delta = Math.min(state.widths[state.index + 1] - nextMin, Math.max(currentMin - state.widths[state.index], rawDelta));
    const next = state.widths.map((width) => Math.round(width));
    next[state.index] = Math.round(state.widths[state.index] + delta);
    next[state.index + 1] = Math.round(state.widths[state.index + 1] - delta);
    state.currentWidths = next;
    setColumnWidths(next);
  }
  function finishColumnResize(event) {
    const state = columnResize.current;
    if (!state || state.pointerId !== event.pointerId) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    const widths = state.currentWidths || state.widths.map((width) => Math.round(width));
    columnResize.current = null;
    document.body.classList.remove("resizing-columns");
    setColumnWidths(widths);
    writeTableWidths(signature, widths);
  }
  function resetColumnWidths(event) {
    event.preventDefault();
    event.stopPropagation();
    columnResize.current = null;
    document.body.classList.remove("resizing-columns");
    setColumnWidths(null);
    writeTableWidths(signature, null);
  }
  function columnName(key) { const index = filterKeys.indexOf(key); return columns[index] || key; }
  return <div className="table-wrap">{activeFilters.length > 0 && <div className="active-filter-strip"><span>已启用条件</span>{activeFilters.map(([key, filter]) => {
    const group = normalizeFilterGroup(filter);
    const rules = group.rules.filter((rule) => rule.value.trim());
    const details = rules.map((rule, ruleIndex) => `${ruleIndex > 0 ? (rule.joiner === "or" ? "或者：" : "并且：") : ""}${operatorOptions.find((option) => option.value === rule.operator)?.label || "包含"} ${rule.value}`).join("；");
    const index = filterKeys.indexOf(key);
    const label = columnName(key);
    return <div className="active-filter-chip" key={key}>
      <button type="button" className="active-filter-view" title={`${details}；点击查看${label}筛选`} aria-label={`查看${label}筛选条件`} aria-expanded={filterEditor?.index === index} onClick={(event) => openFilter(event, index, key)}><strong>{label}</strong><small>{rules.length > 1 ? `${rules.length} 条` : operatorOptions.find((option) => option.value === rules[0]?.operator)?.label || "包含"}</small><code>{rules.length > 1 ? "组合条件" : rules[0]?.value}</code></button>
      <button type="button" className="active-filter-clear" title={`取消${label}筛选`} aria-label={`取消${label}筛选`} onPointerDown={(event) => event.preventDefault()} onClick={(event) => { event.stopPropagation(); clearFilter(key); }}><X size={12} /></button>
    </div>;
  })}</div>}<table className={cls(selectionColumn && "has-selection-column", columnWidths && "has-custom-column-widths")} style={columnWidths ? { width: `${columnWidths.reduce((total, width) => total + width, 0)}px`, minWidth: "100%" } : undefined}><colgroup>{columns.map((column, index) => <col className={selectionColumn && index === 0 ? "selection-column" : undefined} style={columnWidths && !(selectionColumn && index === 0) ? { width: `${columnWidths[index]}px` } : undefined} key={`${column}-${index}`} />)}</colgroup><thead><tr>{columns.map((column, index) => {
    const sortable = column !== "操作" && column !== "选择" && (onSortChange ? Boolean(sortKeys[index]) : true);
    const filterKey = filterKeys[index];
    const filterable = Boolean(filterKey && onFilterChange);
    const currentFilter = filters[filterKey];
    const filterActive = filterable && hasFilterRules(currentFilter);
    const active = activeIndex === index;
    const Icon = active ? (activeDirection === "asc" ? ArrowUp : ArrowDown) : ArrowUpDown;
    return <th key={column} aria-sort={active ? (activeDirection === "asc" ? "ascending" : "descending") : sortable ? "none" : undefined}>
      <div className="table-head-control">
        {sortable ? <button type="button" className={cls("sort-button", active && "active")} aria-label={`${column}，${active ? (activeDirection === "asc" ? "升序" : "降序") : "未排序"}`} onClick={() => toggleSort(index)}><span>{column}</span><Icon size={12} /></button> : <span>{headerCells[index] ?? column}</span>}
        {filterable && <button type="button" className={cls("column-filter-button", filterActive && "active")} aria-label={`筛选${column}`} title={`筛选${column}`} aria-expanded={filterEditor?.index === index} onClick={(event) => openFilter(event, index, filterKey)}><Search size={13} /></button>}
      </div>
      {index < columns.length - 1 && !(selectionColumn && index === 0) && <button type="button" className="column-resize-handle" aria-label={`调整${column}列宽`} title="拖动调整列宽，双击恢复默认" onPointerDown={(event) => startColumnResize(event, index)} onPointerMove={resizeColumn} onPointerUp={finishColumnResize} onPointerCancel={finishColumnResize} onDoubleClick={resetColumnWidths} />}
    </th>;
  })}</tr></thead><tbody>{loading && <tr><td colSpan={columns.length}>加载中...</td></tr>}{!loading && sortedRows.length === 0 && <tr><td colSpan={columns.length}>{empty}</td></tr>}{!loading && sortedRows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody></table>{filterEditor && <ColumnFilterPopover anchor={filterEditor.anchor} column={columns[filterEditor.index]} editor={filterEditor} options={filterOptions[filterEditor.key] || []} operatorOptions={operatorOptions} onChange={setFilterEditor} onCommit={commitFilter} onClear={() => clearFilter(filterEditor.key)} onClose={closeFilter} />}</div>;
}

function sortValue(value) {
  if (value == null) return "";
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    if (/^\s*-?[\d,.]+(?:\s*(?:%|bytes|小时))?\s*$/i.test(value)) return Number(value.replace(/[^0-9.-]/g, ""));
    const timestamp = Date.parse(value);
    return Number.isNaN(timestamp) ? value : timestamp;
  }
  if (React.isValidElement(value)) return sortValue(value.props.children);
  if (Array.isArray(value)) return value.map(sortValue).join(" ");
  return String(value);
}

export function Badge({ children, tone = "muted" }) { return <span className={cls("badge", tone)}>{children}</span>; }
export function Tabs({ value, setValue, items, labels = {} }) { return <div className="tabs">{items.map((item) => <button type="button" key={item} className={value === item ? "active" : ""} onClick={() => setValue(item)}>{labels[item] || item}</button>)}</div>; }
export function Pager({ page, totalPages, setPage }) { return <div className="pager"><button disabled={page <= 1} onClick={() => setPage(page - 1)}>上一页</button><span>{page} / {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>下一页</button></div>; }
export function EmptyState({ text }) { return <div className="empty"><Fingerprint size={24} /><span>{text}</span></div>; }

export function SelectAllCheckbox({ ids, selectedIDs, setSelectedIDs, label = "本页记录" }) {
  const allSelected = ids.length > 0 && ids.every((id) => selectedIDs.includes(id));
  const someSelected = ids.some((id) => selectedIDs.includes(id));
  return <input
    className="row-check"
    type="checkbox"
    aria-label={allSelected ? `取消选择${label}` : `选择${label}`}
    title={allSelected ? `取消选择${label}` : `选择${label}`}
    checked={allSelected}
    disabled={!ids.length}
    ref={(element) => { if (element) element.indeterminate = someSelected && !allSelected; }}
    onChange={() => setSelectedIDs((current) => allSelected ? current.filter((id) => !ids.includes(id)) : [...new Set([...current, ...ids])])}
  />;
}
