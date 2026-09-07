import React, { useState } from "react";
import { Braces, FileSearch, ListFilter } from "lucide-react";
import { Badge, DataTable, EmptyState, Panel, Pager } from "../components/ui.jsx";
import AdvancedSearch from "../components/AdvancedSearch.jsx";
import { useQuery } from "../hooks/useQuery.js";
import { api, compactNumber } from "../lib/api.js";
import { filtersToExpression } from "../lib/searchSyntax.js";

export default function TrafficPage() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ status: "", contentType: "", body: "", min: "", max: "" });
  const [search, setSearch] = useState("");
  const [columnFilters, setColumnFilters] = useState({});
  const [selected, setSelected] = useState(null);
  const [detailError, setDetailError] = useState("");
  const query = new URLSearchParams({ page, page_size: 20, sort_by: "response_content_length", sort_order: "desc" });
  if (filters.status) query.set("status_code", filters.status);
  if (filters.contentType) query.set("content_type", filters.contentType);
  if (filters.body) query.set("body_search", filters.body);
  if (filters.min) query.set("min_length", filters.min);
  if (filters.max) query.set("max_length", filters.max);
  const combinedSearch = [search, filtersToExpression(columnFilters)].filter(Boolean).join(" && ");
  if (combinedSearch) query.set("q", combinedSearch);
  const { data, loading, error } = useQuery(`traffic-${page}-${combinedSearch}-${JSON.stringify(filters)}`, () => api(`/assets/http-transactions?${query}`));

  async function openDetail(id) {
    setDetailError("");
    try { setSelected(await api(`/assets/http-transactions/${id}`)); }
    catch (error) { setSelected(null); setDetailError(`加载详情失败：${error.message}`); }
  }

  return (
    <div className="stack">
      <Panel title="HTTP 响应筛选" icon={<ListFilter size={17} />}>
        <AdvancedSearch value={search} fields={["url", "method", "status", "type", "source", "body", "request"]} placeholder="全文检索 HTTP 记录，例如 status:200 && body:token && !url:logout" onApply={(value) => { setSearch(value); setPage(1); }} />
        <div className="filter-grid">
          <input id="http-status" name="http-status" placeholder="状态码" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })} />
          <input id="http-content-type" name="http-content-type" placeholder="Content-Type" value={filters.contentType} onChange={(e) => setFilters({ ...filters, contentType: e.target.value })} />
          <input id="http-body" name="http-body" placeholder="正文关键词" value={filters.body} onChange={(e) => setFilters({ ...filters, body: e.target.value })} />
          <input id="http-min-length" name="http-min-length" placeholder="最小长度" value={filters.min} onChange={(e) => setFilters({ ...filters, min: e.target.value })} />
          <input id="http-max-length" name="http-max-length" placeholder="最大长度" value={filters.max} onChange={(e) => setFilters({ ...filters, max: e.target.value })} />
          <button type="button" className="ghost-button filter-reset" onClick={() => { setFilters({ status: "", contentType: "", body: "", min: "", max: "" }); setSelected(null); setDetailError(""); }}>清空筛选</button>
        </div>
        {error && <div className="error-box">{error}</div>}
      </Panel>
      <div className="split-layout wide">
        <Panel title="记录列表" icon={<FileSearch size={17} />}>
          <DataTable
            storageKey="http-transactions"
            loading={loading}
            filterKeys={["status", "", "type", "source", "url"]}
            filters={columnFilters}
            filterOptions={{ status: ["200", "301", "302", "400", "401", "403", "404", "500"] }}
            onFilterChange={(key, value) => { setColumnFilters((current) => ({ ...current, [key]: value })); setPage(1); }}
            columns={["状态", "长度", "类型", "来源", "URL"]}
            rows={(data?.items || []).map((x) => [
              x.response_status_code,
              compactNumber(x.response_content_length),
              x.response_content_type || "-",
              x.source,
              <button key="url" className="link-button" onClick={() => openDetail(x.id)}>{x.url}</button>,
            ])}
            empty="暂无 HTTP 记录"
          />
          <Pager page={page} totalPages={data?.total_pages || 1} setPage={setPage} />
        </Panel>
        <Panel title="详情" icon={<Braces size={17} />}>
          {detailError ? <div className="error-box">{detailError}</div> : selected ? (
            <div className="detail">
              <h3>{selected.method} {selected.url}</h3>
              <div className="meta-line">
                <Badge tone={selected.response_status_code >= 400 ? "danger" : "ok"}>{selected.response_status_code}</Badge>
                <span>{selected.response_content_type || "unknown"}</span>
                <span>{compactNumber(selected.response_content_length)} bytes</span>
                {selected.response_body_truncated && <Badge tone="warn">truncated</Badge>}
              </div>
              <h4>Response Body</h4>
              <pre>{selected.response_body || "未保存正文，可能是二进制或超大响应。"}</pre>
            </div>
          ) : <EmptyState text="选择一条记录查看完整响应" />}
        </Panel>
      </div>
    </div>
  );
}
