import { assetTargetURL } from "./assetWorkbench.js";

export const leadStatusOptions = [
  { value: "new", label: "新线索" },
  { value: "investigating", label: "调查中" },
  { value: "validated", label: "已验证" },
  { value: "ignored", label: "已忽略" },
];

export function leadStatusLabel(value) {
  return leadStatusOptions.find((option) => option.value === value)?.label || "新线索";
}

export function leadStatusTone(value) {
  return ({ investigating: "warn", validated: "ok", ignored: "muted", new: "accent" })[value] || "accent";
}

export function leadTypeLabel(value) {
  return ({
    confirmed_vulnerability: "确认漏洞",
    subdomain_takeover: "接管候选",
    sensitive_service: "敏感服务",
    management_surface: "入口暴露",
    poc_opportunity: "PoC 机会",
    surface_change: "攻击面变化",
    recent_exposure: "新增暴露",
  })[value] || value || "线索";
}

export function leadQueueParams({ page = 1, status = "open", severity = "all", type = "all", query = "" } = {}) {
  const params = new URLSearchParams({ page: String(page), page_size: "25", status });
  if (severity && severity !== "all") params.set("severity", severity);
  if (type && type !== "all") params.set("type", type);
  if (query.trim()) params.set("q", query.trim());
  return params.toString();
}

export function leadTargetURL(lead) {
  const target = String(lead?.target || "").trim();
  if (/^https?:\/\//i.test(target)) return target;
  if (lead?.type === "sensitive_service") return assetTargetURL({ kind: "port", display_value: target });
  return assetTargetURL({ kind: lead?.asset_kind, display_value: lead?.asset_value || target });
}

export function leadTriagePayload(lead, status, note = "") {
  const relatedLeads = (lead?.related_assets || [])
    .filter((item) => item?.asset_id && item?.lead_id)
    .map((item) => ({ asset_id: item.asset_id, lead_id: item.lead_id }));
  return {
    asset_id: lead?.asset_id || "",
    lead_id: lead?.id || "",
    status,
    note,
    ...(relatedLeads.length ? { related_leads: relatedLeads } : {}),
  };
}

export function leadPoCExecutionPayload(lead) {
  return {
    asset_id: String(lead?.asset_id || "").trim(),
    lead_id: String(lead?.id || "").trim(),
    confirm: true,
  };
}
