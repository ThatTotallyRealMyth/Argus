import { assetTargetURL } from "./assetWorkbench.js";

export const leadStatusOptions = [
  { value: "new", label: "New Thread" },
  { value: "investigating", label: "In progress" },
  { value: "validated", label: "Verifyed" },
  { value: "ignored", label: "Ignored" },
];

export function leadStatusLabel(value) {
  return leadStatusOptions.find((option) => option.value === value)?.label || "New Thread";
}

export function leadStatusTone(value) {
  return ({ investigating: "warn", validated: "ok", ignored: "muted", new: "accent" })[value] || "accent";
}

export function leadTypeLabel(value) {
  return ({
    confirmed_vulnerability: "Identification of gaps",
    subdomain_takeover: "Subdomain takeover candidate",
    sensitive_service: "Sensitive services",
    management_surface: "Access is compromised.",
    poc_opportunity: "PoC Opportunities",
    surface_change: "Change in the attack.",
    recent_exposure: "Add Exposure",
  })[value] || value || "Threads";
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
