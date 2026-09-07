function quoted(value) {
  return `"${String(value || "").replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function assetPivot(asset) {
  const value = String(asset?.display_value || asset?.canonical_key || "").trim();
  switch (asset?.kind) {
    case "domain": return { tab: "domains", search: `domain:${quoted(value)}` };
    case "ip": return { tab: "ips", search: `ip:${quoted(value)}` };
    case "site": return { tab: "sites", search: `url:${quoted(value)}` };
    case "url": return { tab: "urls", search: `url:${quoted(value)}` };
    case "port": {
      const endpoint = value.replace(/\/(tcp|udp)$/i, "");
      const match = endpoint.match(/^(.+):(\d+)$/);
      return match ? { tab: "ports", search: `ip:${quoted(match[1].replace(/^\[|\]$/g, ""))} && port:${match[2]}` } : { tab: "ports", search: value };
    }
    default: return { tab: "inventory", search: `value:${quoted(value)}` };
  }
}

export function assetTargetURL(asset) {
  const value = String(asset?.display_value || asset?.canonical_key || "").trim();
  if (!value) return "";
  if (asset?.kind === "site") return /^https?:\/\//i.test(value) ? value : `https://${value}`;
  if (asset?.kind === "url") return /^https?:\/\//i.test(value) ? value : `https://${value}`;
  if (asset?.kind === "domain") return `https://${value}`;
  if (asset?.kind === "ip") return `http://${value.includes(":") ? `[${value}]` : value}`;
  if (asset?.kind !== "port") return "";
  const endpoint = value.replace(/\/(tcp|udp)$/i, "");
  const match = endpoint.match(/^(.+):(\d+)$/);
  if (!match) return "";
  const port = Number(match[2]);
  if (![80, 443, 3000, 5000, 5003, 5173, 8000, 8080, 8443, 8888, 9443].includes(port)) return "";
  const host = match[1].replace(/^\[|\]$/g, "");
  const scheme = [443, 8443, 9443].includes(port) ? "https" : "http";
  return `${scheme}://${host.includes(":") ? `[${host}]` : host}:${port}`;
}

export function leadSummary(leads = []) {
  return leads.reduce((summary, lead) => {
    summary.total += 1;
    const severity = ["critical", "high", "medium", "low", "info"].includes(lead?.severity) ? lead.severity : "info";
    summary[severity] += 1;
    if (lead?.poc) summary.poc += 1;
    return summary;
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, poc: 0 });
}
