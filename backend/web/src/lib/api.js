const API_PREFIX = "/api/v1";

export const severityClass = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "ok",
  info: "muted",
};

export function api(path, options = {}) {
  const token = localStorage.getItem("eclipse_token");
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(`${API_PREFIX}${path}`, { ...options, headers }).then(async (res) => {
    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = { message: text }; }
    }
    if (!res.ok) {
      const error = new Error(data?.error || data?.message || res.statusText);
      error.status = res.status;
      error.payload = data;
      if (res.status === 401) window.dispatchEvent(new Event("auth-expired"));
      throw error;
    }
    return data;
  });
}

export function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

export function compactNumber(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

export function cls(...items) {
  return items.filter(Boolean).join(" ");
}

export function parseJSON(value, fallback = {}) {
  if (!value) return fallback;
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return fallback; }
}
