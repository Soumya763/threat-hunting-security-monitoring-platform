// Presentation helpers shared by the analysis pages. Pure functions only.

export const RISK_LABELS = {
  critical: "Critical risk",
  high: "High risk",
  medium: "Medium risk",
  low: "Low risk",
  clean: "Clean - no known threat detected",
  insufficient_evidence: "Unknown - insufficient evidence",
};

export const RISK_SHORT_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  clean: "Clean",
  insufficient_evidence: "Unknown",
};

export const PROVIDER_STATUS_LABELS = {
  ok: "Result received",
  not_found: "No record",
  not_configured: "Not configured",
  unavailable: "Unavailable",
  timeout: "Timed out",
  invalid_key: "Key rejected",
  rate_limited: "Rate limited",
  unsupported: "Not applicable",
  submitted: "Submitted",
};

export const STEP_STATUS_LABELS = {
  complete: "Done",
  skipped: "Skipped",
  failed: "Failed",
  blocked: "Blocked",
  timeout: "Timed out",
};

export const PENDING_STATUSES = ["queued", "running"];

export function isPending(status) {
  return PENDING_STATUSES.includes(status);
}

export function riskKey(level) {
  return level || "unknown";
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatPercent(part, total) {
  if (!total) return "-";
  return `${Math.round((part * 100) / total)}%`;
}

/** Turns an Axios error into a message a user can read. Never exposes stack traces. */
export function errorMessage(error, fallback = "Something went wrong. Please try again.") {
  const detail = error?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail.map((item) => item.msg || "Invalid value").join("; ");
  }
  if (error?.response?.status === 429) return "Too many requests. Please wait a moment and try again.";
  if (error?.response?.status === 503) return "The service this page needs is unavailable right now.";
  if (error?.code === "ERR_NETWORK") return "Cannot reach the security API.";
  return fallback;
}

export function isHttpUrl(value) {
  try {
    const parsed = new URL(value.trim());
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

const HASH_PATTERNS = [/^[a-fA-F0-9]{32}$/, /^[a-fA-F0-9]{40}$/, /^[a-fA-F0-9]{64}$/];
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;

/** Mirrors the backend detector so the UI can show the type before submitting. */
export function guessIndicatorType(value) {
  const v = (value || "").trim();
  if (!v) return null;
  if (HASH_PATTERNS[0].test(v)) return "md5";
  if (HASH_PATTERNS[1].test(v)) return "sha1";
  if (HASH_PATTERNS[2].test(v)) return "sha256";
  const ip = v.match(IPV4);
  if (ip && ip.slice(1).every((n) => Number(n) <= 255)) return "ip";
  if (v.includes(":") && !v.includes("/") && !v.includes(" ")) return "ip";
  if (isHttpUrl(v)) return "url";
  if (DOMAIN.test(v)) return "domain";
  return null;
}
