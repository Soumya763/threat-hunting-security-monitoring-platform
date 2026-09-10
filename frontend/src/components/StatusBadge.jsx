const LABELS = {
  open: "Open",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  resolved: "Resolved",
  closed: "Closed",
};

// Works for both Alert.status (open/acknowledged/closed) and
// Incident.status (open/investigating/resolved/closed) - it just maps
// whatever string it's given to a badge class, with a neutral fallback
// for anything unrecognized.
export default function StatusBadge({ status }) {
  const key = (status || "").toLowerCase();
  const label = LABELS[key] || status || "Unknown";

  return (
    <span className={`status-badge status-badge--${key || "unknown"}`}>
      {label}
    </span>
  );
}
