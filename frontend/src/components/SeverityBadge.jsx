const LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

// critical -> strongest red, high -> red/orange, medium -> yellow/orange,
// low -> blue/gray. Colors are defined once in styles/index.css as
// .severity-badge--<level> and referenced by class name here.
export default function SeverityBadge({ severity }) {
  const key = (severity || "").toLowerCase();
  const label = LABELS[key] || severity || "Unknown";

  return (
    <span className={`severity-badge severity-badge--${key || "unknown"}`}>
      <span className="severity-badge__dot" aria-hidden="true" />
      {label}
    </span>
  );
}
