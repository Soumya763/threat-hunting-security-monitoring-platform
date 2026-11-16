import { RISK_SHORT_LABELS, riskKey } from "../utils/format";

// Risk level is always shown as text as well as colour (accessibility).
export default function RiskBadge({ level, title }) {
  const key = riskKey(level);
  const label = RISK_SHORT_LABELS[key] || "Not analysed";
  return (
    <span className={`risk-badge risk-badge--${key}`} title={title}>
      <span className="risk-badge__dot" aria-hidden="true" />
      {label}
    </span>
  );
}
