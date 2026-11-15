// Circular gauge for a 0-100 risk score. The number is the accessible value.
export default function ScoreGauge({ score, level }) {
  const value = typeof score === "number" ? Math.max(0, Math.min(100, score)) : null;
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const offset = value === null ? circumference : circumference * (1 - value / 100);
  const key = level || "unknown";

  return (
    <div className={`score-gauge score-gauge--${key}`} role="img"
      aria-label={value === null ? "Risk score not available" : `Risk score ${value} out of 100`}>
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle className="score-gauge__track" cx="50" cy="50" r={radius} />
        <circle className="score-gauge__arc" cx="50" cy="50" r={radius}
          strokeDasharray={circumference} strokeDashoffset={offset} />
      </svg>
      <div className="score-gauge__value">{value === null ? "-" : value}</div>
      <div className="score-gauge__unit">/ 100</div>
    </div>
  );
}
