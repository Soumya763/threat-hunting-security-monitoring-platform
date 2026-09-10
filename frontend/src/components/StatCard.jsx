export default function StatCard({ label, value, accent }) {
  return (
    <div className="stat-card">
      <div className="stat-card__label">{label}</div>
      <div
        className={`stat-card__value${accent ? ` stat-card__value--${accent}` : ""}`}
      >
        {value}
      </div>
    </div>
  );
}
