// Small bar chart built from real counts. Empty days are shown, not hidden.
export default function TrendChart({ data, valueKey = "alerts", labelKey = "date" }) {
  const max = Math.max(1, ...data.map((d) => d[valueKey] || 0));
  return (
    <div className="trend-chart" role="img" aria-label="Alerts per day over the last two weeks">
      {data.map((item) => {
        const value = item[valueKey] || 0;
        const height = Math.round((value / max) * 100);
        return (
          <div className="trend-chart__col" key={item[labelKey]} title={`${item[labelKey]}: ${value}`}>
            <div className="trend-chart__bar" style={{ height: `${height}%` }} />
            <span className="trend-chart__label">{item[labelKey].slice(5)}</span>
          </div>
        );
      })}
    </div>
  );
}
