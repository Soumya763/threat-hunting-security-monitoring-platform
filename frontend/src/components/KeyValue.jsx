// Two-column detail list. Values that are null or empty show a dash, never a guess.
export default function KeyValue({ rows }) {
  return (
    <dl className="ta-kv">
      {rows.map(([label, value, mono]) => (
        <div className="ta-kv__row" key={label}>
          <dt>{label}</dt>
          <dd className={mono ? "ta-mono" : undefined}>
            {value === null || value === undefined || value === "" ? "-" : String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
