import { PROVIDER_STATUS_LABELS } from "../utils/format";

// One row per provider, including the ones that were not configured or failed.
// Missing or failed providers are never presented as "no detections".
export default function ProviderTable({ providers }) {
  const entries = Object.entries(providers || {});
  if (entries.length === 0) {
    return <p className="ta-muted">No provider results were recorded.</p>;
  }
  return (
    <table className="data-table ta-table">
      <thead>
        <tr>
          <th scope="col">Provider</th>
          <th scope="col">Status</th>
          <th scope="col">Detections</th>
          <th scope="col">Details</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([name, result]) => {
          const det = result.detection;
          return (
            <tr key={name}>
              <td>{name}</td>
              <td>
                <span className={`provider-status provider-status--${result.status}`}>
                  {PROVIDER_STATUS_LABELS[result.status] || result.status}
                </span>
              </td>
              <td>{det ? `${det.positives} of ${det.total} engines` : "-"}</td>
              <td className="ta-small">
                {result.message || summarise(result.summary)}
                {result.cached ? <span className="ta-tag">cached</span> : null}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function summarise(summary) {
  if (!summary || Object.keys(summary).length === 0) return null;
  const parts = [];
  if (summary.suggested_threat_label) parts.push(`Label: ${summary.suggested_threat_label}`);
  if (summary.signature) parts.push(`Signature: ${summary.signature}`);
  if (summary.pulse_count !== undefined) parts.push(`${summary.pulse_count} OTX pulse(s)`);
  if (summary.abuse_confidence_score !== undefined && summary.abuse_confidence_score !== null) {
    parts.push(`Abuse confidence ${summary.abuse_confidence_score}%`);
  }
  if (summary.malicious_scans !== undefined) parts.push(`${summary.malicious_scans} malicious prior scan(s)`);
  if (summary.registrar) parts.push(`Registrar: ${summary.registrar}`);
  if (summary.age_days !== undefined && summary.age_days !== null) parts.push(`Registered ${summary.age_days} day(s) ago`);
  if (summary.analysis_id) parts.push(`Analysis id ${summary.analysis_id}`);
  return parts.length ? parts.join(" · ") : null;
}
