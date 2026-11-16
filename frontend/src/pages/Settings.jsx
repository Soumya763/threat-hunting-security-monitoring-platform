import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getHealth, getPlatformLimits, getProviders } from "../services/api";
import KeyValue from "../components/KeyValue";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { useAuth } from "../context/AuthContext";
import { errorMessage, formatBytes } from "../utils/format";

export default function Settings() {
  const { username, logout } = useAuth();
  const navigate = useNavigate();
  const [providers, setProviders] = useState(null);
  const [limits, setLimits] = useState(null);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);

  function load() {
    setError(null);
    getHealth().then(setHealth).catch(() => setHealth(null));
    Promise.all([getProviders(), getPlatformLimits()])
      .then(([p, l]) => { setProviders(p); setLimits(l); })
      .catch((err) => setError(errorMessage(err, "Unable to load settings.")));
  }

  useEffect(load, []);

  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!providers || !limits) return <Loading message="Loading settings..." />;

  return (
    <div className="page">
      <h1 className="page-title">Settings</h1>

      <section className="ta-card">
        <h2>Account</h2>
        <KeyValue rows={[["Signed in as", username]]} />
        <button type="button" className="btn" onClick={() => { logout(); navigate("/login"); }}>Log out</button>
      </section>

      <section className="ta-card">
        <h2>Search and log engine</h2>
        <KeyValue rows={[
          ["Engine", "OpenSearch (search and log analytics)"],
          ["Status", health ? health.opensearch : "unknown"],
          ["Used by", "Detection rules, Log Monitoring, local-context pivots, Dashboard event counts"],
        ]} />
      </section>

      <section className="ta-card">
        <h2>Threat-intelligence providers</h2>
        <p className="ta-muted">
          Keys are read from the backend environment (for example <code className="ta-code">VIRUSTOTAL_API_KEY</code>).
          They are never shown in the browser. A provider that is not configured is skipped and the analysis continues
          with local checks.
        </p>
        <table className="data-table ta-table">
          <thead><tr><th scope="col">Provider</th><th scope="col">Status</th><th scope="col">Used for</th><th scope="col">Limits and terms</th></tr></thead>
          <tbody>{providers.map((p) => (
            <tr key={p.id}>
              <td>{p.name}<div className="ta-muted ta-small ta-mono">{p.environment_variable}</div></td>
              <td><span className={`provider-status provider-status--${p.configured ? "ok" : "not_configured"}`}>{p.configured ? "Configured" : "Not configured"}</span></td>
              <td className="ta-small">{p.supports.join(", ")}</td>
              <td className="ta-small">{p.limits}</td>
            </tr>
          ))}</tbody>
        </table>
      </section>

      <section className="ta-card">
        <h2>Retention and limits</h2>
        <KeyValue rows={[
          ["Maximum upload size", formatBytes(limits.max_upload_bytes)],
          ["Supported file types", limits.supported_extensions.join(", ")],
          ["Uploaded file retention", `${limits.file_retention_hours} hour(s), then the bytes are deleted (the report stays)`],
          ["URL redirects followed", `up to ${limits.url_max_redirects}, each one re-checked`],
          ["URL fetch timeout", `${limits.url_fetch_timeout_seconds} s per hop`],
          ["URL body read limit", formatBytes(limits.url_max_body_bytes)],
          ["Hash lookups to providers", limits.provider_hash_lookup_enabled ? "enabled (hash only)" : "disabled"],
          ["Provider cache", `${limits.provider_cache_ttl_hours} hour(s) for consulted results`],
          ["urlscan.io visibility for submissions", limits.urlscan_visibility],
          ["Log search lookback for pivots", `${limits.pivot_lookback_days} day(s)`],
          ["Analysis submissions per user", `${limits.analysis_submissions_per_minute} per minute`],
        ]} />
      </section>
    </div>
  );
}
