import { useState } from "react";
import { checkIpReputation } from "../services/api";
import Loading from "./Loading";
import { formatDateTime } from "../utils/formatDate";

// Analyst-triggered AbuseIPDB lookup for an alert's source IP (Phase 4).
// Deliberately not fetched automatically on mount - a provider call only
// happens when the analyst explicitly clicks "Check Reputation", both to
// respect the "don't hammer AbuseIPDB" requirement and because the API
// key/response never needs to reach the client until asked for. Reuses
// existing primitives only (.detail-card/.detail-grid from the page,
// .btn, .text-muted, <Loading>) - no new CSS classes.
const STATUS_MESSAGES = {
  no_source_ip: "No source IP recorded for this alert.",
  invalid_ip: "This alert's source IP is not a valid address.",
  private_ip: "Private/internal IP address - reputation lookup not applicable.",
  not_configured: "AbuseIPDB is not configured on this server.",
  invalid_api_key: "AbuseIPDB rejected the configured API key.",
  rate_limited: "AbuseIPDB rate limit reached - try again shortly.",
  unavailable: "AbuseIPDB is currently unavailable - try again later.",
};

export default function ReputationPanel({ alertId, sourceIp }) {
  const [status, setStatus] = useState("idle"); // idle | loading | done | error
  const [result, setResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  if (!sourceIp) {
    return <p className="text-muted">No source IP recorded for this alert.</p>;
  }

  const handleCheck = () => {
    setStatus("loading");
    setErrorMessage(null);
    checkIpReputation(alertId)
      .then((data) => {
        setResult(data);
        setStatus("done");
      })
      .catch((err) => {
        setErrorMessage(err.response?.data?.detail || "Unable to check IP reputation.");
        setStatus("error");
      });
  };

  return (
    <div>
      <p className="text-muted" style={{ marginTop: 0 }}>
        Source IP: {sourceIp}
      </p>

      <button type="button" className="btn" onClick={handleCheck} disabled={status === "loading"}>
        {status === "loading" ? "Checking…" : "Check Reputation"}
      </button>

      {status === "loading" && <Loading message="Checking IP reputation…" />}

      {status === "error" && (
        <p className="status-transition__error" style={{ marginTop: "1rem" }}>
          {errorMessage}
        </p>
      )}

      {status === "done" && result && result.status !== "ok" && (
        <p className="text-muted" style={{ marginTop: "1rem" }}>
          {STATUS_MESSAGES[result.status] || result.detail || "Reputation lookup unavailable."}
        </p>
      )}

      {status === "done" && result && result.status === "ok" && (
        <dl className="detail-grid" style={{ marginTop: "1rem" }}>
          <div className="detail-grid__row">
            <dt>IP Address</dt>
            <dd>{result.reputation.ip_address}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Abuse Confidence Score</dt>
            <dd>{result.reputation.abuse_confidence_score}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Country</dt>
            <dd>{result.reputation.country || "—"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>ISP</dt>
            <dd>{result.reputation.isp || "—"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Domain</dt>
            <dd>{result.reputation.domain || "—"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Total Reports</dt>
            <dd>{result.reputation.total_reports ?? "—"}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Last Reported</dt>
            <dd>
              {result.reputation.last_reported_at
                ? formatDateTime(result.reputation.last_reported_at)
                : "—"}
            </dd>
          </div>
          <div className="detail-grid__row">
            <dt>Provider</dt>
            <dd>{result.reputation.provider}</dd>
          </div>
          <div className="detail-grid__row">
            <dt>Queried At</dt>
            <dd>{formatDateTime(result.reputation.queried_at)}</dd>
          </div>
        </dl>
      )}
    </div>
  );
}
