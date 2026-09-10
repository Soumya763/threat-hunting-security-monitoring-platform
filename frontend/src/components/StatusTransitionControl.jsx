import { useState } from "react";

// Small form for submitting a status transition. Receives an
// already-filtered statusOptions array from its parent page (computed
// via getAllowedNextStatuses), so it stays a dumb, presentational
// component with no lifecycle-rule knowledge of its own. The actor is no
// longer a field here - the backend derives it from the authenticated
// user (see api/alerts.py, api/incidents.py); the parent page only
// renders this control at all when the user is logged in.
export default function StatusTransitionControl({ statusOptions, onSubmit }) {
  const [toStatus, setToStatus] = useState(statusOptions[0]?.value || "");
  const [note, setNote] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (statusOptions.length === 0) {
    return null;
  }

  const handleSubmit = (event) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    onSubmit({ to_status: toStatus, note: note || undefined })
      .then(() => setNote(""))
      .catch((err) => {
        setError(err.response?.data?.detail || "Unable to update status.");
      })
      .finally(() => setSubmitting(false));
  };

  return (
    <form className="status-transition" onSubmit={handleSubmit}>
      {error && <p className="status-transition__error">{error}</p>}

      <div className="status-transition__row">
        <label htmlFor="status-transition-to">New status</label>
        <select
          id="status-transition-to"
          value={toStatus}
          onChange={(e) => setToStatus(e.target.value)}
        >
          {statusOptions.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      <div className="status-transition__row">
        <label htmlFor="status-transition-note">Note (optional)</label>
        <textarea
          id="status-transition-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
        />
      </div>

      <button type="submit" className="btn" disabled={submitting}>
        {submitting ? "Updating…" : "Update Status"}
      </button>
    </form>
  );
}
