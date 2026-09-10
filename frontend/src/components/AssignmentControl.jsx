import { useState } from "react";

// Small form for assigning an alert/incident to an analyst, by username
// (Phase 3). Shared by AlertDetails and IncidentDetails - the assignment
// shape is identical for both entities (see the PATCH .../assignment
// endpoints in api/alerts.py / api/incidents.py), so one component
// covers both. Styled with the existing .status-transition / .btn /
// .link-button classes (see StatusTransitionControl.jsx) rather than
// introducing new CSS - no new classes needed.
export default function AssignmentControl({ currentAssignee, onSubmit }) {
  const [username, setUsername] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = (nextUsername) => {
    setError(null);
    setSubmitting(true);
    onSubmit(nextUsername)
      .then(() => setUsername(""))
      .catch((err) => {
        setError(err.response?.data?.detail || "Unable to update assignment.");
      })
      .finally(() => setSubmitting(false));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    const trimmed = username.trim();
    if (!trimmed) return;
    submit(trimmed);
  };

  return (
    <form className="status-transition" onSubmit={handleSubmit}>
      {error && <p className="status-transition__error">{error}</p>}

      <div className="status-transition__row">
        <label htmlFor="assignment-username">Assign to (username)</label>
        <input
          id="assignment-username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder={currentAssignee ? `currently: ${currentAssignee}` : "unassigned"}
        />
      </div>

      <button type="submit" className="btn" disabled={submitting || !username.trim()}>
        {submitting ? "Assigning…" : "Assign"}
      </button>
      {currentAssignee && (
        <button
          type="button"
          className="link-button"
          disabled={submitting}
          onClick={() => submit(null)}
          style={{ marginLeft: "0.75rem" }}
        >
          Unassign
        </button>
      )}
    </form>
  );
}
