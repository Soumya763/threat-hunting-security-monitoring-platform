import { useState } from "react";
import { formatDateTime } from "../utils/formatDate";

// Incident-only investigation notes (Phase 3): a read-only, oldest-first
// list plus an add-note form. Notes are immutable once created - there
// is no edit/delete action here, matching the backend (no PATCH/DELETE
// endpoint exists for a note). Reuses the existing .audit-trail list
// markup (AuditTrail.jsx) for visual consistency and .status-transition
// form styling (StatusTransitionControl.jsx) - no new CSS classes.
export default function InvestigationNotes({ notes, onSubmit }) {
  const [content, setContent] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();
    const trimmed = content.trim();
    if (!trimmed) return;

    setError(null);
    setSubmitting(true);
    onSubmit(trimmed)
      .then(() => setContent(""))
      .catch((err) => {
        setError(err.response?.data?.detail || "Unable to add note.");
      })
      .finally(() => setSubmitting(false));
  };

  return (
    <>
      {notes.length === 0 ? (
        <p className="text-muted">No investigation notes yet.</p>
      ) : (
        <ul className="audit-trail">
          {notes.map((note) => (
            <li className="audit-trail__row" key={note.id}>
              <div className="audit-trail__headline">
                <span>{note.author}</span>
                <span className="text-muted">{formatDateTime(note.created_at)}</span>
              </div>
              <div className="audit-trail__meta">{note.content}</div>
            </li>
          ))}
        </ul>
      )}

      <form className="status-transition" onSubmit={handleSubmit} style={{ marginTop: "1.25rem" }}>
        {error && <p className="status-transition__error">{error}</p>}

        <div className="status-transition__row">
          <label htmlFor="new-note-content">Add note</label>
          <textarea
            id="new-note-content"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={3}
          />
        </div>

        <button type="submit" className="btn" disabled={submitting || !content.trim()}>
          {submitting ? "Saving…" : "Add Note"}
        </button>
      </form>
    </>
  );
}
