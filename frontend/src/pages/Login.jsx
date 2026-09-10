import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    login(username, password)
      .then(() => navigate("/"))
      .catch((err) => {
        setError(err.response?.data?.detail || "Unable to log in.");
      })
      .finally(() => setSubmitting(false));
  };

  return (
    <div className="page" style={{ maxWidth: "360px" }}>
      <h1 className="page-title">Log In</h1>

      <div className="detail-card">
        <form className="status-transition" onSubmit={handleSubmit}>
          {error && <p className="status-transition__error">{error}</p>}

          <div className="status-transition__row">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="status-transition__row">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button type="submit" className="btn" disabled={submitting}>
            {submitting ? "Logging in…" : "Log In"}
          </button>
        </form>
      </div>
    </div>
  );
}
