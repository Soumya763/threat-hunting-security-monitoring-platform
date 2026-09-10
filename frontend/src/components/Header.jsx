import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useHealth } from "../context/HealthContext";

const STATUS_CONFIG = {
  loading: { dot: "", modifier: "", label: "Checking…" },
  operational: { dot: "status-dot--good", modifier: "", label: "SYSTEM OPERATIONAL" },
  degraded: { dot: "status-dot--warn", modifier: "app-header__status--warn", label: "DEGRADED" },
  down: { dot: "status-dot--bad", modifier: "app-header__status--bad", label: "API UNREACHABLE" },
};

export default function Header() {
  const { status } = useHealth();
  const { isAuthenticated, username, logout } = useAuth();
  const navigate = useNavigate();
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.loading;

  // logout() (AuthContext) only clears the stored session/state - it can't
  // navigate itself because AuthProvider sits outside BrowserRouter in
  // App.jsx, so useNavigate() isn't available there. Header is rendered
  // inside BrowserRouter, so doing the redirect here (real React Router
  // navigation, no full page reload) is the smallest fix for "logout
  // doesn't leave the page."
  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <header className="app-header">
      <h1 className="app-header__title">Threat Hunting &amp; Security Monitoring</h1>
      <div className="app-header__right">
        <div className={`app-header__status ${config.modifier}`}>
          {config.dot && <span className={`status-dot ${config.dot}`} aria-hidden="true" />}
          {config.label}
        </div>
        {isAuthenticated ? (
          <button type="button" className="link-button app-header__auth" onClick={handleLogout}>
            Log out ({username})
          </button>
        ) : (
          <Link to="/login" className="app-header__auth">
            Log in
          </Link>
        )}
      </div>
    </header>
  );
}
