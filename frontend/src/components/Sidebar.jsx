import { NavLink } from "react-router-dom";
import { useHealth } from "../context/HealthContext";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/alerts", label: "Alerts", end: false },
  { to: "/incidents", label: "Incidents", end: false },
];

const STATUS_CONFIG = {
  loading: { dot: "", label: "Checking…" },
  operational: { dot: "status-dot--good", label: "API Connected" },
  degraded: { dot: "status-dot--warn", label: "API Degraded" },
  down: { dot: "status-dot--bad", label: "API Unreachable" },
};

function ShieldIcon() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2l7 3v6c0 5-3.4 8.6-7 11-3.6-2.4-7-6-7-11V5l7-3z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        fill="rgba(57, 135, 229, 0.12)"
      />
      <path
        d="M9 12l2 2 4-4.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Sidebar() {
  const { status } = useHealth();
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.loading;

  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <ShieldIcon />
        <div className="sidebar__brand-text">
          <div className="sidebar__brand-title">Threat Hunting</div>
          <div className="sidebar__brand-subtitle">Security Platform</div>
        </div>
      </div>

      <nav className="sidebar__nav">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `sidebar__nav-link${isActive ? " sidebar__nav-link--active" : ""}`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar__status">
        <div className="sidebar__status-title">System Status</div>
        <div className="sidebar__status-row">
          {config.dot && <span className={`status-dot ${config.dot}`} aria-hidden="true" />}
          {config.label}
        </div>
      </div>
    </aside>
  );
}
