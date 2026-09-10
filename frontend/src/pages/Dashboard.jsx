import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts, getIncidents } from "../services/api";
import StatCard from "../components/StatCard";
import AlertTable from "../components/AlertTable";
import IncidentTable from "../components/IncidentTable";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

const ACTIVE_INCIDENT_STATUSES = ["open", "investigating"];

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);

    Promise.all([getAlerts(), getIncidents()])
      .then(([alertsData, incidentsData]) => {
        setAlerts(alertsData);
        setIncidents(incidentsData);
      })
      .catch(() => {
        setError("Unable to connect to the security API.");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;

  // -----------------------------
  // Alert statistics
  // -----------------------------

  const totalAlerts = alerts.length;

  const openAlerts = alerts.filter(
    (alert) => String(alert.status).toLowerCase() === "open"
  ).length;

  const highCriticalAlerts = alerts.filter((alert) => {
    const severity = String(alert.severity).toLowerCase();

    return severity === "high" || severity === "critical";
  }).length;

  const criticalAlerts = alerts.filter(
    (alert) => String(alert.severity).toLowerCase() === "critical"
  ).length;

  // -----------------------------
  // Incident statistics
  // -----------------------------

  const activeIncidents = incidents.filter((incident) =>
    ACTIVE_INCIDENT_STATUSES.includes(
      String(incident.status).toLowerCase()
    )
  );

  const totalIncidents = incidents.length;

  // -----------------------------
  // Recent data
  // -----------------------------

  const recentAlerts = [...alerts]
    .sort(
      (a, b) =>
        new Date(b.created_at).getTime() -
        new Date(a.created_at).getTime()
    )
    .slice(0, 5);

  const recentActiveIncidents = [...activeIncidents].sort(
    (a, b) =>
      new Date(b.created_at).getTime() -
      new Date(a.created_at).getTime()
  );

  return (
    <div className="dashboard">
      <h1 className="page-title">Security Overview</h1>

      {/* Statistics */}
      <div className="stats-grid">
        <StatCard
          label="Total Alerts"
          value={totalAlerts}
        />

        <StatCard
          label="Open Alerts"
          value={openAlerts}
        />

        <StatCard
          label="High/Critical Alerts"
          value={highCriticalAlerts}
          accent="critical"
        />

        <StatCard
          label="Critical Alerts"
          value={criticalAlerts}
          accent="critical"
        />

        <StatCard
          label="Active Incidents"
          value={activeIncidents.length}
        />

        <StatCard
          label="Total Incidents"
          value={totalIncidents}
        />
      </div>

      {/* Recent Alerts */}
      <section className="dashboard-section">
        <div className="section-header">
          <h2>Recent Alerts</h2>

          <Link to="/alerts" className="section-link">
            View all alerts →
          </Link>
        </div>

        <AlertTable
          alerts={recentAlerts}
          compact
        />
      </section>

      {/* Active Incidents */}
      <section className="dashboard-section">
        <div className="section-header">
          <h2>Active Incidents</h2>

          <Link to="/incidents" className="section-link">
            View all incidents →
          </Link>
        </div>

        <IncidentTable
          incidents={recentActiveIncidents}
        />
      </section>
    </div>
  );
}