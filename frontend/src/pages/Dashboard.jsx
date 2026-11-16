import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts, getDashboardSummary, getIncidents } from "../services/api";
import StatCard from "../components/StatCard";
import AlertTable from "../components/AlertTable";
import IncidentTable from "../components/IncidentTable";
import TrendChart from "../components/TrendChart";
import RiskBadge from "../components/RiskBadge";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import { formatDateTime } from "../utils/formatDate";
import { formatPercent } from "../utils/format";

const ACTIVE_INCIDENT_STATUSES = ["open", "investigating"];
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [summary, setSummary] = useState(null);
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
      .then(() => getDashboardSummary().then(setSummary).catch(() => setSummary(null)))
      .catch(() => setError("Unable to connect to the security API."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const stats = useMemo(() => {
    const severityCount = (level) => alerts.filter((a) => String(a.severity).toLowerCase() === level).length;
    const active = incidents.filter((i) => ACTIVE_INCIDENT_STATUSES.includes(String(i.status).toLowerCase()));
    return {
      totalAlerts: alerts.length,
      openAlerts: alerts.filter((a) => String(a.status).toLowerCase() === "open").length,
      highCritical: severityCount("high") + severityCount("critical"),
      severity: SEVERITY_ORDER.map((level) => ({ level, count: severityCount(level) })),
      active,
      totalIncidents: incidents.length,
      recentAlerts: [...alerts].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 5),
      recentActive: [...active].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)),
    };
  }, [alerts, incidents]);

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;

  const analyses = summary?.analyses;
  const severityTotal = stats.totalAlerts || 1;

  return (
    <div className="dashboard">
      <h1 className="page-title">Security Overview</h1>

      <h2 className="ta-subhead">Alerts and incidents</h2>
      <div className="stats-grid">
        <StatCard label="Total Alerts" value={stats.totalAlerts} />
        <StatCard label="Open Alerts" value={stats.openAlerts} />
        <StatCard label="High/Critical Alerts" value={stats.highCritical} accent="critical" />
        <StatCard label="Critical Alerts" value={stats.severity[0].count} accent="critical" />
        <StatCard label="Active Incidents" value={stats.active.length} />
        <StatCard label="Total Incidents" value={stats.totalIncidents} />
      </div>

      <div className="ta-grid-2">
        <section className="ta-card">
          <h2>Alerts by severity</h2>
          {stats.totalAlerts === 0 ? (
            <EmptyState title="No alerts yet">Alerts appear when detection rules match ingested logs.</EmptyState>
          ) : (
            <ul className="severity-bars">
              {stats.severity.map(({ level, count }) => (
                <li key={level}>
                  <span className="severity-bars__label">{level}</span>
                  <span className="severity-bars__track">
                    <span className={`severity-bars__fill severity-bars__fill--${level}`} style={{ width: `${Math.round((count * 100) / severityTotal)}%` }} />
                  </span>
                  <span className="severity-bars__count">{count} ({formatPercent(count, stats.totalAlerts)})</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="ta-card">
          <h2>Alert activity, last 14 days</h2>
          {summary ? <TrendChart data={summary.trend} /> : <p className="ta-muted">Trend data is unavailable.</p>}
        </section>
      </div>

      <h2 className="ta-subhead">Threat analysis (your analyses)</h2>
      <div className="stats-grid">
        <StatCard label="Files Analysed" value={analyses?.files ?? "-"} />
        <StatCard label="URLs Analysed" value={analyses?.urls ?? "-"} />
        <StatCard label="Indicator Searches" value={analyses?.indicator_searches ?? "-"} />
        <StatCard label="High/Critical Results" value={analyses?.malicious_or_high_risk ?? "-"} accent="critical" />
      </div>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Latest analyses</h2>
          <Link to="/history" className="section-link">Analysis history →</Link>
        </div>
        {summary?.recent_analyses?.length ? (
          <table className="data-table">
            <thead><tr><th scope="col">Analysis</th><th scope="col">Type</th><th scope="col">Risk</th><th scope="col">Status</th><th scope="col">When</th></tr></thead>
            <tbody>{summary.recent_analyses.map((a) => (
              <tr key={a.id}>
                <td className="ta-break"><Link to={`/analysis/${a.id}`}>{a.display_name || a.indicator_value}</Link></td>
                <td>{a.kind}</td>
                <td><RiskBadge level={a.risk_level} /></td>
                <td>{a.status}</td>
                <td>{formatDateTime(a.created_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        ) : <EmptyState title="No analyses yet">Try <Link to="/files">File Analysis</Link>, <Link to="/urls">URL Analysis</Link> or <Link to="/search">Threat Intelligence Search</Link>.</EmptyState>}
      </section>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Recent Alerts</h2>
          <Link to="/alerts" className="section-link">View all alerts →</Link>
        </div>
        <AlertTable alerts={stats.recentAlerts} compact />
      </section>

      <section className="dashboard-section">
        <div className="section-header">
          <h2>Active Incidents</h2>
          <Link to="/incidents" className="section-link">View all incidents →</Link>
        </div>
        <IncidentTable incidents={stats.recentActive} />
      </section>
    </div>
  );
}
