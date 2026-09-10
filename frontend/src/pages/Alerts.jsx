import { useCallback, useEffect, useMemo, useState } from "react";
import { getAlerts } from "../services/api";
import AlertTable from "../components/AlertTable";
import FilterBar from "../components/FilterBar";
import Pagination from "../components/Pagination";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

const PAGE_SIZE = 10;

const ALERT_STATUS_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "closed", label: "Closed" },
];

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [eventType, setEventType] = useState("");

  const [sortField, setSortField] = useState("created_at");
  const [sortDirection, setSortDirection] = useState("desc");
  const [currentPage, setCurrentPage] = useState(1);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);

    getAlerts()
      .then(setAlerts)
      .catch(() => setError("Unable to connect to the security API."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const eventTypes = useMemo(() => {
    return [...new Set(alerts.map((alert) => alert.event_type).filter(Boolean))];
  }, [alerts]);

  const filteredAndSortedAlerts = useMemo(() => {
    const searchValue = search.toLowerCase().trim();

    const filtered = alerts.filter((alert) => {
      const matchesSearch =
        !searchValue ||
        [
          alert.event_type,
          alert.source_type,
          alert.source_ip,
          alert.status,
          alert.severity,
        ]
          .filter(Boolean)
          .some((value) =>
            String(value).toLowerCase().includes(searchValue)
          );

      const matchesSeverity =
        !severity || alert.severity === severity;

      const matchesStatus =
        !status || alert.status === status;

      const matchesEventType =
        !eventType || alert.event_type === eventType;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus &&
        matchesEventType
      );
    });

    return [...filtered].sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];

      if (sortField === "created_at") {
        const difference =
          new Date(aValue) - new Date(bValue);

        return sortDirection === "asc" ? difference : -difference;
      }

      const aString = String(aValue ?? "").toLowerCase();
      const bString = String(bValue ?? "").toLowerCase();

      const comparison = aString.localeCompare(bString);

      return sortDirection === "asc"
        ? comparison
        : -comparison;
    });
  }, [
    alerts,
    search,
    severity,
    status,
    eventType,
    sortField,
    sortDirection,
  ]);

  // Kept immediately after the other hooks (rather than further down near
  // the plain derived values below) so every useState/useMemo/useEffect in
  // this component stays grouped at the top level, unconditionally called
  // on every render.
  useEffect(() => {
    setCurrentPage(1);
  }, [search, severity, status, eventType, sortField, sortDirection]);

  // Plain derived values (not hooks) - safe to compute after all hooks.
  const totalPages = Math.max(
    1,
    Math.ceil(filteredAndSortedAlerts.length / PAGE_SIZE)
  );

  const paginatedAlerts = filteredAndSortedAlerts.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  const totalResults = filteredAndSortedAlerts.length;
  const rangeStart = totalResults === 0 ? 0 : (currentPage - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(currentPage * PAGE_SIZE, totalResults);

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;

  return (
    <div className="page">
      <h1 className="page-title">Alerts</h1>

      <FilterBar
  search={search}
  onSearchChange={setSearch}
  severity={severity}
  onSeverityChange={setSeverity}
  status={status}
  onStatusChange={setStatus}
  statusOptions={ALERT_STATUS_OPTIONS}
  eventType={eventType}
  onEventTypeChange={setEventType}
  eventTypes={eventTypes}
  showEventType={true}
  searchPlaceholder="Search alerts..."
/>

      <div className="table-toolbar">
        <span>
          {totalResults === 0
            ? "Showing 0 of 0 alerts"
            : `Showing ${rangeStart}–${rangeEnd} of ${totalResults} alerts`}
        </span>

        <div className="sort-controls">
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value)}
          >
            <option value="created_at">Sort by Created</option>
            <option value="severity">Sort by Severity</option>
            <option value="event_type">Sort by Event Type</option>
            <option value="status">Sort by Status</option>
          </select>

          <button
            type="button"
            onClick={() =>
              setSortDirection((current) =>
                current === "desc" ? "asc" : "desc"
              )
            }
          >
            {sortDirection === "desc"
              ? "↓ Descending"
              : "↑ Ascending"}
          </button>
        </div>
      </div>

      <AlertTable alerts={paginatedAlerts} />

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
      />
    </div>
  );
}