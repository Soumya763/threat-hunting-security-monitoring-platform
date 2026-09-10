import { useCallback, useEffect, useMemo, useState } from "react";
import { getIncidents } from "../services/api";
import IncidentTable from "../components/IncidentTable";
import FilterBar from "../components/FilterBar";
import Pagination from "../components/Pagination";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";

const PAGE_SIZE = 10;

const INCIDENT_STATUS_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const [sortField, setSortField] = useState("created_at");
  const [sortDirection, setSortDirection] = useState("desc");
  const [currentPage, setCurrentPage] = useState(1);

  const loadData = useCallback(() => {
    setLoading(true);
    setError(null);

    getIncidents()
      .then(setIncidents)
      .catch(() => setError("Unable to connect to the security API."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const filteredAndSortedIncidents = useMemo(() => {
    const searchValue = search.toLowerCase().trim();

    const filtered = incidents.filter((incident) => {
      const matchesSearch =
        !searchValue ||
        [
          incident.title,
          incident.description,
          incident.status,
          incident.severity,
        ]
          .filter(Boolean)
          .some((value) =>
            String(value).toLowerCase().includes(searchValue)
          );

      const matchesSeverity =
        !severity || incident.severity === severity;

      const matchesStatus =
        !status || incident.status === status;

      return matchesSearch && matchesSeverity && matchesStatus;
    });

    return [...filtered].sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];

      if (sortField === "created_at") {
        const difference =
          new Date(aValue) - new Date(bValue);

        return sortDirection === "asc"
          ? difference
          : -difference;
      }

      const comparison = String(aValue ?? "")
        .toLowerCase()
        .localeCompare(String(bValue ?? "").toLowerCase());

      return sortDirection === "asc"
        ? comparison
        : -comparison;
    });
  }, [
    incidents,
    search,
    severity,
    status,
    sortField,
    sortDirection,
  ]);

  const totalPages = Math.max(
    1,
    Math.ceil(filteredAndSortedIncidents.length / PAGE_SIZE)
  );

  const paginatedIncidents = filteredAndSortedIncidents.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [search, severity, status, sortField, sortDirection]);

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={loadData} />;

  return (
    <div className="page">
      <h1 className="page-title">Incidents</h1>

      <FilterBar
  search={search}
  onSearchChange={setSearch}
  severity={severity}
  onSeverityChange={setSeverity}
  status={status}
  onStatusChange={setStatus}
  statusOptions={INCIDENT_STATUS_OPTIONS}
  showEventType={false}
  searchPlaceholder="Search incidents..."
/>

      <div className="table-toolbar">
        <span>
          Showing {paginatedIncidents.length} of{" "}
          {filteredAndSortedIncidents.length} incidents
        </span>

        <div className="sort-controls">
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value)}
          >
            <option value="created_at">Sort by Created</option>
            <option value="severity">Sort by Severity</option>
            <option value="status">Sort by Status</option>
            <option value="title">Sort by Title</option>
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

      <IncidentTable incidents={paginatedIncidents} />

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
      />
    </div>
  );
}