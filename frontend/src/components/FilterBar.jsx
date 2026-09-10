import React from "react";

const DEFAULT_STATUS_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "closed", label: "Closed" },
];

export default function FilterBar({
  search,
  onSearchChange,
  severity,
  onSeverityChange,
  status,
  onStatusChange,
  statusOptions = DEFAULT_STATUS_OPTIONS,
  eventType = "",
  onEventTypeChange,
  eventTypes = [],
  showEventType = false,
  searchPlaceholder = "Search alerts...",
}) {
  return (
    <div className="filter-bar">
      <input
        type="text"
        placeholder={searchPlaceholder}
        value={search}
        onChange={(e) => onSearchChange(e.target.value)}
      />

      <select
        value={severity}
        onChange={(e) => onSeverityChange(e.target.value)}
      >
        <option value="">All Severities</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="critical">Critical</option>
      </select>

      <select
        value={status}
        onChange={(e) => onStatusChange(e.target.value)}
      >
        <option value="">All Statuses</option>
        {statusOptions.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>

      {showEventType && (
        <select
          value={eventType}
          onChange={(e) => onEventTypeChange(e.target.value)}
        >
          <option value="">All Event Types</option>

          {eventTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}