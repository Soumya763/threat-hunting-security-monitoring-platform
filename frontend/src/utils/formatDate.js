// Shared timestamp formatter so every table/detail view renders dates the
// same way instead of repeating `new Date(...).toLocaleString()` calls.
export function formatDateTime(isoString) {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  return date.toLocaleString();
}
