// Not one of the explicitly-named components, but the "unable to connect,
// with a retry button" state is needed identically on 5 different pages
// (Dashboard, Alerts, AlertDetails, Incidents, IncidentDetails), so it's
// factored out here rather than duplicated - in line with "keep the code
// clean and componentized".
export default function ErrorState({
  message = "Unable to connect to the security API.",
  onRetry,
}) {
  return (
    <div className="state-panel state-panel--error">
      <p className="state-panel__message">{message}</p>
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
