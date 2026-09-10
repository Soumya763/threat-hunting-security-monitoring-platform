export default function Loading({ message = "Loading..." }) {
  return (
    <div className="state-panel state-panel--loading">
      <div className="spinner" aria-hidden="true" />
      <p>{message}</p>
    </div>
  );
}
