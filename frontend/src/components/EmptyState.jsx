export default function EmptyState({ title, children }) {
  return (
    <div className="state-panel">
      <p className="state-panel__message"><strong>{title}</strong></p>
      {children ? <div className="ta-muted">{children}</div> : null}
    </div>
  );
}
