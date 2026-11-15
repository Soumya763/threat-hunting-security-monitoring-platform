import { STEP_STATUS_LABELS } from "../utils/format";

// The analysis steps and what each one actually did. A failed step is a visible gap.
export default function StepList({ steps }) {
  if (!steps || steps.length === 0) return <p className="ta-muted">No step information yet.</p>;
  return (
    <ol className="ta-steps">
      {steps.map((step) => (
        <li key={step.name} className={`ta-step ta-step--${step.status}`}>
          <span className="ta-step__name">{step.name}</span>
          <span className="ta-step__status">{STEP_STATUS_LABELS[step.status] || step.status}</span>
          {step.message ? <span className="ta-step__message">{step.message}</span> : null}
        </li>
      ))}
    </ol>
  );
}
