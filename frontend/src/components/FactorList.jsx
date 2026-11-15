// Every point of the score with its reason. Nothing is hidden behind the total.
export default function FactorList({ factors }) {
  if (!factors || factors.length === 0) {
    return <p className="ta-muted">No factors contributed to the score.</p>;
  }
  return (
    <table className="data-table ta-table">
      <thead>
        <tr>
          <th scope="col">Points</th>
          <th scope="col">Factor</th>
          <th scope="col">Why it counts</th>
        </tr>
      </thead>
      <tbody>
        {factors.map((factor) => (
          <tr key={factor.code}>
            <td className="ta-points">+{factor.points}</td>
            <td>{factor.label}</td>
            <td>{factor.reason}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
