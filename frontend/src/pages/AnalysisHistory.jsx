import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import RiskBadge from "../components/RiskBadge";
import EmptyState from "../components/EmptyState";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import { getAnalyses } from "../services/api";
import { errorMessage } from "../utils/format";
import { formatDateTime } from "../utils/formatDate";

const KIND_OPTIONS = [["", "All types"], ["file", "Files"], ["url", "URLs"], ["indicator", "Indicator searches"]];
const RISK_OPTIONS = [["", "Any risk"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"],
  ["low", "Low"], ["clean", "Clean"], ["insufficient_evidence", "Unknown"]];
const SORT_OPTIONS = [["created_at", "Date"], ["risk_score", "Risk score"]];
const PAGE_SIZES = [10, 20, 50];

export default function AnalysisHistory() {
  const [params, setParams] = useSearchParams();
  const kind = params.get("kind") || "";
  const risk = params.get("risk") || "";
  const sort = params.get("sort") || "created_at";
  const order = params.get("order") || "desc";
  const page = Number(params.get("page") || 1);
  const pageSize = Number(params.get("page_size") || 20);
  const [text, setText] = useState(params.get("q") || "");

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const update = useCallback((changes) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      Object.entries(changes).forEach(([k, v]) => {
        if (v === "" || v === null || v === undefined) next.delete(k);
        else next.set(k, String(v));
      });
      if (!("page" in changes)) next.delete("page");
      return next;
    });
  }, [setParams]);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    getAnalyses({
      kind: kind || undefined,
      risk: risk || undefined,
      q: params.get("q") || undefined,
      sort, order, page, page_size: pageSize,
    })
      .then(setData)
      .catch((err) => setError(errorMessage(err, "Unable to load analysis history.")))
      .finally(() => setLoading(false));
  }, [kind, risk, params, sort, order, page, pageSize]);

  useEffect(() => { load(); }, [load]);

  function onSearch(event) {
    event.preventDefault();
    update({ q: text.trim() });
  }

  return (
    <div className="page">
      <h1 className="page-title">Analysis History</h1>
      <p className="ta-muted">Every file, URL and indicator search you have run. Only you can see these records.</p>

      <form className="ta-filters" onSubmit={onSearch} role="search">
        <label className="ta-field">
          <span>Type</span>
          <select className="ta-input" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            {KIND_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="ta-field">
          <span>Risk</span>
          <select className="ta-input" value={risk} onChange={(e) => update({ risk: e.target.value })}>
            {RISK_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="ta-field ta-field--grow">
          <span>Search name, indicator or hash</span>
          <div className="ta-inline">
            <input className="ta-input" value={text} maxLength={200} onChange={(e) => setText(e.target.value)} />
            <button type="submit" className="btn">Search</button>
          </div>
        </label>
        <label className="ta-field">
          <span>Sort by</span>
          <select className="ta-input" value={sort} onChange={(e) => update({ sort: e.target.value })}>
            {SORT_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="ta-field">
          <span>Order</span>
          <select className="ta-input" value={order} onChange={(e) => update({ order: e.target.value })}>
            <option value="desc">Newest or highest first</option>
            <option value="asc">Oldest or lowest first</option>
          </select>
        </label>
        <label className="ta-field">
          <span>Per page</span>
          <select className="ta-input" value={pageSize} onChange={(e) => update({ page_size: e.target.value })}>
            {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </form>

      {loading && !data ? <Loading message="Loading history..." /> : null}
      {error ? <ErrorState message={error} onRetry={load} /> : null}

      {data && !error ? (
        data.items.length === 0 ? (
          <EmptyState title="No analyses match these filters">Clear the filters, or start an analysis from the File, URL or Threat Intel pages.</EmptyState>
        ) : (
          <>
            <p className="results-count" aria-live="polite">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, data.total)} of {data.total}
            </p>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Date</th><th scope="col">Type</th><th scope="col">Name or indicator</th>
                    <th scope="col">Status</th><th scope="col">Risk</th><th scope="col">Score</th><th scope="col"><span className="visually-hidden">Open</span></th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id}>
                      <td>{formatDateTime(item.created_at)}</td>
                      <td>{item.kind}</td>
                      <td className="ta-break">{item.display_name || item.indicator_value}</td>
                      <td>{item.status}{item.file_available === false && item.kind === "file" ? <span className="ta-tag">file removed</span> : null}</td>
                      <td><RiskBadge level={item.risk_level} /></td>
                      <td>{item.risk_score ?? "-"}</td>
                      <td><Link to={`/analysis/${item.id}`}>Open</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <nav className="pagination" aria-label="History pages">
              <button type="button" className="btn" disabled={page <= 1} onClick={() => update({ page: page - 1 })}>Previous</button>
              <span>Page {page} of {data.pages}</span>
              <button type="button" className="btn" disabled={page >= data.pages} onClick={() => update({ page: page + 1 })}>Next</button>
            </nav>
          </>
        )
      ) : null}
    </div>
  );
}
