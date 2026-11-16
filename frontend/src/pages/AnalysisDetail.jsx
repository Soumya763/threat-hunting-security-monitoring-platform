import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  addAnalysisNote, deleteAnalysis, downloadReport, externalSubmission, getAnalysis, getAnalysisNotes,
  getAnalysisPivot, getIncidents, getLinkedIncidents, getProviders, linkAnalysisToIncident, rerunAnalysis,
} from "../services/api";
import RiskBadge from "../components/RiskBadge";
import ScoreGauge from "../components/ScoreGauge";
import FactorList from "../components/FactorList";
import ProviderTable from "../components/ProviderTable";
import KeyValue from "../components/KeyValue";
import StepList from "../components/StepList";
import Loading from "../components/Loading";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";
import { formatDateTime } from "../utils/formatDate";
import { errorMessage, formatBytes, isPending, RISK_LABELS } from "../utils/format";

const KIND_LABELS = { file: "File", url: "URL", indicator: "Indicator search" };
const SEVERITIES = ["low", "medium", "high", "critical"];

/** Insufficient evidence is "not scored": a 0 here must never read as a safe score. */
function isUnscored(record) {
  return record.risk_level === "insufficient_evidence";
}

function ProviderCoverage({ summary }) {
  const { applicable = 0, checked = 0, failed = 0, not_configured: notConfigured = 0 } = summary;
  return (
    <p className="ta-small" role="status">
      Checked successfully: <strong>{checked} of {applicable}</strong> applicable providers.
      {" "}Failed: {failed}. Not configured: {notConfigured}.
      {checked === 0 ? " No provider answered, so this result cannot confirm the item is safe." : null}
    </p>
  );
}

export default function AnalysisDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [notes, setNotes] = useState([]);
  const [links, setLinks] = useState([]);
  const [providerInfo, setProviderInfo] = useState([]);
  const [pivot, setPivot] = useState(null);
  const [pivotBusy, setPivotBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [actionError, setActionError] = useState(null);

  const load = useCallback(() => {
    return getAnalysis(id)
      .then((data) => { setRecord(data); setError(null); setNotFound(false); })
      .catch((err) => {
        if (err.response?.status === 404) setNotFound(true);
        else setError(errorMessage(err, "Unable to load this analysis."));
      })
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  // Poll while the background work is still running.
  useEffect(() => {
    if (!record || !isPending(record.status)) return undefined;
    const timer = setTimeout(load, 2000);
    return () => clearTimeout(timer);
  }, [record, load]);

  // Secondary data once the record exists.
  useEffect(() => {
    if (!record) return;
    getAnalysisNotes(record.id).then(setNotes).catch(() => setNotes([]));
    getLinkedIncidents(record.id).then(setLinks).catch(() => setLinks([]));
    getProviders().then(setProviderInfo).catch(() => setProviderInfo([]));
  }, [record?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading && !record) return <Loading message="Loading analysis..." />;
  if (notFound) {
    return (
      <div className="page">
        <EmptyState title="Analysis not found">
          It may have been deleted, or it belongs to another analyst.
          <div><Link to="/history" className="section-link">Back to analysis history</Link></div>
        </EmptyState>
      </div>
    );
  }
  if (error && !record) return <ErrorState message={error} onRetry={load} />;
  if (!record) return null;

  const result = record.result || {};
  const pending = isPending(record.status);
  const providerConfigured = (id) => providerInfo.find((p) => p.id === id)?.configured;

  async function run(action, success) {
    setActionError(null);
    setMessage(null);
    try {
      await action();
      setMessage(success);
    } catch (err) {
      setActionError(errorMessage(err));
    }
  }

  function onDelete() {
    if (!window.confirm("Delete this analysis and its stored file? This cannot be undone.")) return;
    run(() => deleteAnalysis(record.id).then(() => navigate("/history")), "Deleted.");
  }

  function onRerun() {
    run(async () => {
      await rerunAnalysis(record.id);
      await load();
    }, "Analysis queued again.");
  }

  function onPivot() {
    setPivotBusy(true);
    getAnalysisPivot(record.id)
      .then((data) => setPivot(data.result))
      .catch((err) => setActionError(errorMessage(err, "Local log search failed.")))
      .finally(() => setPivotBusy(false));
  }

  function onAddNote(content, reset) {
    run(() => addAnalysisNote(record.id, content).then((note) => {
      setNotes((prev) => [...prev, note]);
      reset();
    }), "Note saved.");
  }

  const reportBase = `/api/v1/analyses/${record.id}/report`;
  const filenameBase = `analysis-${record.id}`;

  return (
    <div className="page analysis-detail">
      <div className="back-link"><Link to="/history">← Analysis history</Link></div>

      <header className="ta-header">
        <div className="ta-header__main">
          <p className="ta-eyebrow">{KIND_LABELS[record.kind]} analysis #{record.id}</p>
          <h1 className="page-title ta-break">{record.display_name || record.indicator_value}</h1>
          <div className="ta-header__meta">
            <RiskBadge level={record.risk_level} />
            <span className={`analysis-status analysis-status--${record.status}`}>{record.status}</span>
            <span className="ta-muted">Submitted {formatDateTime(record.created_at)}</span>
            {record.completed_at ? <span className="ta-muted">Completed {formatDateTime(record.completed_at)}</span> : null}
          </div>
          <p className="ta-muted">{result.classification_label || (pending ? "Analysis in progress..." : RISK_LABELS[record.risk_level] || "No result yet")}</p>
        </div>
        <ScoreGauge score={isUnscored(record) ? null : record.risk_score} level={record.risk_level} />
      </header>

      <div className="ta-actions">
        <button type="button" className="btn" onClick={() => downloadReport(`${reportBase}.pdf`, `${filenameBase}.pdf`)
          .catch((err) => setActionError(errorMessage(err, "Could not download the PDF report.")))}>
          Download PDF report
        </button>
        <button type="button" className="btn" onClick={() => downloadReport(`${reportBase}.json`, `${filenameBase}.json`)
          .catch((err) => setActionError(errorMessage(err, "Could not download the JSON report.")))}>
          Download JSON
        </button>
        <button type="button" className="btn" onClick={onRerun} disabled={pending}>Re-run analysis</button>
        <button type="button" className="btn btn--danger" onClick={onDelete}>Delete</button>
      </div>
      {message ? <p className="ta-notice" role="status">{message}</p> : null}
      {actionError ? <p className="ta-error" role="alert">{actionError}</p> : null}
      {error ? <p className="ta-error" role="alert">{error}</p> : null}

      {pending ? (
        <section className="ta-card ta-progress">
          <div className="spinner" aria-hidden="true" />
          <div>
            <strong>{record.status === "queued" ? "Queued" : "Analysing"}</strong>
            <p className="ta-muted">This page refreshes automatically until the result is ready.</p>
          </div>
        </section>
      ) : null}

      {record.status === "failed" ? (
        <section className="ta-card"><p className="ta-error">{record.error || "The analysis failed."}</p></section>
      ) : null}

      {record.status !== "failed" && record.error ? <p className="ta-muted">{record.error}</p> : null}

      {result.recommendations ? (
        <section className="ta-card">
          <h2>Recommended actions</h2>
          <ul className="ta-list">{result.recommendations.map((r) => <li key={r}>{r}</li>)}</ul>
        </section>
      ) : null}

      {result.caveats?.length ? (
        <section className="ta-card ta-card--caveat">
          <h2>Caveats and uncertainty</h2>
          <ul className="ta-list">{result.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
        </section>
      ) : null}

      {result.factors ? (
        <section className="ta-card">
          <h2>Why this score</h2>
          <div className="ta-score-line">
            <strong>{isUnscored(record) ? "Not scored" : `Score ${record.risk_score ?? "-"} / 100`}</strong>
            <span className="ta-muted">Factors add up to the score; the total is capped at 100.</span>
          </div>
          <FactorList factors={result.factors} />
        </section>
      ) : null}

      {result.providers ? (
        <section className="ta-card">
          <h2>Threat-intelligence providers</h2>
          <p className="ta-muted">Providers that are not configured are listed, not treated as "no detections".</p>
          {result.provider_summary ? <ProviderCoverage summary={result.provider_summary} /> : null}
          <ProviderTable providers={result.providers} />
        </section>
      ) : null}

      {record.kind === "file" && result.file ? <FileFindings result={result} /> : null}
      {record.kind === "url" && result.normalized_url ? <UrlFindings result={result} /> : null}
      {record.kind === "indicator" && result.local ? <IndicatorLocal result={result} /> : null}

      {result.steps ? (
        <section className="ta-card">
          <h2>Analysis steps</h2>
          <StepList steps={result.steps} />
        </section>
      ) : null}

      <section className="ta-card">
        <div className="ta-section-head">
          <h2>Local context (internal logs)</h2>
          <button type="button" className="btn" onClick={onPivot} disabled={pivotBusy || pending}>
            {pivotBusy ? "Searching..." : "Search internal logs"}
          </button>
        </div>
        <p className="ta-muted">
          Searches the platform's own indexed events for this {record.kind === "file" ? "file hash" : "indicator"}. Read-only.
        </p>
        {pivot ? <PivotResult pivot={pivot} /> : null}
      </section>

      <section className="ta-card">
        <h2>Send to an external service</h2>
        <ExternalSubmitPanel
          record={record}
          configured={record.kind === "file" ? providerConfigured("virustotal") : record.kind === "url" ? providerConfigured("urlscan") : false}
          onSubmitted={() => load()}
          setActionError={setActionError}
          setMessage={setMessage}
        />
      </section>

      <IncidentPanel
        record={record}
        links={links}
        setLinks={setLinks}
        setActionError={setActionError}
        setMessage={setMessage}
      />

      <section className="ta-card">
        <h2>Analyst notes</h2>
        <NotesPanel notes={notes} onAdd={onAddNote} />
      </section>
    </div>
  );
}

function FileFindings({ result }) {
  const file = result.file || {};
  const ident = result.identification || {};
  const staticResult = result.static || {};
  const strings = result.strings || {};
  const yara = result.yara || {};
  const det = result.detections || {};
  return (
    <>
      <section className="ta-card">
        <h2>File details</h2>
        <KeyValue rows={[
          ["File name", file.name],
          ["Size", formatBytes(file.size_bytes)],
          ["Detected type", ident.detected_family || "Not recognised"],
          ["Declared extension", ident.declared_extension ? `.${ident.declared_extension}` : "none"],
          ["Extension matches content", ident.extension_matches === null || ident.extension_matches === undefined ? "not checked" : ident.extension_matches ? "yes" : "no"],
          ["MD5", file.md5, true],
          ["SHA-1", file.sha1, true],
          ["SHA-256", file.sha256, true],
          ["Engines flagging", det.engines_total ? `${det.engines_flagging} of ${det.engines_total}` : "not available"],
        ]} />
        {ident.warnings?.length ? <ul className="ta-list ta-warn">{ident.warnings.map((w) => <li key={w}>{w}</li>)}</ul> : null}
      </section>

      <section className="ta-card">
        <h2>Static analysis</h2>
        {staticResult.kind === "pe" ? <PeFindings pe={staticResult} /> : null}
        {staticResult.kind === "pdf" ? <PdfFindings pdf={staticResult} /> : null}
        {staticResult.kind === "office" || staticResult.office ? <OfficeFindings office={staticResult.office || staticResult} /> : null}
        {staticResult.kind === "zip" ? <ZipFindings zip={staticResult} /> : null}
        {staticResult.kind === "image" ? <ImageFindings image={staticResult} /> : null}
        {!staticResult.kind ? <p className="ta-muted">No format-specific analyser applies to this file type.</p> : null}
        {staticResult.parse_error ? <p className="ta-warn">Parser note: {staticResult.parse_error}</p> : null}
        {staticResult.limitations?.length ? (
          <ul className="ta-list ta-muted">{staticResult.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        ) : null}
      </section>

      <section className="ta-card">
        <h2>YARA indicator rules</h2>
        {yara.status === "scanned" ? (
          yara.matches?.length ? (
            <table className="data-table ta-table">
              <thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Meaning</th></tr></thead>
              <tbody>{yara.matches.map((m) => (
                <tr key={m.rule}><td className="ta-mono">{m.rule}</td><td>{m.severity}</td><td>{m.description}</td></tr>
              ))}</tbody>
            </table>
          ) : <p className="ta-muted">Scanned. No indicator rules matched.</p>
        ) : (
          <p className="ta-warn">YARA was not applied: {yara.detail || "not available"}.</p>
        )}
      </section>

      <section className="ta-card">
        <h2>Suspicious strings</h2>
        {strings.categories?.length ? (
          <ul className="ta-list">{strings.categories.map((c) => (
            <li key={c.category}><strong>{c.description}</strong>{c.matched?.length ? `: ${c.matched.join(", ")}` : ""}</li>
          ))}</ul>
        ) : <p className="ta-muted">No suspicious string categories were found in the scanned bytes.</p>}
        {strings.urls?.length ? <div><h3>URLs found in the file</h3><ul className="ta-list ta-mono">{strings.urls.map((u) => <li key={u}>{u}</li>)}</ul></div> : null}
        {strings.truncated ? <p className="ta-muted">Only the first part of the file was scanned.</p> : null}
      </section>
    </>
  );
}

function PeFindings({ pe }) {
  return (
    <>
      <KeyValue rows={[
        ["Machine", pe.machine], ["Type", pe.is_dll ? "DLL" : "Executable"], ["Subsystem", pe.subsystem],
        ["Compile time", pe.compile_time || "not recorded"],
        ["Compile time in the future", pe.compile_time_in_future ? "yes" : "no"],
        ["Import hash (imphash)", pe.imphash, true],
        ["Imported functions", pe.import_count], ["Embedded signature present", pe.has_embedded_signature ? "yes (not validated)" : "no"],
        ["Bytes after the image (overlay)", pe.overlay_bytes],
      ]} />
      {pe.suspicious_imports?.length ? (
        <table className="data-table ta-table"><thead><tr><th scope="col">Function</th><th scope="col">DLL</th><th scope="col">Why it matters</th></tr></thead>
          <tbody>{pe.suspicious_imports.map((i) => <tr key={i.function}><td className="ta-mono">{i.function}</td><td>{i.dll}</td><td>{i.meaning}</td></tr>)}</tbody></table>
      ) : <p className="ta-muted">No high-signal injection or download imports were found.</p>}
      {pe.packing_hints?.length ? <ul className="ta-list ta-warn">{pe.packing_hints.map((h) => <li key={h}>{h}</li>)}</ul> : null}
      {pe.sections?.length ? (
        <table className="data-table ta-table"><thead><tr><th scope="col">Section</th><th scope="col">Raw size</th><th scope="col">Entropy</th><th scope="col">Executable</th></tr></thead>
          <tbody>{pe.sections.map((s) => <tr key={s.name}><td className="ta-mono">{s.name || "(unnamed)"}</td><td>{formatBytes(s.raw_size)}</td><td>{s.entropy}</td><td>{s.executable ? "yes" : "no"}</td></tr>)}</tbody></table>
      ) : null}
    </>
  );
}

function PdfFindings({ pdf }) {
  return (
    <>
      {pdf.indicators?.length ? (
        <ul className="ta-list">{pdf.indicators.map((i) => <li key={i.code}><strong>{i.description}</strong> (found {i.count}×)</li>)}</ul>
      ) : <p className="ta-muted">No JavaScript, automatic actions, launch actions or embedded files were found.</p>}
      {pdf.urls?.length ? <div><h3>Links found in the document</h3><ul className="ta-list ta-mono">{pdf.urls.map((u) => <li key={u}>{u}</li>)}</ul></div> : null}
    </>
  );
}

function OfficeFindings({ office }) {
  return (
    <>
      <KeyValue rows={[["Contains VBA macros", office.has_macros ? "yes" : "no"], ["Macro modules", office.macro_module_count]]} />
      {office.auto_exec_keywords?.length ? <p className="ta-warn">Runs automatically: {office.auto_exec_keywords.join(", ")}</p> : null}
      {office.suspicious_keywords?.length ? <p>Suspicious functions: <span className="ta-mono">{office.suspicious_keywords.join(", ")}</span></p> : null}
      {office.iocs?.length ? <div><h3>Indicators in macros</h3><ul className="ta-list ta-mono">{office.iocs.map((i) => <li key={i}>{i}</li>)}</ul></div> : null}
    </>
  );
}

function ZipFindings({ zip }) {
  return (
    <>
      <KeyValue rows={[
        ["Entries", zip.entry_count], ["Office document (OOXML)", zip.is_ooxml ? "yes" : "no"],
        ["Macro project present", zip.has_vba_macro ? "yes" : "no"],
        ["Largest compression ratio", zip.max_compression_ratio ?? "not available"],
        ["Suspicious size or ratio", zip.is_suspicious_bomb ? "yes" : "no"],
        ["Inspection limit reached", zip.limit_exceeded || "no"],
      ]} />
      {zip.executables?.length ? <p className="ta-warn">Executable or script entries: <span className="ta-mono">{zip.executables.join(", ")}</span></p> : null}
      {zip.path_traversal_entries?.length ? <p className="ta-error">Unsafe entry names (path traversal): <span className="ta-mono">{zip.path_traversal_entries.join(", ")}</span></p> : null}
      {zip.nested_archives?.length ? <p>Nested archives (not extracted): <span className="ta-mono">{zip.nested_archives.join(", ")}</span></p> : null}
    </>
  );
}

function ImageFindings({ image }) {
  return (
    <KeyValue rows={[
      ["Format", image.format], ["Dimensions", image.width ? `${image.width} × ${image.height}` : "not read"],
      ["Bytes after the image end", image.trailing_bytes],
      ["Embedded file signatures", image.embedded_signatures?.length ? image.embedded_signatures.join("; ") : "none"],
    ]} />
  );
}

function UrlFindings({ result }) {
  const dns = result.dns || {};
  const page = result.page || {};
  const rdap = result.rdap || {};
  const tls = result.tls;
  return (
    <>
      <section className="ta-card">
        <h2>URL and network details</h2>
        <KeyValue rows={[
          ["Submitted URL", result.submitted_url, true], ["Normalised URL", result.normalized_url, true],
          ["Final URL", result.final_url || "not retrieved", true], ["Host", result.host],
          ["Registrable domain", result.registrable_domain], ["Resolved public IPs", (result.resolved_ips || []).join(", ") || "none"],
          ["IPv4 (A) records", (dns.A || []).join(", ") || "none"], ["IPv6 (AAAA) records", (dns.AAAA || []).join(", ") || "none"],
          ["Non-public addresses (not used)", (dns.non_public_addresses || []).join(", ") || "none"],
          ["HTTP status", result.http_status], ["Content type", result.content_type], ["Server", result.server],
        ]} />
        {dns.error ? <p className="ta-warn">{dns.error}</p> : null}
      </section>

      <section className="ta-card">
        <h2>Redirect chain</h2>
        {result.redirect_chain?.length ? (
          <ol className="ta-chain">
            {result.redirect_chain.map((hop, i) => (
              <li key={`${hop.url}-${i}`}>
                <span className="ta-mono">{hop.url}</span>
                <span className="ta-muted">
                  {hop.status ? ` · HTTP ${hop.status}` : ""}
                  {hop.location ? ` → ${hop.location}` : ""}
                  {hop.blocked ? ` · blocked: ${hop.blocked}` : ""}
                  {hop.error ? ` · ${hop.error}` : ""}
                </span>
              </li>
            ))}
          </ol>
        ) : <p className="ta-muted">No redirects were followed.</p>}
      </section>

      <section className="ta-card">
        <h2>TLS certificate</h2>
        {tls ? (
          <KeyValue rows={[
            ["Subject", tls.subject], ["Issuer", tls.issuer], ["Valid from", tls.not_before], ["Expires", tls.not_after],
            ["Days remaining", tls.days_remaining ?? "unknown"], ["Names covered", (tls.san || []).join(", ")],
          ]} />
        ) : <p className="ta-muted">No verified certificate was retrieved for this URL.</p>}
        {result.tls_problem ? <p className="ta-error">{result.tls_problem}</p> : null}
      </section>

      <section className="ta-card">
        <h2>Page and phishing indicators</h2>
        {result.phishing_indicators?.length ? (
          <ul className="ta-list ta-warn">{result.phishing_indicators.map((p) => <li key={p}>{p}</li>)}</ul>
        ) : <p className="ta-muted">No phishing-related indicators were found in the page.</p>}
        {page.title ? <p>Page title: <strong>{page.title}</strong></p> : null}
        {page.form_actions?.length ? <p className="ta-mono">Form targets: {page.form_actions.join(", ")}</p> : null}
        {result.lookalike_of ? <p className="ta-warn">Possible imitation of: {result.lookalike_of}</p> : null}
      </section>

      <section className="ta-card">
        <h2>Domain registration (RDAP)</h2>
        {rdap.status === "ok" ? (
          <KeyValue rows={[
            ["Registered", formatDateTime(rdap.registered_at)], ["Age (days)", rdap.age_days],
            ["Expires", formatDateTime(rdap.expires_at)], ["Registrar", rdap.registrar],
            ["Name servers", (rdap.nameservers || []).join(", ")],
          ]} />
        ) : <p className="ta-muted">{rdap.message || "Registration data was not retrieved."}</p>}
      </section>
    </>
  );
}

function IndicatorLocal({ result }) {
  const local = result.local || {};
  return (
    <section className="ta-card">
      <h2>Your earlier analyses and related alerts</h2>
      {local.history?.length ? (
        <table className="data-table ta-table"><thead><tr><th scope="col">Analysis</th><th scope="col">Type</th><th scope="col">Risk</th><th scope="col">Date</th></tr></thead>
          <tbody>{local.history.map((h) => (
            <tr key={h.id}><td><Link to={`/analysis/${h.id}`}>#{h.id}</Link></td><td>{h.kind}</td><td><RiskBadge level={h.risk_level} /></td><td>{formatDateTime(h.created_at)}</td></tr>
          ))}</tbody></table>
      ) : <p className="ta-muted">You have not analysed this indicator before.</p>}
      {local.related_alerts?.length ? (
        <table className="data-table ta-table"><thead><tr><th scope="col">Alert</th><th scope="col">Event</th><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Incident</th></tr></thead>
          <tbody>{local.related_alerts.map((a) => (
            <tr key={a.id}>
              <td><Link to={`/alerts/${a.id}`}>#{a.id}</Link></td><td>{a.event_type}</td><td>{a.severity}</td><td>{a.status}</td>
              <td>{a.incident_id ? <Link to={`/incidents/${a.incident_id}`}>#{a.incident_id}</Link> : "-"}</td>
            </tr>
          ))}</tbody></table>
      ) : <p className="ta-muted">No alerts reference this indicator.</p>}
    </section>
  );
}

function PivotResult({ pivot }) {
  if (pivot.status !== "ok") {
    return <p className="ta-warn">{pivot.message}</p>;
  }
  return (
    <div>
      <p><strong>{pivot.total}</strong> matching event(s) in the last {pivot.lookback_days} day(s).
        {pivot.message ? <span className="ta-muted"> {pivot.message}</span> : null}</p>
      {pivot.event_types?.length ? (
        <p className="ta-muted">Event types: {pivot.event_types.map((e) => `${e.event_type} (${e.count})`).join(", ")}</p>
      ) : null}
      {pivot.samples?.length ? (
        <table className="data-table ta-table"><thead><tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Host</th></tr></thead>
          <tbody>{pivot.samples.map((s, i) => (
            <tr key={`${s.timestamp}-${i}`}><td>{formatDateTime(s.timestamp)}</td><td>{s.event_type || "-"}</td><td>{s.source_ip || "-"}</td><td>{s.destination_ip || "-"}</td><td>{s.host || "-"}</td></tr>
          ))}</tbody></table>
      ) : null}
    </div>
  );
}

function ExternalSubmitPanel({ record, configured, onSubmitted, setActionError, setMessage }) {
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  if (record.kind === "indicator") {
    return <p className="ta-muted">Indicator searches already query the configured providers; nothing is uploaded here.</p>;
  }
  const isFile = record.kind === "file";
  const provider = isFile ? "virustotal" : "urlscan";
  const target = isFile ? "the file" : "this URL";
  const providerName = isFile ? "VirusTotal" : "urlscan.io";

  if (!configured) {
    return <p className="ta-muted">{providerName} is not configured on this server, so nothing can be sent. Settings lists the required environment variable.</p>;
  }
  return (
    <div className="ta-consent">
      <p className="ta-warn">
        Sending {target} to {providerName} means it leaves this platform. {isFile
          ? "The file may be shared with the wider security community and cannot be recalled."
          : "Depending on visibility, the scan may be visible to others. The default for this server is unlisted."}
        {" "}Only do this if the content is not private or confidential.
      </p>
      <label className="ta-checkbox">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
        I understand and consent to sending {target} to {providerName}.
      </label>
      <button type="button" className="btn" disabled={!consent || busy}
        onClick={() => {
          setBusy(true);
          setActionError(null);
          externalSubmission(record.id, provider)
            .then((data) => { setMessage(`${providerName}: ${data.outcome.message || data.outcome.status}`); onSubmitted(); })
            .catch((err) => setActionError(errorMessage(err, `Could not submit to ${providerName}.`)))
            .finally(() => setBusy(false));
        }}>
        {busy ? "Sending..." : `Send to ${providerName}`}
      </button>
    </div>
  );
}

function IncidentPanel({ record, links, setLinks, setActionError, setMessage }) {
  const [incidents, setIncidents] = useState([]);
  const [incidentId, setIncidentId] = useState("");
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getIncidents().then(setIncidents).catch(() => setIncidents([]));
  }, []);

  function attach(body, success) {
    setBusy(true);
    setActionError(null);
    linkAnalysisToIncident(record.id, body)
      .then((data) => {
        setMessage(success(data));
        return getLinkedIncidents(record.id).then(setLinks);
      })
      .catch((err) => setActionError(errorMessage(err, "Could not link the incident.")))
      .finally(() => setBusy(false));
  }

  return (
    <section className="ta-card">
      <h2>Incidents</h2>
      {links.length ? (
        <ul className="ta-list">{links.map((l) => (
          <li key={l.id}><Link to={`/incidents/${l.id}`}>Incident #{l.id}: {l.title}</Link> <span className="ta-muted">({l.status})</span></li>
        ))}</ul>
      ) : <p className="ta-muted">Not linked to any incident yet.</p>}
      <div className="ta-form-grid">
        <div>
          <label htmlFor="link-incident" className="ta-label">Attach to an existing incident</label>
          <div className="ta-inline">
            <select id="link-incident" className="ta-input" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
              <option value="">Choose an incident</option>
              {incidents.map((i) => <option key={i.id} value={i.id}>#{i.id} {i.title}</option>)}
            </select>
            <button type="button" className="btn" disabled={!incidentId || busy}
              onClick={() => attach({ incident_id: Number(incidentId) }, () => "Linked to the incident.")}>
              Attach
            </button>
          </div>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); attach({ create_incident: true, title, severity }, () => "New incident created and linked."); setTitle(""); }}>
          <label htmlFor="new-incident" className="ta-label">Or open a new incident</label>
          <div className="ta-inline">
            <input id="new-incident" className="ta-input" value={title} minLength={3} maxLength={255} required
              placeholder="Incident title" onChange={(e) => setTitle(e.target.value)} />
            <select aria-label="Severity" className="ta-input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button type="submit" className="btn" disabled={busy || title.trim().length < 3}>Create</button>
          </div>
        </form>
      </div>
    </section>
  );
}

function NotesPanel({ notes, onAdd }) {
  const [text, setText] = useState("");
  return (
    <div>
      {notes.length ? (
        <ul className="ta-notes">{notes.map((n) => (
          <li key={n.id}><div className="ta-muted">{n.author} · {formatDateTime(n.created_at)}</div><p>{n.content}</p></li>
        ))}</ul>
      ) : <p className="ta-muted">No notes yet. Record what you found and what you decided.</p>}
      <form onSubmit={(e) => { e.preventDefault(); if (text.trim()) onAdd(text.trim(), () => setText("")); }}>
        <label htmlFor="note-text" className="ta-label">Add a note</label>
        <textarea id="note-text" className="ta-input ta-textarea" rows={3} maxLength={4000} value={text}
          onChange={(e) => setText(e.target.value)} />
        <button type="submit" className="btn" disabled={!text.trim()}>Save note</button>
      </form>
    </div>
  );
}
