import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_ROOT = "/api";

async function apiRequest(path, passphrase, options = {}) {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(passphrase ? { "X-Operator-Passphrase": passphrase } : {}),
      ...options.headers,
    },
  });
  const payload = await response.json().catch(() => ({}));
  const verificationResult = path.includes("/verify") && ["verified", "failed", "unknown"].includes(payload.status);
  if (!response.ok && !verificationResult) {
    const detail = payload.detail;
    const message = typeof detail === "string" ? detail : detail?.code;
    throw new Error(message || `Request failed (${response.status})`);
  }
  return payload;
}

function formatTime(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function humanize(value = "") {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function StatusPill({ value }) {
  const safe = ["verified", "complete", "enabled", "applied", "readback_verified"].includes(value);
  const danger = ["failed", "rejected", "apply_failed", "verification_failed"].includes(value);
  return <span className={`pill ${safe ? "pill-good" : danger ? "pill-bad" : "pill-wait"}`}>{humanize(value || "unknown")}</span>;
}

function App() {
  const [passphrase, setPassphrase] = useState(() => sessionStorage.getItem("veto-operator") || "");
  const [operator, setOperator] = useState("Operator");
  const [connected, setConnected] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [detail, setDetail] = useState(null);
  const [events, setEvents] = useState([]);
  const [coverage, setCoverage] = useState(null);
  const [verification, setVerification] = useState(null);
  const [view, setView] = useState("incidents");
  const [rolloutStage, setRolloutStage] = useState(5);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [incidentForm, setIncidentForm] = useState({
    scenario: "search_sqli",
    reporter: "Operator",
    evidence_summary: "Synthetic local security demonstration finding.",
  });

  const loadWorkspace = useCallback(async (key = passphrase) => {
    const [incidentData, coverageData] = await Promise.all([
      apiRequest("/incidents", key),
      apiRequest("/flags/coverage", key),
    ]);
    setIncidents(incidentData.incidents || []);
    setCoverage(coverageData);
    setConnected(true);
    if (selectedId) {
      const [incident, activity] = await Promise.all([
        apiRequest(`/incidents/${selectedId}`, key),
        apiRequest(`/incidents/${selectedId}/events`, key),
      ]);
      setDetail(incident);
      setEvents(activity.events || []);
      const lastVerification = [...(activity.events || [])]
        .reverse()
        .find((item) => ["post_change_verification", "verification_unavailable"].includes(item.event_type));
      setVerification(lastVerification?.payload || null);
    }
  }, [passphrase, selectedId]);

  const connect = async (event) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      await loadWorkspace(passphrase);
      sessionStorage.setItem("veto-operator", passphrase);
      setNotice("Connected to the local operator API.");
    } catch (error) {
      setConnected(false);
      setNotice(error.message === "operator_auth_failed" ? "That passphrase was not accepted." : error.message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!connected || !passphrase) return undefined;
    loadWorkspace(passphrase).catch(() => {
      sessionStorage.removeItem("veto-operator");
      setConnected(false);
    });
    const timer = window.setInterval(() => {
      loadWorkspace(passphrase).catch(() => {});
    }, 10000);
    return () => window.clearInterval(timer);
  }, [connected, loadWorkspace, passphrase]);

  const selectIncident = (id) => {
    setSelectedId(id);
    setView("incidents");
    setNotice("");
  };

  const runAction = async (path, method, body, successMessage) => {
    if (!detail) return;
    setBusy(true);
    setNotice("");
    try {
      const result = await apiRequest(path, passphrase, {
        method,
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (result.status === "hold") {
        setNotice(`Rollout held: ${humanize(result.reason)}. No flag changed.`);
      } else if (result.status === "failed" || result.status === "unknown") {
        setNotice(`Verification is ${result.status}. Do not treat this incident as contained.`);
      } else {
        setNotice(successMessage);
      }
      await loadWorkspace(passphrase);
      return result;
    } catch (error) {
      setNotice(humanize(error.message));
      await loadWorkspace(passphrase).catch(() => {});
      return null;
    } finally {
      setBusy(false);
    }
  };

  const createIncident = async (event) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      const created = await apiRequest("/incidents", passphrase, {
        method: "POST",
        body: JSON.stringify({ ...incidentForm, reporter: operator }),
      });
      setSelectedId(created.id);
      setDetail(created);
      setEvents([]);
      await loadWorkspace(passphrase);
      setNotice("Incident saved. Review the finding, then analyze it to prepare a proposal.");
    } catch (error) {
      setNotice(humanize(error.message));
    } finally {
      setBusy(false);
    }
  };

  const exportReport = async () => {
    if (!detail) return;
    try {
      const report = await apiRequest(`/incidents/${detail.id}/report`, passphrase);
      const file = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(file);
      link.download = `veto-switch-incident-${detail.id}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
      setNotice("Evidence report downloaded.");
    } catch (error) {
      setNotice(humanize(error.message));
    }
  };

  const selectedProposal = detail?.proposal;
  const preChangeCheck = [...events]
    .reverse()
    .find((item) => item.event_type === "pre_change_security_check")?.payload;
  const stateCounts = useMemo(() => {
    const flags = coverage?.routes?.flatMap((route) => Object.values(route.flag_states || {})) || [];
    return {
      known: flags.filter((state) => state !== "unknown").length,
      total: flags.length,
      gaps: coverage?.gaps?.length || 0,
    };
  }, [coverage]);

  const approve = (decision) => runAction(
    `/proposals/${selectedProposal.id}/decision`,
    "POST",
    { decision, actor: operator, proposal_hash: selectedProposal.proposal_hash, reason: decision === "reject" ? "Rejected by operator" : "Approved by operator" },
    decision === "approve" ? "Proposal approved. The flag change is still waiting for Apply." : "Proposal rejected. No flag was changed.",
  );

  const apply = () => runAction(
    `/proposals/${selectedProposal.id}/apply`,
    "POST",
    { proposal_hash: selectedProposal.proposal_hash },
    "Change receipt saved. Run verification before calling it contained.",
  );

  const verify = () => runAction(
    `/incidents/${detail.id}/verify`,
    "POST",
    {},
    "Verification passed. The safe route and unaffected status route were observed.",
  );

  const stepState = (step) => {
    const status = detail?.status;
    if (!detail) return "upcoming";
    const map = {
      finding: ["finding_received", "pending_approval", "approved", "rejected", "applied", "verification_pending", "verified", "verification_failed", "proposal_stale"],
      approval: ["approved", "applied", "verification_pending", "verified", "verification_failed"],
      change: ["applied", "verification_pending", "verified", "verification_failed"],
      verify: ["verified", "verification_failed", "verification_unavailable"],
    };
    if (step === "verify" && status === "verified") return "done";
    if (step === "change" && ["applied", "verification_pending", "verified", "verification_failed"].includes(status)) return "done";
    if (step === "approval" && ["approved", "applied", "verification_pending", "verified", "verification_failed"].includes(status)) return "done";
    if (map[step]?.includes(status)) return step === "finding" ? "done" : "active";
    return "upcoming";
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="Veto Switch home">
          <span className="brand-mark">V</span>
          <span><strong>VETO SWITCH</strong><small>SECURITY CONTROL PLANE</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <button className={`nav-item ${view === "incidents" ? "selected" : ""}`} onClick={() => setView("incidents")}><span className="nav-icon">◈</span> Incidents <span className="nav-count">{incidents.length}</span></button>
        <button className={`nav-item ${view === "coverage" ? "selected" : ""}`} onClick={() => setView("coverage")}><span className="nav-icon">⌘</span> Flag coverage</button>
        <div className="sidebar-spacer" />
        <div className="sidebar-note"><span className="status-dot" /> Local demo only <small>Synthetic data · loopback access</small></div>
        <a className="docs-link" href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer">API reference <span>↗</span></a>
      </aside>

      <main className="main-panel" id="top">
        <header className="topbar">
          <div className="crumb">Platform <span>/</span> <b>{view === "coverage" ? "Flag coverage" : "Incident command"}</b></div>
          <div className="topbar-right"><span className="demo-label"><span /> DEMO / SYNTHETIC DATA</span><span className="top-divider" />
            {connected ? <span className="connected"><i /> API connected</span> : <span className="disconnected"><i /> Connect operator</span>}
          </div>
        </header>

        <div className="content-wrap">
          <section className="page-heading">
            <div><div className="eyebrow">CONTAINMENT DESK <span>·</span> LOCAL ENVIRONMENT</div><h1>{view === "coverage" ? "Flag coverage" : "Incident command"}</h1><p>{view === "coverage" ? "See which demo routes have known feature-flag states." : "Review a finding, approve one exact change, then verify the result."}</p></div>
            <form className="operator-connect" onSubmit={connect}>
              {connected && <label className="operator-name"><span>OPERATOR</span><input value={operator} onChange={(event) => setOperator(event.target.value)} aria-label="Operator name" /></label>}
              <label className="passphrase-wrap"><span>{connected ? "SESSION" : "OPERATOR PASSPHRASE"}</span><input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Enter local passphrase" autoComplete="current-password" /></label>
              <button className="button button-small button-quiet" type="submit" disabled={busy}>{connected ? "Refresh" : "Connect"}</button>
            </form>
          </section>

          {notice && <div className="notice" role="status"><span>i</span>{notice}<button onClick={() => setNotice("")} aria-label="Dismiss message">×</button></div>}

          {!connected ? (
            <section className="connect-card panel"><div className="connect-icon">⌁</div><h2>Connect to your local demo</h2><p>Enter the operator passphrase from your private <code>.env</code> file. It is kept in this browser tab only.</p><form onSubmit={connect} className="connect-form"><input type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Operator passphrase" autoComplete="current-password" /><button className="button button-primary" disabled={busy}>{busy ? "Connecting…" : "Connect to API"}<span>→</span></button></form><small>API is expected at <code>127.0.0.1:8000</code>. Start it with Docker Compose from the repository root.</small></section>
          ) : view === "coverage" ? (
            <CoverageView coverage={coverage} counts={stateCounts} />
          ) : (
            <>
              <section className="metric-grid">
                <MetricCard label="OPEN INCIDENTS" value={incidents.filter((item) => !["verified", "rejected"].includes(item.status)).length} note="Across this local demo" accent="mint" />
                <MetricCard label="FLAG STATES KNOWN" value={`${stateCounts.known}/${stateCounts.total || 0}`} note={stateCounts.gaps ? `${stateCounts.gaps} coverage gaps` : "All referenced flags are known"} accent={stateCounts.gaps ? "amber" : "mint"} />
                <MetricCard label="CURRENT INCIDENT" value={detail ? humanize(detail.status) : "None selected"} note={detail ? humanize(detail.scenario) : "Choose or create a finding"} accent="blue" compact />
              </section>

              <section className="workspace-grid">
                <div className="left-column">
                  <div className="panel incident-panel">
                    <div className="panel-heading"><div><span className="section-kicker">QUEUE</span><h2>Incidents <span className="heading-count">{incidents.length}</span></h2></div><button className="icon-button" onClick={() => loadWorkspace().catch((error) => setNotice(humanize(error.message)))} aria-label="Refresh incidents">↻</button></div>
                    {incidents.length ? <div className="incident-list">{incidents.map((incident) => <button key={incident.id} className={`incident-row ${incident.id === selectedId ? "active" : ""}`} onClick={() => selectIncident(incident.id)}><span className={`incident-symbol ${incident.scenario === "search_sqli" ? "symbol-orange" : "symbol-purple"}`}>{incident.scenario === "search_sqli" ? "⌕" : "↗"}</span><span className="incident-info"><b>{humanize(incident.scenario)}</b><small>{incident.id.slice(0, 8)} · {formatTime(incident.created_at)}</small></span><StatusPill value={incident.status} /></button>)}</div> : <div className="empty-queue"><span>◈</span><b>No incidents yet</b><small>Create a synthetic finding to begin the approval flow.</small></div>}
                  </div>
                  <form className="panel new-incident" onSubmit={createIncident}>
                    <div className="panel-heading"><div><span className="section-kicker">NEW FINDING</span><h2>Create incident</h2></div><span className="new-indicator">LOCAL</span></div>
                    <label>Scenario<select value={incidentForm.scenario} onChange={(event) => setIncidentForm({ ...incidentForm, scenario: event.target.value })}><option value="search_sqli">Search injection</option><option value="path_traversal">File path traversal</option></select></label>
                    <label>Evidence summary<textarea value={incidentForm.evidence_summary} onChange={(event) => setIncidentForm({ ...incidentForm, evidence_summary: event.target.value })} maxLength={500} rows={3} /></label>
                    <button className="button button-primary button-wide" disabled={busy}>Create synthetic finding <span>＋</span></button>
                  </form>
                </div>

                <div className="right-column">
                  {detail ? <>
                    <div className="panel detail-panel">
                      <div className="panel-heading detail-title"><div><span className="section-kicker">SELECTED FINDING</span><h2>{humanize(detail.scenario)}</h2></div><StatusPill value={detail.status} /></div>
                      <div className="incident-meta"><span>INCIDENT ID</span><code>{detail.id}</code><button className="text-button" onClick={() => navigator.clipboard?.writeText(detail.id)}>Copy</button></div>
                      <p className="evidence-copy">{detail.evidence_summary}</p>
                      {preChangeCheck && <div className={`precheck-card precheck-${preChangeCheck.status}`}><div className="precheck-head"><span>BEFORE CHANGE</span><b>{preChangeCheck.status === "vulnerability_observed" ? "Attack reproduced" : preChangeCheck.status === "attack_not_observed" ? "Attack not observed" : "Observation unknown"}</b></div><small>{preChangeCheck.route || "Demo route"} · {preChangeCheck.variant || "no variant observed"} · {formatTime(preChangeCheck.observed_at)}</small>{preChangeCheck.checks && <div className="check-list">{Object.entries(preChangeCheck.checks).map(([name, passed]) => { const issue = name.includes("returned_synthetic") ? passed : !passed; return <div key={name}><span className={issue ? "check-fail" : "check-pass"}>{issue ? "!" : "✓"}</span>{humanize(name)}</div>; })}</div>}</div>}
                      <div className="flow-steps">
                        {[{ id: "finding", label: "Finding" }, { id: "approval", label: "Approval" }, { id: "change", label: "Flag change" }, { id: "verify", label: "Verify" }].map((step, index) => <div className={`flow-step ${stepState(step.id)}`} key={step.id}><span className="step-node">{stepState(step.id) === "done" ? "✓" : `0${index + 1}`}</span><span>{step.label}</span></div>)}
                      </div>
                      <div className="proposal-card">
                        <div className="proposal-head"><div><span className="section-kicker">CONTAINMENT PROPOSAL</span><b>{selectedProposal ? `${selectedProposal.vulnerable_flag} off → ${selectedProposal.safe_flag} on` : "No proposal prepared"}</b></div>{selectedProposal && <StatusPill value={selectedProposal.status} />}</div>
                        {selectedProposal ? <><div className="proposal-meta"><span>Target <b>{humanize(selectedProposal.target_environment || "local")}</b></span><span>Expires <b>{formatTime(selectedProposal.expires_at)}</b></span></div><div className="hash-line"><span>APPROVAL HASH</span><code>{selectedProposal.proposal_hash}</code></div></> : <p className="proposal-hint">Analysis records the exact flag state. A change requires a separate operator decision.</p>}
                        <div className="action-row">
                          {!selectedProposal && <button className="button button-primary" disabled={busy} onClick={() => runAction(`/incidents/${detail.id}/analyze`, "POST", {}, "Proposal prepared with a 15-minute expiry.")}>Analyze finding <span>→</span></button>}
                          {selectedProposal?.status === "pending_approval" && <><button className="button button-danger" disabled={busy} onClick={() => approve("reject")}>Reject</button><button className="button button-primary" disabled={busy} onClick={() => approve("approve")}>Approve exact change <span>→</span></button></>}
                          {selectedProposal?.status === "approved" && <button className="button button-primary" disabled={busy} onClick={apply}>Apply approved change <span>→</span></button>}
                          {["applied", "verification_pending", "verification_failed", "verification_unavailable"].includes(detail.status) && <button className="button button-primary" disabled={busy} onClick={verify}>Run verification <span>→</span></button>}
                          {detail.status === "verified" && <><button className="button button-quiet" disabled={busy} onClick={() => runAction(`/incidents/${detail.id}/patch`, "POST", {}, "Safe variant is available in the demo app; no deployment was made.")}>View patch option</button><label className="rollout-select"><span>STAGE</span><select value={rolloutStage} onChange={(event) => setRolloutStage(Number(event.target.value))}><option value={5}>5%</option><option value={25}>25%</option><option value={50}>50%</option><option value={100}>100%</option></select></label><button className="button button-quiet" disabled={busy} onClick={() => runAction(`/incidents/${detail.id}/rollout`, "POST", { percentage: rolloutStage }, "Rollout status updated.")}>Preview stage</button></>}
                        </div>
                      {detail.status === "verified" && <p className="rollout-note">Stage control is preview-only. It does not change Flagsmith targeting.</p>}
                      {verification && <div className={`verification-card ${verification.status === "verified" ? "verification-good" : "verification-bad"}`}><div className="verification-head"><span>{verification.status === "verified" ? "✓" : "!"}</span><div><b>Post-change verification: {humanize(verification.status)}</b><small>{formatTime(verification.observed_at)}</small></div></div>{verification.checks && <div className="check-list">{Object.entries(verification.checks).map(([name, passed]) => <div key={name}><span className={passed ? "check-pass" : "check-fail"}>{passed ? "✓" : "×"}</span>{humanize(name)}</div>)}</div>}</div>}
                      {detail.operation_receipt && <div className="receipt-card"><div className="receipt-title"><div><span className="section-kicker">CHANGE RECEIPT</span><b>{humanize(detail.operation_receipt.adapter)}</b></div><StatusPill value={detail.operation_receipt.readback_verified ? "readback_verified" : "apply_failed"} /></div><div className="receipt-states">{Object.keys(detail.operation_receipt.after || {}).map((flag) => <div key={flag}><code>{flag}</code><span>{humanize(detail.operation_receipt.before?.[flag] || "unknown")} <i>→</i> <b>{humanize(detail.operation_receipt.after[flag])}</b></span></div>)}</div><small>Actor: {detail.decision?.actor || "unknown"} · {formatTime(detail.operation_receipt.executed_at)}</small></div>}
                      </div>
                      <button className="export-button" onClick={exportReport}>⇩ Export evidence report <span>JSON</span></button>
                    </div>
                    <div className="panel timeline-panel"><div className="panel-heading"><div><span className="section-kicker">PERSISTED ACTIVITY</span><h2>Incident timeline</h2></div><span className="timeline-count">{events.length} events</span></div>{events.length ? <ol className="timeline">{[...events].reverse().map((event) => <li key={event.id}><span className="timeline-dot" /><div><b>{humanize(event.event_type)}</b><small>{humanize(event.actor)} · {formatTime(event.created_at)}</small>{event.payload?.status && <p>{humanize(event.payload.status)}</p>}</div></li>)}</ol> : <div className="empty-timeline">The event log will appear here and remain after refresh.</div>}</div>
                  </> : <div className="panel empty-detail"><div className="empty-detail-art">⌁</div><h2>Select an incident</h2><p>Choose a finding in the queue or create a synthetic one to begin.</p></div>}
                </div>
              </section>
            </>
          )}
          <footer className="page-footer"><span>VETO SWITCH <i>·</i> LOCAL DEMO BUILD</span><span>Never treat a change as contained until verification passes.</span></footer>
        </div>
      </main>
    </div>
  );
}

function MetricCard({ label, value, note, accent, compact }) {
  return <div className={`metric-card metric-${accent}`}><span>{label}</span><strong className={compact ? "metric-compact" : ""}>{value}</strong><small>{note}</small></div>;
}

function CoverageView({ coverage, counts }) {
  if (!coverage) return <div className="panel loading-card">Loading route coverage…</div>;
  return <section className="panel coverage-panel"><div className="panel-heading"><div><span className="section-kicker">ROUTE → FLAG MAP</span><h2>Coverage overview</h2></div><StatusPill value={coverage.status} /></div><p className="coverage-copy">A route is marked covered only when every referenced flag has a known state. Unknown or missing Flagsmith values remain visible as gaps.</p><div className="coverage-summary"><div><span>KNOWN STATES</span><b>{counts.known}<small> / {counts.total}</small></b></div><div><span>OPEN GAPS</span><b className={counts.gaps ? "orange-text" : ""}>{counts.gaps}</b></div><div><span>FLAG ADAPTER</span><b>{humanize(coverage.adapter)}</b></div></div><div className="coverage-table"><div className="coverage-row coverage-head"><span>ROUTE</span><span>FEATURE FLAGS</span><span>STATUS</span></div>{coverage.routes.map((route) => <div className="coverage-row" key={route.path}><span><code>{route.path}</code><small>{route.method}</small></span><span className="flag-tags">{Object.entries(route.flag_states || {}).length ? Object.entries(route.flag_states).map(([name, state]) => <span className={`flag-tag flag-${state}`} key={name}><b>{name}</b><i>{humanize(state)}</i></span>) : <span className="muted">No feature flag required</span>}</span><span><StatusPill value={route.covered ? "complete" : "incomplete"} /></span></div>)}</div>{coverage.gaps?.length > 0 && <div className="coverage-warning"><span>!</span><div><b>Coverage needs attention</b><small>{coverage.gaps.map((gap) => `${gap.route} · ${gap.flag}`).join("; ")}</small></div></div>}</section>;
}

createRoot(document.getElementById("root")).render(<App />);
