import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  const safe = ["verified", "complete", "enabled", "applied", "passed", "readback_verified"].includes(value);
  const danger = ["failed", "rejected", "apply_failed", "verification_failed", "violated"].includes(value);
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
  const [telemetry, setTelemetry] = useState(null);
  const [resetAllowed, setResetAllowed] = useState(false);
  const [verification, setVerification] = useState(null);
  const [patchCandidate, setPatchCandidate] = useState(null);
  const [patchTest, setPatchTest] = useState(null);
  const [trafficCount, setTrafficCount] = useState(20);
  const eventCursor = useRef({});
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
    const [incidentData, coverageData, healthData, telemetryData] = await Promise.all([
      apiRequest("/incidents", key),
      apiRequest("/flags/coverage", key),
      apiRequest("/health", key),
      apiRequest("/telemetry", key),
    ]);
    setIncidents(incidentData.incidents || []);
    setCoverage(coverageData);
    setResetAllowed(Boolean(healthData.reset_allowed));
    setTelemetry(telemetryData);
    setConnected(true);
    if (selectedId) {
      const [incident, activity] = await Promise.all([
        apiRequest(`/incidents/${selectedId}`, key),
        apiRequest(`/incidents/${selectedId}/events`, key),
      ]);
      setDetail(incident);
      setEvents(activity.events || []);
      eventCursor.current[selectedId] = Math.max(0, ...(activity.events || []).map((item) => item.id || 0));
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

  useEffect(() => {
    if (!connected || !passphrase || !selectedId) return undefined;
    const controller = new AbortController();
    const readStream = async () => {
      let cursor = eventCursor.current[selectedId] || 0;
      const response = await fetch(`${API_ROOT}/incidents/${selectedId}/events/stream?after=${cursor}`, {
        headers: { "X-Operator-Passphrase": passphrase, Accept: "text/event-stream" },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) return;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!controller.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() || "";
        for (const block of blocks) {
          const dataLine = block.split("\n").find((line) => line.startsWith("data: "));
          if (!dataLine) continue;
          try {
            const item = JSON.parse(dataLine.slice(6));
            cursor = Math.max(cursor, item.id || 0);
            eventCursor.current[selectedId] = cursor;
            setEvents((current) => current.some((existing) => existing.id === item.id) ? current : [...current, item]);
          } catch {
            // Ignore malformed events; the persisted polling endpoint is the fallback.
          }
        }
      }
    };
    readStream().catch(() => {});
    return () => controller.abort();
  }, [connected, passphrase, selectedId]);

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
      } else if (result.status === "failed" || result.status === "unknown" || result.readback_verified === false || result.app_evaluation_verified === false) {
        setNotice(`The operation is not verified (${humanize(result.status || "readback failed")}). Do not treat this incident as contained.`);
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

  const exportReportMarkdown = async () => {
    if (!detail) return;
    try {
      const report = await apiRequest(`/incidents/${detail.id}/report`, passphrase);
      const rows = (report.events || []).map((event) => `| ${formatTime(event.created_at)} | ${humanize(event.event_type)} | ${humanize(event.actor)} |`).join("\n");
      const releases = (report.releases || []).map((item) => `- **${humanize(item.action)} ${item.percentage}%** — ${humanize(item.status)}; ${Object.values(item.desired_overrides || {}).filter(Boolean).length} of 20 identities targeted.`).join("\n");
      const markdown = [
        `# Veto-Switch evidence report: ${report.incident.id}`,
        "",
        `- Data label: ${report.data_label}`,
        `- Scenario: ${humanize(report.incident.scenario)}`,
        `- Status: ${humanize(report.incident.status)}`,
        `- Severity: ${humanize(report.incident.finding?.severity || "unknown")}`,
        `- Reporter: ${report.incident.reporter}`,
        "",
        "## Finding summary",
        "",
        report.incident.evidence_summary,
        "",
        "## Containment",
        "",
        report.operation_receipt ? `- Adapter: ${humanize(report.operation_receipt.adapter)}\n- Readback verified: ${report.operation_receipt.readback_verified}\n- Flag states after: ${JSON.stringify(report.operation_receipt.after)}` : "No flag operation receipt is recorded.",
        "",
        "## Staged releases and rollback",
        "",
        releases || "No staged release proposal is recorded.",
        "",
        "## Patch checks",
        "",
        ...(report.patch_tests || []).map((item) => `- ${humanize(item.result.status)} at ${formatTime(item.created_at)}: ${JSON.stringify(item.result.checks)}`),
        "",
        "## Persisted event timeline",
        "",
        "| Time | Event | Actor |",
        "| --- | --- | --- |",
        rows || "| — | No events | — |",
        "",
        "All identities and observations in this report are synthetic demo data.",
      ].join("\n");
      const file = new Blob([markdown], { type: "text/markdown" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(file);
      link.download = `veto-switch-incident-${detail.id}.md`;
      link.click();
      URL.revokeObjectURL(link.href);
      setNotice("Markdown evidence report downloaded.");
    } catch (error) {
      setNotice(humanize(error.message));
    }
  };

  const selectedProposal = detail?.proposal;
  const latestPatchTest = detail?.patch_tests?.at(-1)?.result || (patchTest?.incident_id === detail?.id ? patchTest : null);
  const latestRecoverableReleaseId = detail?.releases?.filter((item) => ["applied", "apply_failed"].includes(item.status)).at(-1)?.id;
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

  const viewPatch = async () => {
    const result = await runAction(
      `/incidents/${detail.id}/patch`,
      "POST",
      {},
      "Patch option loaded below. It has not been deployed.",
    );
    if (result?.status === "candidate_available") setPatchCandidate(result);
  };

  const previewStage = async () => {
    const result = await runAction(
      `/incidents/${detail.id}/rollout`,
      "POST",
      { percentage: rolloutStage },
      "Stage proposal prepared. No identity flags change until it is approved and applied.",
    );
    if (result?.status === "pending_approval") setNotice("Review the exact identity list and hash below, then approve or reject this stage.");
  };

  const runPatchTest = async () => {
    if (!detail) return;
    const result = await runAction(
      `/incidents/${detail.id}/patch/test`,
      "POST",
      {},
      "Fixed synthetic patch checks completed.",
    );
    if (result) setPatchTest({ ...result, incident_id: detail.id });
  };

  const decideRelease = (release, decision) => runAction(
    `/release-proposals/${release.id}/decision`,
    "POST",
    {
      decision,
      actor: operator,
      proposal_hash: release.proposal_hash,
      reason: decision === "approve" ? "Approved by operator" : "Rejected by operator",
    },
    decision === "approve" ? "Stage approved. It still needs Apply." : "Stage rejected. No identity flag changed.",
  );

  const applyRelease = (release) => runAction(
    `/release-proposals/${release.id}/apply`,
    "POST",
    { proposal_hash: release.proposal_hash },
    "Stage applied and identity evaluations were read back.",
  );

  const proposeRollback = async (release) => {
    const result = await runAction(
      `/incidents/${detail.id}/rollouts/${release.id}/rollback`,
      "POST",
      {},
      "Rollback proposal prepared. Review and approve it as a separate change.",
    );
    if (result?.status === "pending_approval") setNotice("Review the rollback hash and approve it as a new change.");
  };

  const generateTraffic = async () => {
    setBusy(true);
    try {
      const result = await apiRequest("/telemetry/generate", passphrase, {
        method: "POST",
        body: JSON.stringify({ requests: trafficCount, route: "/search" }),
      });
      setNotice(`Generated ${result.completed} synthetic requests; refreshing telemetry.`);
      await loadWorkspace(passphrase);
    } catch (error) {
      setNotice(humanize(error.message));
    } finally {
      setBusy(false);
    }
  };

  const resetDemo = async () => {
    if (!window.confirm("Reset local demo incidents, approvals, rollouts and telemetry? Flag overrides return to the safe off state.")) return;
    setBusy(true);
    try {
      await apiRequest("/demo/reset", passphrase, { method: "POST", body: JSON.stringify({}) });
      setSelectedId("");
      setDetail(null);
      setEvents([]);
      setVerification(null);
      setPatchCandidate(null);
      setPatchTest(null);
      setNotice("Local demo reset. Synthetic users and documents were retained; local flag overrides were cleared to safe defaults.");
      const [incidentData, coverageData, telemetryData] = await Promise.all([
        apiRequest("/incidents", passphrase),
        apiRequest("/flags/coverage", passphrase),
        apiRequest("/telemetry", passphrase),
      ]);
      setIncidents(incidentData.incidents || []);
      setCoverage(coverageData);
      setTelemetry(telemetryData);
    } catch (error) {
      setNotice(humanize(error.message));
    } finally {
      setBusy(false);
    }
  };

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
        <button className={`nav-item ${view === "telemetry" ? "selected" : ""}`} onClick={() => setView("telemetry")}><span className="nav-icon">⌁</span> Demo telemetry</button>
        <div className="sidebar-spacer" />
        <div className="sidebar-note"><span className="status-dot" /> Local demo only <small>Synthetic data · loopback access</small></div>
        <a className="docs-link" href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer">API reference <span>↗</span></a>
        {connected && resetAllowed && <button className="reset-demo-button" onClick={resetDemo} disabled={busy}>Reset local demo</button>}
      </aside>

      <main className="main-panel" id="top">
        <header className="topbar">
          <div className="crumb">Platform <span>/</span> <b>{view === "coverage" ? "Flag coverage" : view === "telemetry" ? "Demo telemetry" : "Incident command"}</b></div>
          <div className="topbar-right"><span className="demo-label"><span /> DEMO / SYNTHETIC DATA</span><span className="top-divider" />
            {connected ? <span className="connected"><i /> API connected</span> : <span className="disconnected"><i /> Connect operator</span>}
          </div>
        </header>

        <div className="content-wrap">
          <section className="page-heading">
            <div><div className="eyebrow">CONTAINMENT DESK <span>·</span> LOCAL ENVIRONMENT</div><h1>{view === "coverage" ? "Flag coverage" : view === "telemetry" ? "Demo telemetry" : "Incident command"}</h1><p>{view === "coverage" ? "See which demo routes have known feature-flag states." : view === "telemetry" ? "Inspect synthetic requests and the feature variant each seeded user received." : "Review a finding, approve one exact change, then verify the result."}</p></div>
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
          ) : view === "telemetry" ? (
            <TelemetryView telemetry={telemetry} busy={busy} count={trafficCount} setCount={setTrafficCount} onGenerate={generateTraffic} />
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
                      {detail.finding && <div className="finding-facts"><span>Category <b>{humanize(detail.finding.category || detail.scenario)}</b></span><span>Severity <b>{humanize(detail.finding.severity || "unknown")}</b></span><span>Source <b>{humanize(detail.finding.reporter || detail.reporter)}</b></span>{detail.finding.evidence_ids?.length > 0 && <span>Evidence IDs <b>{detail.finding.evidence_ids.join(", ")}</b></span>}</div>}
                      <div className="advisory-panel"><div><span className="section-kicker">ADVISORY ENRICHMENT</span><StatusPill value="not_connected" /></div><p>No external CVE or threat-intelligence source is connected. This view uses only the finding details supplied to the local demo.</p></div>
                      {!(["search_sqli", "path_traversal"].includes(detail.scenario)) && <div className="advisory-note"><b>No safe action is mapped for this finding type yet.</b><small>The finding is saved for review. Veto-Switch will not invent a flag change or advisory result.</small></div>}
                      {preChangeCheck && <div className={`precheck-card precheck-${preChangeCheck.status}`}><div className="precheck-head"><span>BEFORE CHANGE</span><b>{preChangeCheck.status === "vulnerability_observed" ? "Attack reproduced" : preChangeCheck.status === "attack_not_observed" ? "Attack not observed" : "Observation unknown"}</b></div><small>{preChangeCheck.route || "Demo route"} · {preChangeCheck.variant || "no variant observed"} · {formatTime(preChangeCheck.observed_at)}</small>{preChangeCheck.checks && <div className="check-list">{Object.entries(preChangeCheck.checks).map(([name, passed]) => { const issue = name.includes("returned_synthetic") ? passed : !passed; return <div key={name}><span className={issue ? "check-fail" : "check-pass"}>{issue ? "!" : "✓"}</span>{humanize(name)}</div>; })}</div>}</div>}
                      <ImpactComparison incident={detail} routes={coverage?.routes || []} preChangeCheck={preChangeCheck} />
                      <div className="flow-steps">
                        {[{ id: "finding", label: "Finding" }, { id: "approval", label: "Approval" }, { id: "change", label: "Flag change" }, { id: "verify", label: "Verify" }].map((step, index) => <div className={`flow-step ${stepState(step.id)}`} key={step.id}><span className="step-node">{stepState(step.id) === "done" ? "✓" : `0${index + 1}`}</span><span>{step.label}</span></div>)}
                      </div>
                      <div className="proposal-card">
                        <div className="proposal-head"><div><span className="section-kicker">CONTAINMENT PROPOSAL</span><b>{selectedProposal ? `${selectedProposal.vulnerable_flag} off · safe fallback stays available` : "No proposal prepared"}</b></div>{selectedProposal && <StatusPill value={selectedProposal.status} />}</div>
                        {selectedProposal ? <><div className="proposal-meta"><span>Target <b>{humanize(selectedProposal.target_environment || "local")}</b></span><span>Expires <b>{formatTime(selectedProposal.expires_at)}</b></span></div><div className="hash-line"><span>APPROVAL HASH</span><code>{selectedProposal.proposal_hash}</code></div></> : <p className="proposal-hint">Analysis records the exact flag state. A change requires a separate operator decision.</p>}
                        <div className="action-row">
                          {!selectedProposal && ["search_sqli", "path_traversal"].includes(detail.scenario) && <button className="button button-primary" disabled={busy} onClick={() => runAction(`/incidents/${detail.id}/analyze`, "POST", {}, "Proposal prepared with a 15-minute expiry.")}>Analyze finding <span>→</span></button>}
                          {selectedProposal?.status === "pending_approval" && <><button className="button button-danger" disabled={busy} onClick={() => approve("reject")}>Reject</button><button className="button button-primary" disabled={busy} onClick={() => approve("approve")}>Approve exact change <span>→</span></button></>}
                          {selectedProposal?.status === "approved" && <button className="button button-primary" disabled={busy} onClick={apply}>Apply approved change <span>→</span></button>}
                          {["applied", "verification_pending", "verification_failed", "verification_unavailable"].includes(detail.status) && <button className="button button-primary" disabled={busy} onClick={verify}>Run verification <span>→</span></button>}
                          {detail.status === "verified" && <><button className="button button-quiet" disabled={busy} onClick={viewPatch}>View patch option</button><button className="button button-quiet" disabled={busy || patchCandidate?.incident_id !== detail.id} onClick={runPatchTest}>Run patch tests</button><label className="rollout-select"><span>STAGE</span><select value={rolloutStage} onChange={(event) => setRolloutStage(Number(event.target.value))}><option value={5}>5%</option><option value={25}>25%</option><option value={50}>50%</option><option value={100}>100%</option></select></label><button className="button button-quiet" disabled={busy || latestPatchTest?.status !== "passed"} onClick={previewStage}>Prepare stage</button></>}
                        </div>
                      {detail.status === "verified" && <p className="rollout-note">A stage needs passing patch tests, separate approval, and a separate Apply. It changes only the fixed synthetic identities.</p>}
                      {verification && <div className={`verification-card ${verification.status === "verified" ? "verification-good" : "verification-bad"}`}><div className="verification-head"><span>{verification.status === "verified" ? "✓" : "!"}</span><div><b>Post-change verification: {humanize(verification.status)}</b><small>{formatTime(verification.observed_at)}</small></div></div>{verification.checks && <div className="check-list">{Object.entries(verification.checks).map(([name, passed]) => <div key={name}><span className={passed ? "check-pass" : "check-fail"}>{passed ? "✓" : "×"}</span>{humanize(name)}</div>)}</div>}</div>}
                      {detail.operation_receipt && <div className="receipt-card"><div className="receipt-title"><div><span className="section-kicker">CHANGE RECEIPT</span><b>{humanize(detail.operation_receipt.adapter)}</b></div><StatusPill value={detail.operation_receipt.readback_verified ? "readback_verified" : "apply_failed"} /></div><div className="receipt-states">{Object.keys(detail.operation_receipt.after || {}).map((flag) => <div key={flag}><code>{flag}</code><span>{humanize(detail.operation_receipt.before?.[flag] || "unknown")} <i>→</i> <b>{humanize(detail.operation_receipt.after[flag])}</b></span></div>)}</div>{detail.operation_receipt.error_code && <small>Change not confirmed: {humanize(detail.operation_receipt.error_code)}{detail.operation_receipt.error_status_code ? ` (HTTP ${detail.operation_receipt.error_status_code})` : ""}. The before and after states above are the current readback.</small>}<small>Actor: {detail.decision?.actor || "unknown"} · {formatTime(detail.operation_receipt.executed_at)}</small></div>}
                      {patchCandidate?.incident_id === detail.id && <div className="patch-preview"><div className="patch-preview-heading"><div><span className="section-kicker">PATCH OPTION</span><b>{humanize(patchCandidate.safe_variant)} safe variant</b></div><StatusPill value="not_deployed" /></div><p>{patchCandidate.note}</p><div className="patch-file-pair"><code>{patchCandidate.before_file}</code><span>→</span><code>{patchCandidate.after_file}</code></div><div className="patch-test-status"><span>PATCH TEST</span><b>{humanize(latestPatchTest?.status || "not run")}</b></div>{latestPatchTest?.checks && <div className="check-list">{Object.entries(latestPatchTest.checks).map(([name, passed]) => <div key={name}><span className={passed ? "check-pass" : "check-fail"}>{passed ? "✓" : "×"}</span>{humanize(name)}</div>)}</div>}<pre aria-label="Code difference">{patchCandidate.diff}</pre></div>}
                      {detail.releases?.length > 0 && <div className="release-list"><div className="release-list-heading"><span className="section-kicker">STAGED RELEASES</span><b>Identity targeting and approvals</b></div>{detail.releases.map((release) => <ReleaseCard key={release.id} release={release} isLatestRecoverable={release.id === latestRecoverableReleaseId} busy={busy} onDecision={decideRelease} onApply={applyRelease} onRollback={proposeRollback} />)}</div>}
                      </div>
                      <div className="export-actions"><button className="export-button" onClick={exportReport}>⇩ Export evidence report <span>JSON</span></button><button className="export-button" onClick={exportReportMarkdown}>⇩ Export evidence report <span>Markdown</span></button></div>
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

function ImpactComparison({ incident, routes, preChangeCheck }) {
  const scenarios = {
    search_sqli: { path: "/search", vulnerableFlag: "search_v1", safeFlag: "search_v2" },
    path_traversal: { path: "/files", vulnerableFlag: "files_v1", safeFlag: "files_v2" },
  };
  const scenario = scenarios[incident.scenario];
  if (!scenario) return null;

  const route = routes.find((item) => item.path === scenario.path);
  const unrelatedRoutes = routes.filter(
    (item) => !(item.flags || []).includes(scenario.vulnerableFlag)
      && !(item.flags || []).includes(scenario.safeFlag),
  );
  const vulnerableState = route?.flag_states?.[scenario.vulnerableFlag] || "unknown";
  const safeState = route?.flag_states?.[scenario.safeFlag] || "unknown";

  return (
    <section className="impact-panel" aria-label="Containment impact comparison">
      <div className="impact-heading"><div><span className="section-kicker">BLAST RADIUS · LOCAL DEMO</span><h3>Containment impact</h3></div><span className="impact-readonly">Comparison only</span></div>
      <div className="impact-route"><div><span>AFFECTED ROUTE</span><code>{scenario.path}</code></div><div><span>FLAG STATES NOW</span><code>{scenario.vulnerableFlag}: {humanize(vulnerableState)} · {scenario.safeFlag}: {humanize(safeState)}</code></div></div>
      <div className="impact-options">
        <article className="impact-option impact-recommended"><span>PREPARED PROPOSAL</span><b>{incident.proposal ? `${incident.proposal.vulnerable_flag} off` : `${scenario.vulnerableFlag} off`}</b><p>Disables the vulnerable path. The predeployed safe variant stays separately controlled; the route uses its safe fallback until targeted rollout. {preChangeCheck?.status === "vulnerability_observed" ? "The before-change check reproduced the issue." : ""}</p></article>
        <article className="impact-option"><span>SAFE FALLBACK</span><b>{scenario.vulnerableFlag} off</b><p>The demo route uses its safe fallback if the safe-variant flag is not enabled. This is not a separate prepared approval.</p></article>
        <article className="impact-option"><span>HOLD</span><b>Leave flags unchanged</b><p>No change is applied; the vulnerable variant remains available when its flag is enabled.</p></article>
      </div>
      <div className="impact-footer"><span>Unaffected routes</span><b>{unrelatedRoutes.length ? unrelatedRoutes.map((item) => item.path).join(", ") : "None identified"}</b><small>Local code evidence only. No production traffic or customer cohort counts are connected.</small></div>
    </section>
  );
}

function ReleaseCard({ release, isLatestRecoverable, busy, onDecision, onApply, onRollback }) {
  const selected = Object.entries(release.desired_overrides || {}).filter(([, enabled]) => enabled === true).map(([identity]) => identity);
  return (
    <article className="release-card">
      <div className="release-card-head"><div><span className="section-kicker">{humanize(release.action)} · {release.percentage}%</span><b>{release.safe_flag} for {selected.length} of {Object.keys(release.desired_overrides || {}).length} synthetic users</b></div><StatusPill value={release.status} /></div>
      <div className="release-identities">{selected.length ? selected.join(", ") : "No identities enabled in the restored state"}</div>
      <div className="hash-line"><span>APPROVAL HASH</span><code>{release.proposal_hash}</code></div>
      <div className="proposal-meta"><span>Environment <b>{humanize(release.target_environment)}</b></span><span>Expires <b>{formatTime(release.expires_at)}</b></span>{release.release_actor && <span>Decision by <b>{release.release_actor}</b></span>}</div>
      {release.receipt && <div className="release-receipt"><span>Management readback <b>{release.receipt.readback_verified ? "confirmed" : "not confirmed"}</b></span><span>Demo identity evaluation <b>{release.receipt.app_evaluation_verified ? "confirmed" : "not confirmed"}</b></span>{release.receipt.guardrail_status && <span>Guardrail <StatusPill value={release.receipt.guardrail_status} /></span>}{release.receipt.guardrail_violations?.length > 0 && <small>Failed identities: {release.receipt.guardrail_violations.join(", ")}</small>}{release.receipt.recommendation && <small>Next step: {humanize(release.receipt.recommendation)}</small>}{release.receipt.error_code && <small>Failure code: {humanize(release.receipt.error_code)}</small>}</div>}
      <div className="action-row release-actions">
        {release.status === "pending_approval" && <><button className="button button-danger" disabled={busy} onClick={() => onDecision(release, "reject")}>Reject stage</button><button className="button button-primary" disabled={busy} onClick={() => onDecision(release, "approve")}>Approve exact stage</button></>}
        {release.status === "approved" && <button className="button button-primary" disabled={busy} onClick={() => onApply(release)}>Apply stage</button>}
        {["applied", "apply_failed"].includes(release.status) && isLatestRecoverable && <button className="button button-quiet" disabled={busy} onClick={() => onRollback(release)}>Propose rollback</button>}
      </div>
      {release.action === "rollback" && <small className="release-restore-note">This rollback is a new proposal and needs its own approval before any identity override changes.</small>}
    </article>
  );
}

function TelemetryView({ telemetry, busy, count, setCount, onGenerate }) {
  if (!telemetry) return <div className="panel loading-card">Loading synthetic telemetry…</div>;
  return (
    <section className="telemetry-layout">
      <div className="panel telemetry-control">
        <div className="panel-heading"><div><span className="section-kicker">SIMULATED TRAFFIC</span><h2>Generate bounded demo requests</h2></div><span className="new-indicator">SYNTHETIC</span></div>
        <p>Requests use the fixed demo identities and safe sample queries. They never represent real users or customer traffic.</p>
        <div className="traffic-form"><label>Requests<input type="number" min="1" max="500" value={count} onChange={(event) => setCount(Math.min(500, Math.max(1, Number(event.target.value) || 1)))} /></label><button className="button button-primary" disabled={busy} onClick={onGenerate}>Run synthetic traffic <span>→</span></button></div>
      </div>
      <div className="panel telemetry-table-panel">
        <div className="panel-heading"><div><span className="section-kicker">OBSERVED ROUTES AND FLAGS</span><h2>Request outcomes</h2></div><span className="timeline-count">{telemetry.simulation ? "DEMO ONLY" : "UNKNOWN"}</span></div>
        {telemetry.summary?.length ? <div className="coverage-table"><div className="coverage-row telemetry-head"><span>ROUTE / VARIANT</span><span>OUTCOME</span><span>REQUESTS</span></div>{telemetry.summary.map((item) => <div className="coverage-row telemetry-row" key={`${item.route}-${item.variant}-${item.outcome}-${item.status_code}`}><span><code>{item.route}</code><small>{humanize(item.variant)}</small></span><span>{humanize(item.outcome)} · {item.status_code}</span><b>{item.requests}</b></div>)}</div> : <div className="empty-timeline">No synthetic requests recorded yet. Run a bounded sample above.</div>}
      </div>
      <div className="panel telemetry-table-panel">
        <div className="panel-heading"><div><span className="section-kicker">MOST RECENT</span><h2>Identity observations</h2></div><span className="timeline-count">up to 100 rows</span></div>
        {telemetry.recent?.length ? <div className="coverage-table"><div className="coverage-row telemetry-head"><span>IDENTITY / ROUTE</span><span>VARIANT / OUTCOME</span><span>TIME</span></div>{telemetry.recent.map((item) => <div className="coverage-row telemetry-row" key={item.id}><span><code>{item.identity || "system check"}</code><small>{item.route}</small></span><span>{humanize(item.variant)} · {humanize(item.outcome)}</span><small>{formatTime(item.created_at)}</small></div>)}</div> : <div className="empty-timeline">Telemetry remains empty until the app receives a request.</div>}
        <p className="coverage-copy">No request query strings, file contents, or personal data are saved in telemetry.</p>
      </div>
    </section>
  );
}

function CoverageView({ coverage, counts }) {
  if (!coverage) return <div className="panel loading-card">Loading route coverage…</div>;
  return <section className="panel coverage-panel"><div className="panel-heading"><div><span className="section-kicker">ROUTE → FLAG MAP</span><h2>Coverage overview</h2></div><StatusPill value={coverage.status} /></div><p className="coverage-copy">A route is marked covered only when every referenced flag has a known state. Unknown or missing Flagsmith values remain visible as gaps.</p>{coverage.error && <div className="coverage-warning"><span>!</span><div><b>Flagsmith state could not be read</b><small>{humanize(coverage.error)}. Coverage remains unknown until the service responds.</small></div></div>}<div className="coverage-summary"><div><span>KNOWN STATES</span><b>{counts.known}<small> / {counts.total}</small></b></div><div><span>OPEN GAPS</span><b className={counts.gaps ? "orange-text" : ""}>{counts.gaps}</b></div><div><span>FLAG ADAPTER</span><b>{humanize(coverage.adapter)}</b></div></div><div className="coverage-table"><div className="coverage-row coverage-head"><span>ROUTE</span><span>FEATURE FLAGS</span><span>STATUS</span></div>{coverage.routes.map((route) => <div className="coverage-row" key={route.path}><span><code>{route.path}</code><small>{route.method}</small></span><span className="flag-tags">{Object.entries(route.flag_states || {}).length ? Object.entries(route.flag_states).map(([name, state]) => <span className={`flag-tag flag-${state}`} key={name}><b>{name}</b><i>{humanize(state)}</i></span>) : <span className="muted">No feature flag required</span>}</span><span><StatusPill value={route.covered ? "complete" : "incomplete"} /></span></div>)}</div>{coverage.gaps?.length > 0 && <div className="coverage-warning"><span>!</span><div><b>Coverage needs attention</b><small>{coverage.gaps.map((gap) => `${gap.route} · ${gap.flag}`).join("; ")}</small></div></div>}</section>;
}

createRoot(document.getElementById("root")).render(<App />);
