import { useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  Clipboard,
  Code2,
  Download,
  FileWarning,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react";

const severityStyles = {
  CRITICAL: "border-[#ef4444]/40 bg-[#431a20] text-[#fca5a5]",
  HIGH: "border-[#fb923c]/40 bg-[#42251b] text-[#fdba74]",
  MEDIUM: "border-[#f59e0b]/40 bg-[#44351a] text-[#fcd34d]",
};

const severityIcons = {
  CRITICAL: ShieldAlert,
  HIGH: FileWarning,
  MEDIUM: FileWarning,
};

function DeepDive({ children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-5 border-t border-[#285c41] pt-4">
      <button
        onClick={() => setOpen((current) => !current)}
        className="deep-dive-toggle"
      >
        <ChevronDown size={13} className={`transition-transform ${open ? "rotate-180" : ""}`} />
        {open ? "Hide technical deep dive" : "View technical deep dive"}
      </button>
      {open && <div className="mt-4 animate-[fade-in_.2s_ease-out]">{children}</div>}
    </div>
  );
}

function ActionButton({ children, onClick }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-2 border-2 border-[#3b7657] border-t-white/20 border-l-white/10 border-b-4 border-r-4 border-b-black/60 border-r-black/60 px-3 py-2 text-sm font-semibold text-[#c7f9d9] transition hover:border-[#86efac] hover:bg-[#1b3d2b] active:translate-y-0.5"
    >
      {children}
    </button>
  );
}

function copyText(text) {
  navigator.clipboard?.writeText(text || "");
}

function downloadText(name, text) {
  const url = URL.createObjectURL(new Blob([text || ""], { type: "text/plain" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

function ReportSection({ eyebrow, title, description, children, className = "" }) {
  return (
    <section className={`report-section ${className}`}>
      <div className="mb-6">
        <p className="report-eyebrow">{eyebrow}</p>
        <h3 className="report-heading">{title}</h3>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-[#94a3b8]">{description}</p>
      </div>
      {children}
    </section>
  );
}

export default function ResultsDashboard({ report, focus = "all" }) {
  const [artifactTab, setArtifactTab] = useState("backend");
  const verdict = report.verdict?.verdict || "BLOCK";
  const findings = report.security?.findings || [];
  const drift = report.drift?.findings || [];
  const remediation = report.remediation || {};
  const blocked = verdict === "BLOCK";
  const criticalCount = report.verdict?.counts?.CRITICAL || 0;
  const verdictSummary = blocked
    ? `Deployment blocked: ${criticalCount || "critical"} critical security issue${criticalCount === 1 ? "" : "s"} require attention before release.`
    : verdict === "WARN"
      ? "Deployment can continue with warnings. Review the highlighted risks and documentation mismatches before release."
      : "Deployment approved: the submitted artifacts passed the security and documentation checks.";
  const VerdictIcon = blocked ? ShieldAlert : CheckCircle2;
  const artifactContent = {
    backend: ["HARDENED BACKEND", "hardened_backend.py", remediation.hardened_backend_code],
    docs: ["UPDATED README", "README.updated.md", remediation.updated_docs],
    infra: ["HARDENED INFRA", "hardened_infra.yml", remediation.hardened_infra_config],
  };
  const [artifactTitle, artifactName, artifactText] = artifactContent[artifactTab];

  return (
    <div className="mt-12 space-y-8">
      <section className={`verdict-card ${blocked ? "verdict-block" : "verdict-pass"}`}>
        <div className="flex items-start gap-4">
          <div className="verdict-icon"><VerdictIcon size={28} /></div>
          <div>
            <p className="report-eyebrow">01 / GATEKEEPER DECISION</p>
            <h2 className="pixel-title mt-3 text-xl text-[#f8fafc] sm:text-2xl">{verdict}</h2>
            <p className="mt-3 max-w-2xl text-base leading-7 text-[#f8fafc]">{verdictSummary}</p>
          </div>
        </div>
        <div className="verdict-meta">
          <span>{report.verdict?.headline || "AUDIT COMPLETE"}</span>
          <span>{report.verdict?.triggered_rules?.join(" · ") || "No blocking rules triggered"}</span>
        </div>
      </section>

      {focus !== "patched" && <ReportSection
        eyebrow="02 / SECURITY REVIEW"
        title="Security & shadow endpoints"
        description={report.security?.summary || "Potential security risks found across your code and infrastructure."}
        className="report-section-purple"
      >
        {findings.length === 0 ? (
          <div className="empty-report"><CheckCircle2 size={22} /> No security findings were detected.</div>
        ) : (
          <div className="grid gap-5 lg:grid-cols-2">
            {findings.map((item) => {
              const Icon = severityIcons[item.severity] || FileWarning;
              return (
                <article key={item.id} className="finding-card">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="finding-icon"><Icon size={20} /></div>
                      <div>
                        <span className={`severity-badge ${severityStyles[item.severity] || severityStyles.MEDIUM}`}>{item.severity}</span>
                        <h4 className="mt-3 text-lg font-semibold leading-6 text-[#f8fafc]">{item.title}</h4>
                      </div>
                    </div>
                    <span className="text-xs font-semibold text-[#64748b]">{item.id}</span>
                  </div>
                  <p className="mt-4 text-sm leading-6 text-[#cbd5e1]">{item.risk}</p>
                  <div className="mt-4 border-2 border-[#285c41] bg-[#0b1e14] px-3 py-3 text-sm text-[#94a3b8]">
                    <span className="font-semibold text-[#a7f3d0]">Recommended fix: </span>{item.recommendation}
                  </div>
                  <DeepDive>
                    <div className="grid gap-3 text-sm text-[#94a3b8] sm:grid-cols-2">
                      <p><span className="font-semibold text-[#a7f3d0]">Location</span><br />{item.location || "Not specified"}</p>
                      <p><span className="font-semibold text-[#a7f3d0]">Endpoint / port</span><br />{item.endpoint || (item.port ? `Port ${item.port}` : "Not applicable")}</p>
                    </div>
                    <pre className="code-detail">{item.evidence || "No evidence snippet supplied."}</pre>
                  </DeepDive>
                </article>
              );
            })}
          </div>
        )}
      </ReportSection>}

      {focus !== "patched" && <ReportSection
        eyebrow="03 / CONTRACT HEALTH"
        title="Documentation drift analysis"
        description={report.drift?.summary || "A comparison of implemented behavior and documented expectations."}
        className="report-section-purple"
      >
        {drift.length === 0 ? (
          <div className="empty-report"><CheckCircle2 size={22} /> Documentation is fully synchronized with the implementation.</div>
        ) : (
          <div className="drift-list">
            {drift.map((item) => (
              <article key={item.id} className="drift-row">
                <div className="drift-route">
                  <span className="drift-type">{item.drift_type.replaceAll("_", " ")}</span>
                  <strong>{item.method} {item.endpoint}</strong>
                </div>
                <div className="drift-columns">
                  <div><p className="comparison-label">CODE SAYS</p><p>{item.code_behavior}</p></div>
                  <div><p className="comparison-label">DOCS SAY</p><p>{item.docs_behavior}</p></div>
                </div>
                <DeepDive><p className="text-sm leading-6 text-[#94a3b8]">{item.explanation}</p></DeepDive>
              </article>
            ))}
          </div>
        )}
      </ReportSection>}

      {focus !== "details" && <ReportSection
        eyebrow="04 / REMEDIATION"
        title="Auto-patched artifacts"
        description="Review the generated fixes, then copy or download the artifact you want to take forward."
      >
        <div className="artifact-card">
          <div className="artifact-tabs">
            {Object.entries(artifactContent).map(([id, [label]]) => (
              <button key={id} onClick={() => setArtifactTab(id)} className={artifactTab === id ? "artifact-tab active" : "artifact-tab"}>{label}</button>
            ))}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#285c41] px-5 py-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#d9f99d]"><Code2 size={17} />{artifactName}</div>
            <div className="flex gap-2"><ActionButton onClick={() => copyText(artifactText)}><Clipboard size={15} />Copy</ActionButton><ActionButton onClick={() => downloadText(artifactName, artifactText)}><Download size={15} />Download</ActionButton></div>
          </div>
          <pre className="artifact-code"><TerminalSquare size={17} className="mb-3 text-[#4ade80]" />{artifactText || "No patched artifact returned."}</pre>
        </div>
      </ReportSection>}
    </div>
  );
}
