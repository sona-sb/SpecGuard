import { ArrowRight, CheckCircle2, FileCode2, Search, ShieldAlert, Wrench } from "lucide-react";

export default function VerdictHub({ report, onDetails, onPatched, onBack }) {
  const verdict = report.verdict?.verdict || "BLOCK";
  const blocked = verdict === "BLOCK";
  const critical = report.verdict?.counts?.CRITICAL || 0;
  const summary = blocked
    ? `Deployment blocked: ${critical || "critical"} critical issue${critical === 1 ? "" : "s"} need attention before release.`
    : verdict === "WARN"
      ? "Deployment can continue with warnings. Review the audit before release."
      : "Deployment approved: the submitted artifacts passed the security and documentation checks.";

  return (
    <main className="verdict-hub pixel-grid">
      <button onClick={onBack} className="back-button">← BACK TO WORKSPACE</button>
      <section className={`hub-card ${blocked ? "hub-block" : "hub-pass"}`}>
        <div className={`hub-status-icon ${blocked ? "hub-status-block" : "hub-status-pass"}`}>
          {blocked ? <ShieldAlert size={42} /> : <CheckCircle2 size={42} />}
        </div>
        <p className="report-eyebrow">GATEKEEPER // FINAL DECISION</p>
        <h1 className="pixel-title mt-5 text-3xl text-[#f8fafc]">{verdict}</h1>
        <p className="hub-summary">{summary}</p>
        <p className="hub-headline">{report.verdict?.headline}</p>
        <div className="hub-actions">
          <button onClick={onDetails} className="hub-action hub-action-primary"><Search size={18} /> VIEW DETAILED AUDIT REPORT <ArrowRight size={16} /></button>
          <button onClick={onPatched} className="hub-action"><Wrench size={18} /> VIEW AUTO-PATCHED FILES <ArrowRight size={16} /></button>
        </div>
      </section>
      <div className="hub-stats">
        <span><ShieldAlert size={16} /> {report.verdict?.counts?.CRITICAL || 0} critical findings</span>
        <span><FileCode2 size={16} /> {report.drift?.findings?.length || 0} documentation mismatches</span>
      </div>
    </main>
  );
}
