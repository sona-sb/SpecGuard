import { useState } from "react";
import { ArrowLeft, Play, Shield, Upload, Zap } from "lucide-react";
import EditorPanel from "./components/EditorPanel";
import LandingPage from "./components/LandingPage";
import ResultsDashboard from "./components/ResultsDashboard";
import VerdictHub from "./components/VerdictHub";

const API_URL = "http://localhost:8000";

export default function App() {
  const [page, setPage] = useState("landing");
  const [apiKey, setApiKey] = useState("");
  const [mockMode, setMockMode] = useState(true);
  const [backendCode, setBackendCode] = useState("");
  const [apiDocs, setApiDocs] = useState("");
  const [infraConfig, setInfraConfig] = useState("");
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function loadDemo() {
    setMessage("LOADING DEMO ARTIFACTS...");
    try {
      const response = await fetch(`${API_URL}/demo-sample`);
      if (!response.ok) throw new Error("Demo sample request failed.");
      const sample = await response.json();
      setBackendCode(sample.backend_code); setApiDocs(sample.api_docs); setInfraConfig(sample.infra_config);
      setReport(null); setMessage("DEMO SAMPLE READY // 3 ARTIFACTS LOADED");
    } catch (error) { setMessage(error.message); }
  }

  async function runAudit() {
    if (!backendCode.trim()) { setMessage("BACKEND CODE IS REQUIRED."); return; }
    setBusy(true); setMessage("RUNNING 3-ARTIFACT CROSS-EXAMINATION...");
    try {
      const response = await fetch(`${API_URL}/audit`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ api_key: apiKey, mock_mode: mockMode, backend_code: backendCode, api_docs: apiDocs, infra_config: infraConfig }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || "Audit failed.");
      setReport(payload); setMessage("AUDIT COMPLETE // GATEKEEPER EVALUATED"); setPage("verdict");
    } catch (error) { setMessage(error.message); } finally { setBusy(false); }
  }

  if (page === "landing") return <LandingPage onEnter={() => setPage("workspace")} />;
  if (page === "verdict" && report) return <VerdictHub report={report} onDetails={() => setPage("details")} onPatched={() => setPage("patched")} onBack={() => setPage("workspace")} />;
  if ((page === "details" || page === "patched") && report) {
    return <div className="workspace-shell"><main className="mx-auto max-w-[1500px] px-5 py-10"><button onClick={() => setPage("verdict")} className="back-button">← BACK TO VERDICT HUB</button><ResultsDashboard report={report} focus={page} /></main></div>;
  }

  return <div className="workspace-shell pixel-grid">
    <header className="border-b-2 border-[#1f4d34] bg-[#0a1c12]/95">
      <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-5 px-5 py-5">
        <button onClick={() => setPage("landing")} className="flex items-center gap-3 text-left" aria-label="Back to home"><Shield className="text-[#a78bfa]" size={34} strokeWidth={2.5} /><h1 className="pixel-title text-lg text-[#f8fafc] sm:text-xl">SPEC GUARD</h1></button>
        <div className="flex flex-wrap items-center justify-end gap-3">
          <div className="api-key-bar">
            <label className="api-key-label"><span>Gemini API key</span><input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="optional in mock" /></label>
          </div>
          <label className="flex items-center gap-2 text-xs text-[#a7f3d0]"><input type="checkbox" checked={mockMode} onChange={(e) => setMockMode(e.target.checked)} className="accent-lime-500" /> DEMO MOCK MODE</label>
          <button onClick={loadDemo} className="violet-outline-button"><Upload size={15} /> LOAD DEMO</button>
        </div>
      </div>
    </header>
    <main className="mx-auto max-w-[1500px] px-5 py-10">
      <button onClick={() => setPage("landing")} className="back-button"><ArrowLeft size={15} /> BACK TO HOME</button>
      <section className="mb-9 mt-7 flex flex-col justify-between gap-7 md:flex-row md:items-end"><div><p className="eyebrow mb-4">AUDIT WORKSPACE // 3 ARTIFACT CHECK</p><h2 className="pixel-title max-w-3xl text-xl leading-8 text-[#f8fafc] sm:text-3xl">SHIP NOTHING<br /><span className="text-[#a78bfa]">UNVERIFIED.</span></h2><p className="mt-5 max-w-xl text-lg text-[#94a3b8]">Cross-examine backend code, API contracts, and infrastructure before they reach production.</p></div><button onClick={runAudit} disabled={busy} className="primary-button lime-glow"><Play size={18} fill="currentColor" /> {busy ? "AUDITING..." : "RUN PRE-DEPLOY AUDIT"}</button></section>
      {message && <div className="mb-6 flex items-center gap-2 border-l-4 border-[#84cc16] bg-[#133322] px-4 py-3 text-[#d9f99d]"><Zap size={16} />{message}</div>}
      <div className="grid gap-5 xl:grid-cols-3"><EditorPanel title="BACKEND CODE" filename="main.py / app.js" language="source code" value={backendCode} onChange={setBackendCode} /><EditorPanel title="API DOCUMENTATION" filename="README.md / openapi.yaml" language="README or OpenAPI" value={apiDocs} onChange={setApiDocs} /><EditorPanel title="INFRA CONFIG" filename="docker-compose.yml" language="Docker Compose" value={infraConfig} onChange={setInfraConfig} /></div>
      {report && <button onClick={() => setPage("verdict")} className="mt-8 violet-outline-button">VIEW VERDICT HUB <ArrowLeft size={15} /></button>}
      {!report && <div className="mt-9 border-2 border-dashed border-[#1f4d34] p-8 text-center text-[#527c63]"><p className="pixel-label text-[10px]">AWAITING ARTIFACTS</p><p className="mt-3 text-lg">Load the demo sample or paste three artifacts, then start the audit.</p></div>}
    </main>
  </div>;
}
