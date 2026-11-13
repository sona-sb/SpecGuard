"""
app.py - SpecGuard AI Streamlit dashboard.

Run with:  streamlit run app.py
"""

import difflib
import html
import json
import os

import streamlit as st
import streamlit.components.v1 as components

from analyzer import (
    DEFAULT_MODEL,
    AnalyzerError,
    DriftFinding,
    InvalidAPIKeyError,
    MissingAPIKeyError,
    RateLimitError,
    SecurityFinding,
    Severity,
    run_full_audit,
)
from ingestor import IngestionError, ingest, load_demo_sample, read_uploaded_file
from validator import Verdict, evaluate

st.set_page_config(page_title="SpecGuard AI", page_icon="🛡️", layout="wide")

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
MODELS = ["gemini-3.8-flash"]

CSS = """
<style>
.sg-hero h1 {margin-bottom:0; font-size:2.1rem;}
.sg-hero p {margin-top:.2rem; opacity:.75;}
.sg-banner {padding:1.3rem 1.6rem; border-radius:14px; margin:.4rem 0 1.1rem; color:#fff;}
.sg-banner h2 {margin:0; color:#fff; font-size:1.8rem; letter-spacing:.02em;}
.sg-banner p {margin:.25rem 0 0; opacity:.95;}
.sg-block {background:linear-gradient(135deg,#991b1b,#ef4444);}
.sg-pass {background:linear-gradient(135deg,#166534,#22c55e);}
.sg-warn {background:linear-gradient(135deg,#b45309,#f59e0b);}
.sg-badge {display:inline-block; padding:2px 10px; border-radius:999px; font-size:.72rem;
           font-weight:700; letter-spacing:.05em; color:#fff; margin-right:6px;}
.sg-critical {background:#dc2626;} .sg-high {background:#ea580c;} .sg-medium {background:#ca8a04;}
.sg-tag {display:inline-block; padding:2px 9px; border-radius:6px; font-size:.72rem;
         background:rgba(128,128,128,.18); font-family:ui-monospace,monospace;}
.sg-rule {padding:.5rem .8rem; margin:.3rem 0; border-left:4px solid #ef4444;
          background:rgba(239,68,68,.08); border-radius:4px; font-size:.92rem;}
.sg-rule.warn {border-left-color:#f59e0b; background:rgba(245,158,11,.08);}
.sg-rule.ok {border-left-color:#22c55e; background:rgba(34,197,94,.08);}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# State + callbacks
# --------------------------------------------------------------------------- #
for _k in ("backend_code", "api_docs", "infra_config"):
    st.session_state.setdefault(_k, "")
st.session_state.setdefault("result", None)
st.session_state.setdefault("verdict", None)
st.session_state.setdefault("inputs", None)


def _load_demo() -> None:
    sample = load_demo_sample()
    st.session_state["backend_code"] = sample["backend_code"]
    st.session_state["api_docs"] = sample["api_docs"]
    st.session_state["infra_config"] = sample["infra_config"]
    st.session_state["result"] = None
    st.session_state["verdict"] = None
    st.session_state["notice"] = "Demo sample loaded - click **Run Pre-Deploy Audit**."


def _on_upload(upload_key: str, target_key: str) -> None:
    """Copy an uploaded file's text into the matching text area."""
    uploaded = st.session_state.get(upload_key)
    if uploaded is None:
        return
    try:
        st.session_state[target_key] = read_uploaded_file(uploaded.name, uploaded.getvalue())
        st.session_state["notice"] = f"Loaded `{uploaded.name}`."
    except IngestionError as exc:
        st.session_state["upload_error"] = str(exc)


def resolve_api_key() -> str:
    """Return the key chosen in the sidebar (custom field or environment)."""
    if st.session_state.get("key_mode") == "Enter custom key":
        return (st.session_state.get("google_api_key") or "").strip()
    return (os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY") or "").strip()


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown("## 🛡️ SpecGuard AI")
    st.caption("Pre-deployment gatekeeper for code, infra & API docs.")
    st.button("⚡ Load Demo Sample", on_click=_load_demo, type="primary")
    st.divider()

    st.markdown("**🔑 Gemini API key**")
    key_mode = st.radio(
        "Key source",
        ["Use environment variable", "Enter custom key"],
        key="key_mode",
        label_visibility="collapsed",
    )
    st.text_input(
        "Google API Key",
        type="password",
        key="google_api_key",
        placeholder="AIza...",
        disabled=(key_mode != "Enter custom key"),
        help="Free keys are available at https://aistudio.google.com/apikey",
    )
    if resolve_api_key():
        st.success("API key detected", icon="✅")
    else:
        st.warning(
            "No API key found. Set `GOOGLE_API_KEY` (or `GEMINI_API_KEY`) or enter a custom key above.",
            icon="⚠️",
        )

    model = st.selectbox("Model", MODELS, index=MODELS.index(DEFAULT_MODEL))
    offline_mock = st.checkbox(
        "🛡️ Enable Offline / Demo Mock Mode",
        help="Skip Gemini and use realistic local audit results for demos, recordings, and UI testing.",
    )
    if offline_mock:
        st.info("Live Gemini calls are disabled. Results will be generated locally.", icon="🧪")
    st.divider()
    st.caption(
        "Each audit makes 3 Gemini calls with a 4 s buffer between them to stay inside "
        "free-tier rate limits (~30-60 s total)."
    )

# --------------------------------------------------------------------------- #
# Header + inputs
# --------------------------------------------------------------------------- #
st.markdown(
    '<div class="sg-hero"><h1>🛡️ SpecGuard AI</h1>'
    "<p>Cross-examine backend code, infrastructure and API docs before you ship.</p></div>",
    unsafe_allow_html=True,
)

if st.session_state.get("notice"):
    st.info(st.session_state.pop("notice"), icon="ℹ️")
if st.session_state.get("upload_error"):
    st.error(st.session_state.pop("upload_error"))

col_code, col_docs, col_infra = st.columns(3)
INPUT_SPECS = [
    (col_code, "📦 Backend Code", "backend_code", "up_code", ["py", "js", "ts", "mjs", "txt"],
     "Paste FastAPI / Flask / Express source..."),
    (col_docs, "📄 API Docs", "api_docs", "up_docs", ["md", "markdown", "yaml", "yml", "json", "txt"],
     "Paste README.md or an OpenAPI YAML/JSON spec..."),
    (col_infra, "🐳 Infra Config", "infra_config", "up_infra", ["yml", "yaml", "txt", "dockerfile"],
     "Paste docker-compose.yml and/or Dockerfile..."),
]
for col, title, key, up_key, types_, placeholder in INPUT_SPECS:
    with col:
        st.markdown(f"**{title}**")
        st.text_area(title, key=key, height=340, placeholder=placeholder, label_visibility="collapsed")
        st.file_uploader(
            f"Upload {title}", key=up_key, type=types_, label_visibility="collapsed",
            on_change=_on_upload, args=(up_key, key),
        )
        st.caption(f"{len(st.session_state[key]):,} characters")

run_clicked = st.button("🚀 Run Pre-Deploy Audit", type="primary")

# --------------------------------------------------------------------------- #
# Run the audit
# --------------------------------------------------------------------------- #
if run_clicked:
    api_key = resolve_api_key()
    if not api_key and not offline_mock:
        st.error("A Google API key is required. Add one in the sidebar (free at aistudio.google.com/apikey).")
    else:
        try:
            audit_inputs = ingest(
                st.session_state["backend_code"],
                st.session_state["api_docs"],
                st.session_state["infra_config"],
            )
            for w in audit_inputs.warnings:
                st.warning(w, icon="⚠️")

            with st.status("Running SpecGuard audit...", expanded=True) as status:
                def _progress(step: int, total: int, message: str) -> None:
                    st.write(f"**Step {step}/{total}** - {message}")

                result = run_full_audit(
                    audit_inputs,
                    api_key,
                    model,
                    progress_cb=_progress,
                    mock_mode=offline_mock,
                )
                st.write("**Evaluating deterministic gatekeeper rules...**")
                verdict = evaluate(result.security, result.drift, audit_inputs)
                status.update(label=f"Audit complete in {result.duration_seconds:.0f}s",
                              state="complete", expanded=False)

            st.session_state["result"] = result
            st.session_state["verdict"] = verdict
            st.session_state["inputs"] = audit_inputs

        except IngestionError as exc:
            st.error(f"Input problem: {exc}")
        except MissingAPIKeyError:
            st.error("No API key provided.")
        except InvalidAPIKeyError as exc:
            st.error(str(exc))
        except RateLimitError as exc:
            st.error(str(exc))
        except AnalyzerError as exc:
            st.error(f"Audit failed: {exc}")


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def badge(sev: Severity) -> str:
    return f'<span class="sg-badge sg-{sev.value.lower()}">{sev.value}</span>'


def render_security_finding(f: SecurityFinding) -> None:
    with st.expander(f"{SEV_ICON[f.severity.value]} {f.id} · {f.title}",
                     expanded=(f.severity == Severity.CRITICAL)):
        st.markdown(
            f'{badge(f.severity)}<span class="sg-tag">{html.escape(f.category.value)}</span>',
            unsafe_allow_html=True,
        )
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**Location**  \n`{f.location}`")
        c2.markdown(f"**Endpoint**  \n`{f.endpoint}`" if f.endpoint else "**Endpoint**  \n-")
        c3.markdown(f"**Port**  \n`{f.port}`" if f.port else "**Port**  \n-")
        st.markdown("**Evidence**")
        st.code(f.evidence, language=None)
        st.markdown(f"**Risk:** {f.risk}")
        st.markdown(f"**Recommended fix:** {f.recommendation}")


def render_drift_finding(f: DriftFinding) -> None:
    label = f"{f.method} {f.endpoint}".strip()
    with st.expander(f"{SEV_ICON[f.severity.value]} {f.id} · {f.drift_type.value} · {label}"):
        st.markdown(
            f'{badge(f.severity)}<span class="sg-tag">{html.escape(f.drift_type.value)}</span>',
            unsafe_allow_html=True,
        )
        left, right = st.columns(2)
        left.markdown("**💻 Code says**")
        left.info(f.code_behavior)
        right.markdown("**📄 Docs say**")
        right.warning(f.docs_behavior)
        st.markdown(f"**Why it matters:** {f.explanation}")


def unified_diff(old: str, new: str, from_name: str, to_name: str) -> str:
    return "\n".join(
        difflib.unified_diff(old.splitlines(), new.splitlines(), fromfile=from_name, tofile=to_name, n=3, lineterm="")
    )


def side_by_side_html(old: str, new: str, from_name: str, to_name: str) -> str:
    table = difflib.HtmlDiff(tabsize=4, wrapcolumn=72).make_table(
        old.splitlines(), new.splitlines(), fromdesc=from_name, todesc=to_name, context=True, numlines=3
    )
    css = """<style>
    body{background:#fff;color:#111;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;margin:0}
    table.diff{width:100%;border-collapse:collapse;border:1px solid #d0d7de}
    th.diff_header{background:#f1f3f5;padding:6px;text-align:center;border-bottom:1px solid #d0d7de}
    td{padding:1px 6px;vertical-align:top;white-space:pre-wrap;word-break:break-word}
    td.diff_header{background:#f6f8fa;color:#8c959f;text-align:right;user-select:none}
    .diff_next{background:#e9ecef}
    .diff_add{background:#c8f7d2}.diff_chg{background:#fff3b0}.diff_sub{background:#ffd0d0}
    </style>"""
    return f"<html><head>{css}</head><body>{table}</body></html>"


def code_block_with_download(text: str, language: str, filename: str, mime: str = "text/plain") -> None:
    st.code(text, language=language, line_numbers=True)
    st.download_button(f"⬇️ Download {filename}", data=text, file_name=filename, mime=mime, key=f"dl_{filename}")


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
st.divider()
result = st.session_state["result"]
verdict = st.session_state["verdict"]
audit_inputs = st.session_state["inputs"]

tab1, tab2, tab3 = st.tabs([
    "🚦 Gatekeeper Verdict & Security Audit",
    "📚 Documentation Drift Report",
    "🛠️ Auto-Patched Artifacts",
])

if result is None or verdict is None:
    for tab in (tab1, tab2, tab3):
        with tab:
            st.info("Load the demo sample (or paste your own files) and click **Run Pre-Deploy Audit**.", icon="👈")
else:
    # ---------------- Tab 1 ---------------- #
    with tab1:
        css_class = {Verdict.BLOCK: "sg-block", Verdict.PASS: "sg-pass", Verdict.WARN: "sg-warn"}[verdict.verdict]
        icon = {Verdict.BLOCK: "⛔", Verdict.PASS: "✅", Verdict.WARN: "⚠️"}[verdict.verdict]
        st.markdown(
            f'<div class="sg-banner {css_class}"><h2>{icon} {verdict.verdict.value} - {verdict.headline}</h2>'
            f"<p>Rules triggered: {', '.join(verdict.triggered_rules) or 'none'} · "
            f"model {html.escape(result.model)} · {result.duration_seconds:.0f}s</p></div>",
            unsafe_allow_html=True,
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🔴 Critical", verdict.counts["CRITICAL"])
        m2.metric("🟠 High", verdict.counts["HIGH"])
        m3.metric("🟡 Medium", verdict.counts["MEDIUM"])
        m4.metric("📚 Drift issues", verdict.drift_count)

        st.markdown("#### Why this verdict")
        rule_css = {Verdict.BLOCK: "", Verdict.WARN: "warn", Verdict.PASS: "ok"}[verdict.verdict]
        for reason in verdict.reasons:
            st.markdown(f'<div class="sg-rule {rule_css}">{html.escape(reason)}</div>', unsafe_allow_html=True)

        st.markdown("#### Executive summary")
        st.write(result.security.summary)
        if verdict.static_findings_added:
            st.caption(f"🔎 {verdict.static_findings_added} finding(s) added by the deterministic static cross-check.")

        st.markdown("#### Security findings")
        chosen = st.multiselect("Filter by severity", [s.value for s in Severity],
                                default=[s.value for s in Severity], key="sev_filter")
        shown = [f for f in verdict.security_findings if f.severity.value in chosen]
        if not shown:
            st.success("No findings match the current filter.")
        for f in shown:
            render_security_finding(f)

        report = {"verdict": verdict.to_dict(), **result.to_dict()}
        st.download_button("⬇️ Download full JSON report", data=json.dumps(report, indent=2),
                           file_name="specguard_report.json", mime="application/json")

    # ---------------- Tab 2 ---------------- #
    with tab2:
        st.markdown("#### Documentation health")
        st.write(result.drift.summary)
        drift = result.drift.findings
        if not drift:
            st.success("Documentation is fully synchronised with the code. 🎉")
        else:
            d_types = ["PARAMETER_MISMATCH", "MISSING_IN_DOCS", "MISSING_IN_CODE", "CONTRACT_MISMATCH"]
            cols = st.columns(4)
            for col, t in zip(cols, d_types):
                col.metric(t.replace("_", " ").title(), sum(1 for f in drift if f.drift_type.value == t))

            st.markdown("#### Overview")
            st.dataframe(
                [{
                    "ID": f.id,
                    "Severity": f"{SEV_ICON[f.severity.value]} {f.severity.value}",
                    "Type": f.drift_type.value,
                    "Route": f"{f.method} {f.endpoint}".strip(),
                    "Code says": f.code_behavior,
                    "Docs say": f.docs_behavior,
                } for f in drift],
                hide_index=True,
            )
            st.markdown("#### Details")
            for f in drift:
                render_drift_finding(f)

    # ---------------- Tab 3 ---------------- #
    with tab3:
        rem = result.remediation
        st.markdown("#### What changed")
        for item in rem.change_summary:
            st.markdown(f"- {item}")
        st.caption("Tip: use the copy icon at the top-right of any code block for one-click copy.")

        docs_ext = {"markdown": ("README.updated.md", "markdown", "text/markdown"),
                    "openapi_yaml": ("openapi.updated.yaml", "yaml", "text/yaml"),
                    "openapi_json": ("openapi.updated.json", "json", "application/json")}[rem.docs_format.value]
        backend_ext = {"python": "py", "javascript": "js", "typescript": "ts"}.get(rem.backend_language.lower(), "txt")
        backend_name = f"hardened_backend.{backend_ext}"

        t_code, t_docs, t_infra, t_diff = st.tabs(
            ["🔒 Hardened Backend", "📝 Updated Docs", "🐳 Hardened Infra", "🔍 Diff View"]
        )
        with t_code:
            code_block_with_download(rem.hardened_backend_code, rem.backend_language.lower(), backend_name)
        with t_docs:
            code_block_with_download(rem.updated_docs, docs_ext[1], docs_ext[0], docs_ext[2])
        with t_infra:
            code_block_with_download(rem.hardened_infra_config, "yaml", "hardened_infra.yml", "text/yaml")

        with t_diff:
            artifacts = {
                "📝 Docs (original vs updated)": (audit_inputs.api_docs, rem.updated_docs, "original docs", docs_ext[0]),
                "🔒 Backend code": (audit_inputs.backend_code, rem.hardened_backend_code, "original code", backend_name),
                "🐳 Infra config": (audit_inputs.infra_config, rem.hardened_infra_config, "original infra", "hardened_infra.yml"),
            }
            c_a, c_b = st.columns([2, 1])
            pick = c_a.selectbox("Artifact to compare", list(artifacts.keys()))
            mode = c_b.radio("View", ["Side-by-side", "Unified diff"], horizontal=True)
            old, new, old_name, new_name = artifacts[pick]

            if old.strip() == new.strip():
                st.info("No changes were needed for this artifact.")
            else:
                udiff = unified_diff(old, new, old_name, new_name)
                added = sum(1 for l in udiff.splitlines() if l.startswith("+") and not l.startswith("+++"))
                removed = sum(1 for l in udiff.splitlines() if l.startswith("-") and not l.startswith("---"))
                st.markdown(f"**+{added} added · -{removed} removed**")
                if mode == "Unified diff":
                    st.code(udiff, language="diff")
                else:
                    components.html(side_by_side_html(old, new, old_name, new_name), height=560, scrolling=True)
                st.download_button("⬇️ Download unified diff (.patch)", data=udiff + "\n",
                                   file_name="specguard.patch", mime="text/x-diff", key="dl_patch")
