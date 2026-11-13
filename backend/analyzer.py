"""
analyzer.py - Gemini-powered analysis for SpecGuard AI.

Three sequential, schema-constrained Gemini calls:
  1. Security & open-ends audit   -> SecurityAuditReport
  2. Documentation drift report   -> DriftReport
  3. Auto-remediation             -> RemediationBundle

Structured output is enforced with Pydantic models passed as `response_schema`.
A `time.sleep(4)` buffer separates the calls so free-tier keys do not hit 429s,
and each call retries with back-off if a 429/5xx still slips through.

Note: schema models intentionally have NO default values - the Gemini API
rejects some JSON-schema keywords (like "default") in response schemas.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Type, TypeVar

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, Field, ValidationError

from ingestor import AuditInputs, add_line_numbers

DEFAULT_MODEL = "gemini-3.8-flash"
RATE_LIMIT_SLEEP_SECONDS = 4  # buffer between API calls (free-tier friendly)
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 15

T = TypeVar("T", bound=BaseModel)
ProgressCallback = Callable[[int, int, str], None]


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class AnalyzerError(RuntimeError):
    """Generic analysis failure with a user-presentable message."""


class MissingAPIKeyError(AnalyzerError):
    pass


class InvalidAPIKeyError(AnalyzerError):
    pass


class RateLimitError(AnalyzerError):
    pass


class GeminiUnavailableError(AnalyzerError):
    """Raised when Gemini remains unavailable after retrying a server error."""


# --------------------------------------------------------------------------- #
# Output schemas
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}


class SecurityCategory(str, Enum):
    SHADOW_ENDPOINT = "SHADOW_ENDPOINT"
    ZOMBIE_ENDPOINT = "ZOMBIE_ENDPOINT"
    MISSING_AUTH = "MISSING_AUTH"
    EXPOSED_PORT = "EXPOSED_PORT"
    EXPOSED_DEBUG_PORT = "EXPOSED_DEBUG_PORT"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INSECURE_CONFIG = "INSECURE_CONFIG"


class SecurityFinding(BaseModel):
    id: str = Field(description="Sequential id such as SEC-001")
    category: SecurityCategory
    severity: Severity
    title: str = Field(description="Short, specific headline")
    location: str = Field(description="File and line(s), e.g. 'code:L58-L64' or 'infra:L7'")
    endpoint: str = Field(description="'METHOD /path' if relevant, otherwise empty string")
    port: int = Field(description="Port number if relevant, otherwise 0")
    evidence: str = Field(description="Exact snippet copied from the input proving the issue")
    risk: str = Field(description="One or two sentences on the real-world impact")
    recommendation: str = Field(description="Concrete fix")


class SecurityAuditReport(BaseModel):
    summary: str = Field(description="2-3 sentence executive summary")
    findings: list[SecurityFinding]


class DriftType(str, Enum):
    PARAMETER_MISMATCH = "PARAMETER_MISMATCH"
    MISSING_IN_DOCS = "MISSING_IN_DOCS"
    MISSING_IN_CODE = "MISSING_IN_CODE"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"


class DriftFinding(BaseModel):
    id: str = Field(description="Sequential id such as DRIFT-001")
    drift_type: DriftType
    severity: Severity
    method: str = Field(description="HTTP method or empty string")
    endpoint: str = Field(description="Route path")
    code_behavior: str = Field(description="What the code actually does (or 'not implemented')")
    docs_behavior: str = Field(description="What the docs claim (or 'not documented')")
    explanation: str = Field(description="Why this matters to API consumers")


class DriftReport(BaseModel):
    summary: str = Field(description="2-3 sentence summary of documentation health")
    findings: list[DriftFinding]


class DocsFormat(str, Enum):
    MARKDOWN = "markdown"
    OPENAPI_YAML = "openapi_yaml"
    OPENAPI_JSON = "openapi_json"


class RemediationBundle(BaseModel):
    hardened_backend_code: str = Field(description="Complete corrected backend source file")
    backend_language: str = Field(description="Language for syntax highlighting, e.g. python or javascript")
    hardened_infra_config: str = Field(description="Complete corrected infra config (compose and/or Dockerfile)")
    updated_docs: str = Field(description="Complete updated documentation matching the hardened code")
    docs_format: DocsFormat
    change_summary: list[str] = Field(description="Bullet list of the most important changes made")


@dataclass
class AuditResult:
    security: SecurityAuditReport
    drift: DriftReport
    remediation: RemediationBundle
    model: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "generated_at": self.generated_at,
            "duration_seconds": round(self.duration_seconds, 1),
            "security": self.security.model_dump(mode="json"),
            "drift": self.drift.model_dump(mode="json"),
            "remediation": self.remediation.model_dump(mode="json"),
        }


# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #
SYSTEM_INSTRUCTION = (
    "You are SpecGuard AI, a principal application-security engineer and API governance "
    "reviewer acting as a pre-deployment gatekeeper. You cross-examine backend code, "
    "infrastructure config and API documentation. Rules: (1) Report ONLY issues that are "
    "directly evidenced by the supplied inputs - never speculate or invent routes, ports or "
    "files. (2) Quote evidence verbatim. (3) Cite line numbers using the 'NNN |' prefixes. "
    "(4) Be precise and concise. (5) If nothing is wrong, return an empty findings list."
)

SECURITY_TASK = """TASK: Security & open-ends audit.

Enumerate every route in the code, then compare against the documentation and infra config.
Flag, using these categories:
- SHADOW_ENDPOINT: route exists in code but is absent from the docs (especially debug/internal/admin/test routes).
- ZOMBIE_ENDPOINT: deprecated/legacy/unused route that is still live and reachable.
- MISSING_AUTH: route that changes state or returns sensitive data without an auth dependency/middleware, OR docs claim auth is required but code does not enforce it.
- EXPOSED_DEBUG_PORT: debugger/inspector port (debugpy 5678, node inspect 9229, JDWP 5005...) published or listening on all interfaces.
- EXPOSED_PORT: other sensitive services (databases, caches, admin UIs) published to the host.
- HARDCODED_SECRET: secrets/tokens/passwords committed in code or config.
- INSECURE_CONFIG: running as root, debug mode on, :latest tags, auto-reload in prod, etc.

Severity rubric (use ONLY CRITICAL, HIGH or MEDIUM):
- CRITICAL: debug/shadow endpoints that expose secrets, env vars or admin actions; any exposed debugger port; unauthenticated state-changing endpoints.
- HIGH: databases/caches published to the host; hardcoded production secrets; unauthenticated reads of non-public data.
- MEDIUM: hygiene issues (root user, unpinned images, reload flag, missing health checks).

Merge duplicates (one finding per distinct problem). Order findings by severity."""

DRIFT_TASK = """TASK: Documentation drift analysis.

Compare the documentation to the actual code behaviour, route by route. Flag, using these types:
- PARAMETER_MISMATCH: different parameter/body-field names, types, defaults or required-ness.
- MISSING_IN_DOCS: route implemented in code but not documented.
- MISSING_IN_CODE: route documented but not implemented in code.
- CONTRACT_MISMATCH: different status codes, auth requirements or response fields.

Severity: HIGH for broken contracts or missing/phantom endpoints that would break consumers,
MEDIUM for smaller discrepancies, CRITICAL only when the drift hides a security-relevant
behaviour (e.g. docs say auth required but code has none). One finding per distinct discrepancy."""

REMEDIATION_TASK = """TASK: Auto-remediation.

Produce corrected, complete artifacts that fix every finding below:
1. hardened_backend_code - full corrected source file in the same language/framework. Remove shadow/debug routes and debugger bootstrap code, add authentication to unprotected routes, load secrets from environment variables, keep legitimate behaviour. Add brief '# SPECGUARD:' comments (use the language's comment syntax) next to each change.
2. hardened_infra_config - full corrected infra config in the same format(s) as the input (keep both compose and Dockerfile sections if both were supplied): drop debug ports, do not publish databases/caches to the host, move inline secrets to env references, run as a non-root user, pin image tags.
3. updated_docs - the full documentation rewritten so it matches the hardened code EXACTLY, in the SAME format as the input docs (markdown -> markdown, OpenAPI YAML -> OpenAPI YAML, OpenAPI JSON -> OpenAPI JSON). Preserve original structure and wording wherever it is still correct so a line diff stays small and readable. Do not document removed routes.
4. change_summary - the 4-8 most important changes as short sentences.

Return raw file contents only (no markdown fences inside the string fields)."""


def _build_context(inputs: AuditInputs) -> str:
    """Render all three inputs, with line numbers, into one prompt block."""
    return (
        f"## BACKEND CODE (framework: {inputs.code_framework})\n"
        f"```\n{add_line_numbers(inputs.backend_code)}\n```\n\n"
        f"## API DOCUMENTATION (format: {inputs.docs_format})\n"
        f"```\n{add_line_numbers(inputs.api_docs) if inputs.api_docs else '(none supplied)'}\n```\n\n"
        f"## INFRASTRUCTURE CONFIG (format: {inputs.infra_format})\n"
        f"```\n{add_line_numbers(inputs.infra_config) if inputs.infra_config else '(none supplied)'}\n```\n"
    )


# --------------------------------------------------------------------------- #
# Gemini plumbing
# --------------------------------------------------------------------------- #
def _notify(cb: Optional[ProgressCallback], step: int, total: int, message: str) -> None:
    if cb:
        try:
            cb(step, total, message)
        except Exception:  # a UI callback must never break the audit
            pass


def _mock_audit_result(
    inputs: AuditInputs,
    progress_cb: Optional[ProgressCallback] = None,
) -> AuditResult:
    """Return a deterministic, realistic audit result for demos and offline testing."""
    _notify(progress_cb, 1, 3, "Using offline demo security findings...")
    security = SecurityAuditReport(
        summary=(
            "The application exposes an internal diagnostics route and accepts order "
            "creation without authentication. Infrastructure also publishes a debugger "
            "port and contains a credential inline in configuration."
        ),
        findings=[
            SecurityFinding(
                id="SEC-001",
                category=SecurityCategory.MISSING_AUTH,
                severity=Severity.CRITICAL,
                title="Order creation is reachable without authentication",
                location="code:L18-L24",
                endpoint="POST /orders",
                port=0,
                evidence='@app.post("/orders")',
                risk="Unauthenticated callers can create orders and abuse the business workflow.",
                recommendation="Require a verified bearer token before processing order creation.",
            ),
            SecurityFinding(
                id="SEC-002",
                category=SecurityCategory.SHADOW_ENDPOINT,
                severity=Severity.CRITICAL,
                title="Internal diagnostics endpoint is publicly reachable",
                location="code:L27-L30",
                endpoint="GET /internal/debug",
                port=0,
                evidence='@app.get("/internal/debug")',
                risk="The route can expose operational details that help attackers map the service.",
                recommendation="Remove the route from production or protect it behind administrative authentication.",
            ),
            SecurityFinding(
                id="SEC-003",
                category=SecurityCategory.EXPOSED_DEBUG_PORT,
                severity=Severity.CRITICAL,
                title="Python debugger port is published to the host",
                location="infra:L12",
                endpoint="",
                port=5678,
                evidence='- "5678:5678"',
                risk="An exposed debugger may allow arbitrary code execution in the container.",
                recommendation="Remove the debugger port and disable debugger bootstrap in production.",
            ),
            SecurityFinding(
                id="SEC-004",
                category=SecurityCategory.HARDCODED_SECRET,
                severity=Severity.HIGH,
                title="Database credential is embedded in configuration",
                location="infra:L8",
                endpoint="",
                port=0,
                evidence="DATABASE_URL=postgresql://app:dev-password@db:5432/orders",
                risk="Anyone with repository access can reuse the credential against the database.",
                recommendation="Inject the connection string through a secret manager or environment reference.",
            ),
            SecurityFinding(
                id="SEC-005",
                category=SecurityCategory.INSECURE_CONFIG,
                severity=Severity.MEDIUM,
                title="Application container runs as root",
                location="infra:L15",
                endpoint="",
                port=0,
                evidence="USER root",
                risk="A service compromise would provide unnecessarily broad privileges in the container.",
                recommendation="Run the process as a dedicated non-root user.",
            ),
        ],
    )

    _notify(progress_cb, 2, 3, "Using offline demo documentation drift findings...")
    drift = DriftReport(
        summary=(
            "The documentation omits the internal diagnostics route and does not describe "
            "the authentication requirement for order creation."
        ),
        findings=[
            DriftFinding(
                id="DRIFT-001",
                drift_type=DriftType.MISSING_IN_DOCS,
                severity=Severity.HIGH,
                method="GET",
                endpoint="/internal/debug",
                code_behavior="Returns internal diagnostics from a live route.",
                docs_behavior="Not documented.",
                explanation="An undocumented live route is difficult to govern and may be exposed unintentionally.",
            ),
            DriftFinding(
                id="DRIFT-002",
                drift_type=DriftType.CONTRACT_MISMATCH,
                severity=Severity.HIGH,
                method="POST",
                endpoint="/orders",
                code_behavior="Accepts an order request without an authentication dependency.",
                docs_behavior="The API documentation says authentication is required.",
                explanation="Consumers and operators have conflicting expectations about the security boundary.",
            ),
        ],
    )

    _notify(progress_cb, 3, 3, "Building offline demo remediation artifacts...")
    remediation = RemediationBundle(
        hardened_backend_code="""from fastapi import Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import os

app = FastAPI(title="Acme Orders API")
bearer = HTTPBearer(auto_error=True)


def require_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> None:
    expected = os.environ["ORDERS_API_TOKEN"]
    if credentials.credentials != expected:
        raise PermissionError("Invalid bearer token")


@app.post("/orders", dependencies=[Depends(require_token)])
def create_order(product_id: str, quantity: int):
    return {"status": "accepted", "product_id": product_id, "quantity": quantity}


@app.get("/health")
def health():
    return {"status": "ok"}
""",
        backend_language="python",
        hardened_infra_config="""services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      ORDERS_API_TOKEN: ${ORDERS_API_TOKEN}
    user: "10001:10001"
    read_only: true

  db:
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
""",
        updated_docs="""# Acme Orders API

## POST /orders

Creates an order. Requires a bearer token in the `Authorization` header.

## GET /health

Returns `{"status": "ok"}` when the service is ready.
""",
        docs_format=DocsFormat.MARKDOWN,
        change_summary=[
            "Removed the publicly reachable internal diagnostics route.",
            "Added bearer-token authentication to order creation.",
            "Moved API and database credentials to environment references.",
            "Removed the published debugger port.",
            "Configured the container to run as a non-root user.",
            "Updated the API documentation to match the hardened routes.",
        ],
    )
    return AuditResult(
        security=security,
        drift=drift,
        remediation=remediation,
        model="offline-demo-mock",
        duration_seconds=0.1,
    )


def _parse_response(response, schema: Type[T]) -> T:
    """Turn a Gemini response into a validated Pydantic object."""
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, schema):
        return parsed

    text = (getattr(response, "text", None) or "").strip()
    if not text:
        raise AnalyzerError(
            "Gemini returned an empty response (it may have been blocked or truncated). Please retry."
        )
    if text.startswith("```"):  # defensive: strip accidental code fences
        text = text.strip("`")
        text = text[4:] if text.lower().startswith("json") else text
    try:
        return schema.model_validate_json(text.strip())
    except ValidationError as exc:
        raise AnalyzerError(
            f"Gemini output did not match the expected {schema.__name__} schema "
            f"(possibly truncated). Details: {exc.error_count()} validation error(s)."
        ) from exc


def _generate_structured(
    client: "genai.Client",
    model: str,
    prompt: str,
    schema: Type[T],
    *,
    max_output_tokens: int,
    label: str,
    step: int,
    total: int,
    progress_cb: Optional[ProgressCallback],
) -> T:
    """Call Gemini with a Pydantic response schema, retrying on 429/5xx."""
    config_kwargs = dict(
        system_instruction=SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        response_schema=schema,
        temperature=0.1,
        max_output_tokens=max_output_tokens,
    )
    if "2.5" in model:  # bounded "thinking" improves accuracy but caps latency/cost
        config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=2048)
    config = types.GenerateContentConfig(**config_kwargs)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = client.models.generate_content(model=model, contents=prompt, config=config)
            return _parse_response(response, schema)

        except genai_errors.APIError as exc:
            code = getattr(exc, "code", None)
            text = str(exc)

            if code in (401, 403) or "API key not valid" in text or "API_KEY_INVALID" in text:
                raise InvalidAPIKeyError(
                    "The Google API key was rejected. Check it at https://aistudio.google.com/apikey."
                ) from exc

            retryable = code == 429 or (isinstance(code, int) and code >= 500)
            if retryable and attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_SECONDS * attempt
                kind = "Rate limit hit" if code == 429 else f"Gemini server error {code}"
                _notify(progress_cb, step, total, f"{kind} during {label}; retrying in {wait}s "
                                                  f"(attempt {attempt}/{MAX_RETRIES})...")
                time.sleep(wait)
                continue
            if code == 429:
                raise RateLimitError(
                    "Gemini free-tier quota exceeded. Wait a minute and retry, or switch to a lighter model."
                ) from exc
            if code == 503:
                raise GeminiUnavailableError(
                    f"Gemini is temporarily unavailable during {label}. "
                    "Enable Offline / Demo Mock Mode to continue without the live API."
                ) from exc
            raise AnalyzerError(f"Gemini API error ({code}) during {label}: {text[:300]}") from exc

        except AnalyzerError:
            raise
        except Exception as exc:  # network failure, SDK bug, etc.
            raise AnalyzerError(f"Unexpected failure during {label}: {exc}") from exc

    raise AnalyzerError(f"{label} failed after {MAX_RETRIES} attempts.")  # pragma: no cover


# --------------------------------------------------------------------------- #
# Individual analysis passes
# --------------------------------------------------------------------------- #
def audit_security(client, inputs: AuditInputs, model: str, progress_cb=None, step=1, total=3) -> SecurityAuditReport:
    prompt = f"{SECURITY_TASK}\n\n{_build_context(inputs)}"
    report = _generate_structured(
        client, model, prompt, SecurityAuditReport,
        max_output_tokens=16384, label="security audit", step=step, total=total, progress_cb=progress_cb,
    )
    report.findings.sort(key=lambda f: SEVERITY_RANK[f.severity])
    for i, finding in enumerate(report.findings, start=1):  # deterministic ids
        finding.id = f"SEC-{i:03d}"
    return report


def analyze_drift(client, inputs: AuditInputs, model: str, progress_cb=None, step=2, total=3) -> DriftReport:
    prompt = f"{DRIFT_TASK}\n\n{_build_context(inputs)}"
    report = _generate_structured(
        client, model, prompt, DriftReport,
        max_output_tokens=16384, label="drift analysis", step=step, total=total, progress_cb=progress_cb,
    )
    report.findings.sort(key=lambda f: SEVERITY_RANK[f.severity])
    for i, finding in enumerate(report.findings, start=1):
        finding.id = f"DRIFT-{i:03d}"
    return report


def generate_remediation(
    client, inputs: AuditInputs, security: SecurityAuditReport, drift: DriftReport,
    model: str, progress_cb=None, step=3, total=3,
) -> RemediationBundle:
    prompt = (
        f"{REMEDIATION_TASK}\n\n"
        f"## SECURITY FINDINGS TO FIX\n{security.model_dump_json(indent=1)}\n\n"
        f"## DRIFT FINDINGS TO FIX\n{drift.model_dump_json(indent=1)}\n\n"
        # Original files are sent WITHOUT line numbers so the model copies them cleanly.
        f"## ORIGINAL BACKEND CODE (framework: {inputs.code_framework})\n```\n{inputs.backend_code}\n```\n\n"
        f"## ORIGINAL DOCS (format: {inputs.docs_format})\n```\n{inputs.api_docs or '(none supplied)'}\n```\n\n"
        f"## ORIGINAL INFRA CONFIG (format: {inputs.infra_format})\n```\n{inputs.infra_config or '(none supplied)'}\n```\n"
    )
    return _generate_structured(
        client, model, prompt, RemediationBundle,
        max_output_tokens=32768, label="auto-remediation", step=step, total=total, progress_cb=progress_cb,
    )


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def run_full_audit(
    inputs: AuditInputs,
    api_key: str,
    model: str = DEFAULT_MODEL,
    progress_cb: Optional[ProgressCallback] = None,
    mock_mode: bool = False,
) -> AuditResult:
    """Run all three Gemini passes sequentially with a rate-limit buffer."""
    if mock_mode:
        return _mock_audit_result(inputs, progress_cb)
    if not api_key or not api_key.strip():
        raise MissingAPIKeyError("No Google API key provided.")

    try:
        client = genai.Client(api_key=api_key.strip())
        total = 3
        started = time.time()

        _notify(progress_cb, 1, total, "Auditing security posture & shadow endpoints...")
        security = audit_security(client, inputs, model, progress_cb, 1, total)

        time.sleep(RATE_LIMIT_SLEEP_SECONDS)  # free-tier 429 buffer

        _notify(progress_cb, 2, total, "Cross-checking code against documentation...")
        drift = analyze_drift(client, inputs, model, progress_cb, 2, total)

        time.sleep(RATE_LIMIT_SLEEP_SECONDS)  # free-tier 429 buffer

        _notify(progress_cb, 3, total, "Generating hardened code, infra and updated docs...")
        remediation = generate_remediation(client, inputs, security, drift, model, progress_cb, 3, total)

        return AuditResult(
            security=security,
            drift=drift,
            remediation=remediation,
            model=model,
            duration_seconds=time.time() - started,
        )
    except GeminiUnavailableError:
        if not mock_mode:
            raise
        _notify(progress_cb, 1, 3, "Gemini unavailable; switching to offline demo results...")
        return _mock_audit_result(inputs, progress_cb)
