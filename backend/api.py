"""FastAPI adapter for the SpecGuard audit pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Keep the existing modules importable when this file is started as either
# `uvicorn api:app` from backend/ or `uvicorn backend.api:app` from the root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import (  # noqa: E402
    AnalyzerError,
    DEFAULT_MODEL,
    InvalidAPIKeyError,
    MissingAPIKeyError,
    RateLimitError,
    run_full_audit,
)
from ingestor import IngestionError, ingest, load_demo_sample  # noqa: E402
from validator import evaluate  # noqa: E402


class AuditRequest(BaseModel):
    api_key: str = Field(default="", description="Google Gemini API key")
    mock_mode: bool = False
    backend_code: str
    api_docs: str = ""
    infra_config: str = ""
    model: str = DEFAULT_MODEL


app = FastAPI(title="SpecGuard API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/demo-sample")
def demo_sample() -> dict[str, str]:
    """Return the built-in intentionally broken sample application."""
    return load_demo_sample()


@app.post("/audit")
def audit(request: AuditRequest) -> dict:
    """Run ingestion, analysis, remediation, and deterministic validation."""
    try:
        inputs = ingest(request.backend_code, request.api_docs, request.infra_config)
        result = run_full_audit(
            inputs,
            request.api_key,
            model=request.model,
            mock_mode=request.mock_mode,
        )
        verdict = evaluate(result.security, result.drift, inputs)
    except IngestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (MissingAPIKeyError, InvalidAPIKeyError, RateLimitError, AnalyzerError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "verdict": verdict.to_dict(),
        **result.to_dict(),
        "warnings": inputs.warnings,
        "input_meta": {
            "code_framework": inputs.code_framework,
            "docs_format": inputs.docs_format,
            "infra_format": inputs.infra_format,
        },
    }
