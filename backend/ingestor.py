"""
ingestor.py - Input ingestion & cleaning for SpecGuard AI.

Responsibilities
----------------
* Normalise the three audit inputs (backend code, API docs, infra config).
* Decode uploaded files safely (UTF-8 first, Latin-1 fallback, reject binaries).
* Detect formats/frameworks so the analyzer can tailor its prompts.
* Provide `load_demo_sample()` - a realistic, intentionally broken project
  that can be audited with a single click.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import yaml

# Hard cap per input. Keeps prompts well inside free-tier token budgets.
MAX_CHARS_PER_INPUT = 60_000
# Reject absurdly large uploads before decoding.
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


class IngestionError(ValueError):
    """Raised when an input cannot be used (empty, binary, too large...)."""


@dataclass
class AuditInputs:
    """Cleaned, validated bundle handed to the analyzer."""

    backend_code: str
    api_docs: str
    infra_config: str
    code_framework: str = "unknown"
    docs_format: str = "markdown"  # markdown | openapi-yaml | openapi-json | none
    infra_format: str = "unknown"
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Cleaning helpers
# --------------------------------------------------------------------------- #
def decode_bytes(data: bytes) -> str:
    """Decode raw bytes to text, rejecting obvious binary content."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise IngestionError(
            f"File is larger than {MAX_UPLOAD_BYTES // 1024} KB - please upload a smaller file."
        )
    if b"\x00" in data[:4096]:
        raise IngestionError("File looks binary, not text. Please upload a source/config file.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def read_uploaded_file(name: str, data: bytes) -> str:
    """Decode an uploaded file (Streamlit UploadedFile.getvalue())."""
    text = decode_bytes(data)
    if not text.strip():
        raise IngestionError(f"'{name}' is empty.")
    return text


def clean_text(raw: str | bytes | None, max_chars: int = MAX_CHARS_PER_INPUT, label: str = "input"):
    """Normalise newlines, strip control chars/trailing spaces, enforce size cap.

    Returns (clean_text, notes).
    """
    notes: list[str] = []
    if raw is None:
        return "", notes
    if isinstance(raw, bytes):
        raw = decode_bytes(raw)

    text = raw.replace("\ufeff", "").replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.split("\n")).strip("\n")

    if len(text) > max_chars:
        text = text[:max_chars]
        notes.append(f"{label} was truncated to {max_chars:,} characters.")
    return text, notes


def add_line_numbers(text: str) -> str:
    """Prefix each line with its number so the LLM can cite exact locations."""
    return "\n".join(f"{i:>4} | {line}" for i, line in enumerate(text.split("\n"), start=1))


# --------------------------------------------------------------------------- #
# Format / framework detection
# --------------------------------------------------------------------------- #
def detect_code_framework(code: str) -> str:
    if re.search(r"from\s+fastapi|import\s+fastapi|FastAPI\(", code):
        return "python-fastapi"
    if re.search(r"from\s+flask|import\s+flask|Flask\(", code):
        return "python-flask"
    if re.search(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]|express\(\)", code):
        return "node-express"
    return "unknown"


def detect_docs_format(docs: str) -> str:
    stripped = docs.lstrip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(docs)
            if isinstance(obj, dict) and ("openapi" in obj or "swagger" in obj):
                return "openapi-json"
        except json.JSONDecodeError:
            pass
    if re.search(r"^\s*(openapi|swagger)\s*:", docs, flags=re.MULTILINE):
        return "openapi-yaml"
    return "markdown"


def detect_infra_format(infra: str) -> str:
    has_compose = bool(re.search(r"^\s*services\s*:", infra, flags=re.MULTILINE))
    has_dockerfile = bool(re.search(r"^\s*FROM\s+\S+", infra, flags=re.MULTILINE))
    if has_compose and has_dockerfile:
        return "dockerfile+compose"
    if has_compose:
        return "docker-compose"
    if has_dockerfile:
        return "dockerfile"
    return "unknown"


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def ingest(backend_code: str, api_docs: str, infra_config: str) -> AuditInputs:
    """Clean + validate the three inputs and return an `AuditInputs` bundle."""
    warnings: list[str] = []

    code, notes = clean_text(backend_code, label="Backend code")
    warnings += notes
    docs, notes = clean_text(api_docs, label="API docs")
    warnings += notes
    infra, notes = clean_text(infra_config, label="Infra config")
    warnings += notes

    if not code:
        raise IngestionError("Backend code is empty - paste code or load the demo sample.")
    if not docs:
        warnings.append("No API documentation supplied - every route will be reported as undocumented.")
    if not infra:
        warnings.append("No infrastructure config supplied - port exposure cannot be audited.")

    docs_format = detect_docs_format(docs) if docs else "none"
    if docs_format == "openapi-yaml":
        try:
            yaml.safe_load(docs)
        except yaml.YAMLError as exc:
            first_line = str(exc).splitlines()[0] if str(exc) else "unknown error"
            warnings.append(f"OpenAPI YAML does not parse cleanly ({first_line}).")

    return AuditInputs(
        backend_code=code,
        api_docs=docs,
        infra_config=infra,
        code_framework=detect_code_framework(code),
        docs_format=docs_format,
        infra_format=detect_infra_format(infra) if infra else "none",
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Demo sample: a realistic, deliberately broken & drifted application
# --------------------------------------------------------------------------- #
_DEMO_BACKEND = '''# main.py - Acme Orders API (FastAPI)
import os
import debugpy
from typing import Optional

from fastapi import FastAPI, Depends, Header, HTTPException, Query
from pydantic import BaseModel

SECRET_KEY = "acme-prod-secret-key-2023"   # TODO: move to env
ADMIN_RESET_TOKEN = "letmein"

app = FastAPI(title="Acme Orders API", version="1.4.0")

# Remote debugger left on "for easier troubleshooting in staging"
if os.getenv("ENABLE_DEBUGGER", "true") == "true":
    debugpy.listen(("0.0.0.0", 5678))


def verify_token(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    if token != SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid token")
    return {"sub": "service-account"}


class OrderIn(BaseModel):
    customer_id: int
    sku: str
    quantity: int
    coupon_code: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/v1/users")
def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, le=100),
    user: dict = Depends(verify_token),
):
    return {"page": page, "page_size": page_size, "items": []}


@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int, user: dict = Depends(verify_token)):
    return {"id": user_id, "email": f"user{user_id}@acme.io"}


@app.post("/api/v1/orders")
def create_order(order: OrderIn):
    # NOTE: no auth dependency - anyone can create orders
    return {"order_id": 9001, "status": "created", "sku": order.sku}


@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: int, user: dict = Depends(verify_token)):
    return {"order_id": order_id, "status": "shipped"}


@app.get("/debug/config")
def debug_config():
    # Handy during development...
    return {
        "env": dict(os.environ),
        "secret_key": SECRET_KEY,
        "database_url": os.getenv("DATABASE_URL"),
    }


@app.post("/internal/admin/reset-cache")
def reset_cache(token: str = Query(...)):
    if token == ADMIN_RESET_TOKEN:
        return {"cache": "cleared"}
    raise HTTPException(status_code=403, detail="Nope")
'''

_DEMO_DOCS = '''# Acme Orders API

Base URL: `https://api.acme.io`

## Authentication

All endpoints **except** `GET /health` require a `Authorization: Bearer <token>` header.

## Endpoints

### GET /health
Liveness probe. Returns `{"status": "ok"}`.

### GET /api/v1/users
List users.

| Param    | Type | Default | Description          |
|----------|------|---------|----------------------|
| `limit`  | int  | 50      | Max rows to return   |
| `offset` | int  | 0       | Rows to skip         |

### GET /api/v1/users/{user_id}
Fetch a single user.

Response: `{"id": 1, "email": "a@b.com", "name": "Ada"}`

### DELETE /api/v1/users/{user_id}
Delete a user. Returns `204 No Content`.

### POST /api/v1/orders
Create an order. Requires Bearer auth.

Body:

```json
{"customer_id": 1, "sku": "ABC-1", "qty": 2}
```

Response: `201 Created` with `{"order_id": 123, "status": "created"}`

### GET /api/v1/orders/{order_id}
Fetch an order by ID.

### GET /api/v1/products
List the product catalogue (paginated).
'''

_DEMO_INFRA = '''# ---------------- docker-compose.yml ----------------
version: "3.9"
services:
  api:
    build: .
    ports:
      - "8000:8000"
      - "5678:5678"   # debugpy
    environment:
      - DATABASE_URL=postgresql://acme:acme@db:5432/orders
      - ENABLE_DEBUGGER=true
      - SECRET_KEY=acme-prod-secret-key-2023
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
    depends_on: [db]

  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: acme
      POSTGRES_PASSWORD: acme
      POSTGRES_DB: orders

  redis:
    image: redis:latest
    ports: ["6379:6379"]

# ---------------- Dockerfile ----------------
FROM python:3.11
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8000 5678
USER root
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
'''


def load_demo_sample() -> dict[str, str]:
    """Return a pre-packaged broken/drifted app for one-click testing.

    Planted problems:
      * Shadow debug route        -> GET  /debug/config (dumps env + secrets)
      * Shadow internal route     -> POST /internal/admin/reset-cache (weak token)
      * Unauthenticated endpoint  -> POST /api/v1/orders (docs claim Bearer auth)
      * Exposed debug port        -> 5678 (debugpy) in compose + Dockerfile
      * Other infra smells        -> Postgres/Redis published, runs as root, secrets inline
      * Docs drift                -> limit/offset vs page/page_size, qty vs quantity,
                                     DELETE user & GET /products not implemented,
                                     missing `name` field, 201 vs 200
    """
    return {
        "backend_code": _DEMO_BACKEND,
        "api_docs": _DEMO_DOCS,
        "infra_config": _DEMO_INFRA,
    }
