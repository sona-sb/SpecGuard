"""
validator.py - Deterministic Pre-Deploy Gatekeeper Verdict Engine.

No LLM is involved here. The verdict is computed from explicit, auditable rules
applied to the findings produced by analyzer.py, plus a small regex "static
cross-check" that catches obvious debug-port exposure even if the LLM misses it.

Rules
-----
BLOCK-1  any CRITICAL security finding
BLOCK-2  any shadow / zombie endpoint
BLOCK-3  any exposed debug port
WARN-1   HIGH / MEDIUM security findings (non-blocking)
WARN-2   any documentation drift (non-blocking)
PASS     no findings at all: clean and fully synchronised
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from analyzer import (
    SEVERITY_RANK,
    DriftReport,
    SecurityAuditReport,
    SecurityCategory,
    SecurityFinding,
    Severity,
)
from ingestor import AuditInputs

# Well-known debugger / inspector ports.
DEBUG_PORTS = {
    5678: "debugpy",
    9229: "Node.js inspector",
    9230: "Node.js inspector (alt)",
    5858: "Node.js legacy debugger",
    5005: "Java JDWP",
}

_PORT_PAIR = re.compile(r"(?<![\d.])(\d{2,5}):(\d{2,5})(?![\d:])")
_DEBUGPY_LISTEN = re.compile(r"debugpy\.listen\(\s*\(?\s*['\"]([\w.]*)['\"]\s*,\s*(\d+)")
_NODE_INSPECT = re.compile(r"--inspect(?:-brk)?=0\.0\.0\.0:(\d+)")
_FLASK_DEBUG = re.compile(r"\.run\([^)]*debug\s*=\s*True")


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class VerdictResult:
    verdict: Verdict
    headline: str
    reasons: list[str]
    triggered_rules: list[str]
    blocking_findings: list[SecurityFinding]
    security_findings: list[SecurityFinding]  # LLM findings + static cross-check, sorted
    counts: dict[str, int]
    drift_count: int
    static_findings_added: int = 0

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "headline": self.headline,
            "reasons": self.reasons,
            "triggered_rules": self.triggered_rules,
            "counts": self.counts,
            "drift_count": self.drift_count,
            "static_findings_added": self.static_findings_added,
            "blocking_finding_ids": [f.id for f in self.blocking_findings],
        }


# --------------------------------------------------------------------------- #
# Static cross-check (deterministic safety net)
# --------------------------------------------------------------------------- #
def _has_debug_port_finding(findings: list[SecurityFinding], port: int) -> bool:
    return any(
        f.port == port and f.category in (SecurityCategory.EXPOSED_DEBUG_PORT, SecurityCategory.EXPOSED_PORT)
        for f in findings
    )


def static_crosscheck(inputs: AuditInputs, existing: list[SecurityFinding]) -> list[SecurityFinding]:
    """Regex scan for debug exposure the LLM may have missed. Only adds NEW findings."""
    found: list[SecurityFinding] = []
    known = list(existing)

    def add(**kw) -> None:
        finding = SecurityFinding(id=f"STATIC-{len(found) + 1:03d}", endpoint="", **kw)
        found.append(finding)
        known.append(finding)

    # 1) Published / exposed debug ports in compose + Dockerfile.
    for n, line in enumerate(inputs.infra_config.split("\n"), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        ports: set[int] = set()
        if stripped.startswith("-") or "ports" in stripped:
            for host, container in _PORT_PAIR.findall(stripped):
                ports.update({int(host), int(container)})
        expose = re.match(r"EXPOSE\s+(.*)", stripped)
        if expose:
            ports.update(int(p) for p in re.findall(r"\d+", expose.group(1)))
        for port in sorted(ports & DEBUG_PORTS.keys()):
            if _has_debug_port_finding(known, port):
                continue
            add(
                category=SecurityCategory.EXPOSED_DEBUG_PORT,
                severity=Severity.CRITICAL,
                title=f"Debug port {port} ({DEBUG_PORTS[port]}) is exposed",
                location=f"infra:L{n}",
                port=port,
                evidence=stripped,
                risk="A reachable debugger allows remote code execution inside the container.",
                recommendation="Remove the port mapping/EXPOSE and disable the debugger in deployed builds.",
            )

    # 2) Debuggers bound to all interfaces inside the application code.
    for n, line in enumerate(inputs.backend_code.split("\n"), start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//")):
            continue
        m = _DEBUGPY_LISTEN.search(stripped)
        if m and m.group(1) in ("0.0.0.0", ""):
            port = int(m.group(2))
            if not _has_debug_port_finding(known, port):
                add(
                    category=SecurityCategory.EXPOSED_DEBUG_PORT,
                    severity=Severity.CRITICAL,
                    title=f"debugpy listening on all interfaces (port {port})",
                    location=f"code:L{n}",
                    port=port,
                    evidence=stripped,
                    risk="Anyone who can reach this port can execute arbitrary code in the process.",
                    recommendation="Remove debugpy from production code or bind to 127.0.0.1 behind a flag.",
                )
        m = _NODE_INSPECT.search(stripped)
        if m and not _has_debug_port_finding(known, int(m.group(1))):
            add(
                category=SecurityCategory.EXPOSED_DEBUG_PORT,
                severity=Severity.CRITICAL,
                title=f"Node inspector bound to 0.0.0.0:{m.group(1)}",
                location=f"code:L{n}",
                port=int(m.group(1)),
                evidence=stripped,
                risk="The inspector protocol grants full remote code execution.",
                recommendation="Never bind --inspect to all interfaces; remove it from deployed builds.",
            )
        if _FLASK_DEBUG.search(stripped):
            add(
                category=SecurityCategory.INSECURE_CONFIG,
                severity=Severity.CRITICAL,
                title="Flask debug mode enabled (Werkzeug debugger)",
                location=f"code:L{n}",
                port=0,
                evidence=stripped,
                risk="The interactive Werkzeug debugger permits remote code execution.",
                recommendation="Run with debug=False and use a production WSGI server.",
            )
    return found


# --------------------------------------------------------------------------- #
# Verdict engine
# --------------------------------------------------------------------------- #
def _titles(findings: list[SecurityFinding], limit: int = 3) -> str:
    names = [f.title for f in findings[:limit]]
    extra = len(findings) - limit
    return "; ".join(names) + (f" (+{extra} more)" if extra > 0 else "")


def evaluate(security: SecurityAuditReport, drift: DriftReport, inputs: Optional[AuditInputs] = None) -> VerdictResult:
    """Apply the deterministic rule set and return the gatekeeper verdict."""
    findings = list(security.findings)
    added = static_crosscheck(inputs, findings) if inputs is not None else []
    findings += added
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.id))

    counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    shadow = [f for f in findings if f.category in (SecurityCategory.SHADOW_ENDPOINT, SecurityCategory.ZOMBIE_ENDPOINT)]
    debug_ports = [f for f in findings if f.category == SecurityCategory.EXPOSED_DEBUG_PORT]
    non_blocking = [f for f in findings if f.severity != Severity.CRITICAL]

    reasons: list[str] = []
    rules: list[str] = []
    blocking: list[SecurityFinding] = []

    if critical:
        rules.append("BLOCK-1")
        reasons.append(f"BLOCK-1: {len(critical)} CRITICAL security finding(s) - {_titles(critical)}")
    if shadow:
        rules.append("BLOCK-2")
        reasons.append(f"BLOCK-2: {len(shadow)} shadow/zombie endpoint(s) detected - {_titles(shadow)}")
    if debug_ports:
        rules.append("BLOCK-3")
        reasons.append(f"BLOCK-3: {len(debug_ports)} exposed debug port(s) - {_titles(debug_ports)}")
    for f in critical + shadow + debug_ports:
        if f not in blocking:
            blocking.append(f)

    if blocking:
        verdict = Verdict.BLOCK
        headline = "DEPLOYMENT BLOCKED"
    else:
        if non_blocking:
            rules.append("WARN-1")
            reasons.append(f"WARN-1: {len(non_blocking)} HIGH/MEDIUM finding(s) should be reviewed")
        if drift.findings:
            rules.append("WARN-2")
            reasons.append(f"WARN-2: {len(drift.findings)} documentation drift issue(s) found")
        if rules:
            verdict = Verdict.WARN
            headline = "PASS WITH WARNINGS"
        else:
            verdict = Verdict.PASS
            headline = "SAFE TO DEPLOY"
            reasons.append("No security findings and documentation is fully synchronised with the code.")

    # Rank-ordered so the most severe appear first in the UI.
    blocking.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.id))

    return VerdictResult(
        verdict=verdict,
        headline=headline,
        reasons=reasons,
        triggered_rules=rules,
        blocking_findings=blocking,
        security_findings=findings,
        counts=counts,
        drift_count=len(drift.findings),
        static_findings_added=len(added),
    )
