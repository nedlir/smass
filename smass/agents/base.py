"""Shared agent pieces: the scanner base class, finding normalization, and the
single LLM-call helper. LLM agents do not inherit ScannerAgent; they call run_llm.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .. import ledger

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

# How long to wait for a scan that MCPwner backgrounded (returns after ~50s).
_REPORT_POLL_ATTEMPTS = 60
_REPORT_POLL_SECONDS = 5


@dataclass
class AgentResult:
    name: str
    findings: list = field(default_factory=list)
    skipped: bool = False
    note: str = ""


def _repo_relative(path: str) -> str:
    # MCPwner copies the source to /workspaces/<id>/source; report it repo-relative.
    # Grype reports paths rooted at the scan dir ("/requirements.txt").
    marker = "/source/"
    path = path.split(marker, 1)[1] if marker in path else path
    return path.lstrip("/")


def _as_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def normalize_finding(raw: dict, agent: str = "") -> dict:
    return {
        "tool": raw.get("tool", ""),
        "rule_id": raw.get("rule_id") or raw.get("ruleId") or "",
        "severity": str(raw.get("severity") or "info").lower(),
        "file": _repo_relative(raw.get("file") or ""),
        "line": _as_int(raw.get("line")),
        "message": raw.get("message") or "",
        "snippet": raw.get("snippet") or "",
        "agent": agent,
    }


def parse_sarif(raw, agent: str = "") -> list[dict]:
    """Normalize a scanner report into findings.

    MCPwner's get_<cat>_report returns the tool's own report under a `sarif` key,
    and the shape is tool-dependent, so this handles several:
      - a list (e.g. several trufflehog findings): parse each
      - a SARIF document ({"runs": [...]}, e.g. semgrep/gitleaks)
      - a {"findings": [...]} shape (already close to normalized)
      - a single trufflehog finding object ({"SourceMetadata", "DetectorName", ...})
    """
    if isinstance(raw, list):
        out: list[dict] = []
        for item in raw:
            out.extend(parse_sarif(item, agent))
        return out
    if not isinstance(raw, dict) or not raw:
        return []
    if "SourceMetadata" in raw or "DetectorName" in raw:
        return [_normalize_trufflehog(raw, agent)]
    if "findings" in raw:
        return [normalize_finding(f, agent) for f in (raw.get("findings") or [])
                if isinstance(f, dict)]

    out = []
    for run in raw.get("runs", []):
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        tool = driver.get("name", "")
        rules = driver.get("rules", []) or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results", []):
            loc = ((res.get("locations") or [{}])[0] or {}).get("physicalLocation", {})
            uri = (loc.get("artifactLocation", {}) or {}).get("uri", "")
            line = (loc.get("region", {}) or {}).get("startLine", 0)
            rule = by_id.get(res.get("ruleId"))
            idx = res.get("ruleIndex")
            if rule is None and isinstance(idx, int) and 0 <= idx < len(rules):
                rule = rules[idx]
            out.append(
                normalize_finding(
                    {
                        "tool": tool,
                        "rule_id": res.get("ruleId", ""),
                        "severity": _sarif_severity(res, rule),
                        "file": uri,
                        "line": line,
                        "message": (res.get("message", {}) or {}).get("text", ""),
                    },
                    agent,
                )
            )
    return out


def _sarif_severity(res: dict, rule: dict | None) -> str:
    rule = rule or {}
    for props in (res.get("properties") or {}, rule.get("properties") or {}):
        score = _sev_from_score(props.get("security-severity"))
        if score:
            return score
        if props.get("severity"):
            return str(props["severity"]).lower()
    # In SARIF a result with no level inherits the rule's default level; semgrep
    # relies on this, so an unresolved level must fall back to the rule.
    level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _SARIF_LEVEL.get(level or "warning", "medium")


def _sev_from_score(value) -> str | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def normalize_severity(value) -> str:
    """Map a tool's severity (a word, a SARIF level, or a numeric score) to one of
    critical/high/medium/low/info; default medium for anything unrecognized."""
    text = str(value or "").lower()
    if text in SEVERITY_ORDER:
        return text
    score = _sev_from_score(value)
    if score:
        return score
    return _SARIF_LEVEL.get(text, "medium")


def _normalize_trufflehog(obj: dict, agent: str = "") -> dict:
    """Map a trufflehog native finding to smass's normalized shape."""
    data = (obj.get("SourceMetadata", {}) or {}).get("Data", {}) or {}
    loc = data.get("Filesystem") or data.get("Git") or {}
    detector = obj.get("DetectorName", "secret")
    verified = bool(obj.get("Verified", False))
    return normalize_finding(
        {
            "tool": "trufflehog",
            "rule_id": detector,
            "severity": "critical" if verified else "high",
            "file": loc.get("file", ""),
            "line": loc.get("line", 0),
            "message": f"{detector} secret ({'verified' if verified else 'unverified'})",
            "snippet": obj.get("Redacted", ""),
        },
        agent,
    )


def ledger_finding(f: dict, finding_id: str, status: str = "hypothesis") -> dict:
    """Map a normalized finding to an MCPwner ledger entry (needs id + status)."""
    return {
        "id": finding_id,
        "status": status,
        "severity": f.get("severity", "info"),
        "title": (f.get("message") or f.get("rule_id") or "finding")[:120],
        "discovery_lane": f.get("agent", ""),
        "sink_loc": {"file": f.get("file", ""), "line": f.get("line", 0)},
        "rule_id": f.get("rule_id", ""),
        "tool": f.get("tool", ""),
        "evidence": {"snippet": f.get("snippet", "")},
    }


def _report_body(report: dict):
    # MCPwner puts the report under "sarif" only when it is a dict; a list report
    # (e.g. trufflehog with several findings) lands in "report_content".
    return report.get("sarif") or report.get("report_content") or {}


def upsert_findings(client, workspace_id: str, findings: list[dict], lane: str) -> None:
    """Assign an id to each finding, tag it on the finding, and write the ledger."""
    for i, f in enumerate(findings):
        fid = f.get("id") or f"{lane}-{i + 1}"
        f["id"] = fid
        ledger.upsert(client, workspace_id, ledger_finding(f, fid))


class ScannerAgent:
    """Run one MCPwner scanner: scan, fetch the SARIF report, normalize, upsert.

    MCPwner scan tools take the specific `tool` to run and return a count plus a
    report path (not inline findings); the SARIF itself comes from the matching
    `get_<category>_report` tool.
    """

    category: str = ""
    name: str = ""

    def __init__(self, cfg=None):
        self.cfg = cfg

    def scanner(self) -> str | None:
        return getattr(self.cfg, f"{self.category}_tool", None) if self.cfg else None

    def run(self, client, workspace_id: str) -> AgentResult:
        tool = self.scanner()
        if not tool:
            return AgentResult(self.name, [], skipped=True, note="no tool configured")
        scan = client.call(
            f"run_{self.category}_scan", tool=tool, workspace_id=workspace_id, config=None
        )
        status = scan.get("status")
        if status not in ("success", "backgrounded"):
            return AgentResult(
                self.name, [], skipped=True,
                note=scan.get("error") or f"{tool} unavailable",
            )
        findings = fetch_report_findings(
            client, self.category, tool, workspace_id, self.name,
            poll=(status == "backgrounded"),
        )
        upsert_findings(client, workspace_id, findings, self.name)
        return AgentResult(self.name, findings, note=f"{tool}: {len(findings)}")


def fetch_report_findings(client, category, tool, workspace_id, agent, poll):
    """Fetch and parse a scanner's report. MCPwner returns 'backgrounded' for a
    scan over ~50s and writes the report later, so poll until it is ready."""
    report: dict = {}
    attempts = _REPORT_POLL_ATTEMPTS if poll else 1
    for i in range(attempts):
        report = client.call(f"get_{category}_report", tool=tool, workspace_id=workspace_id)
        if report.get("status") == "success" or not poll or i == attempts - 1:
            break
        time.sleep(_REPORT_POLL_SECONDS)
    return parse_sarif(_report_body(report), agent)


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(block.get("text", ""))
            else:
                parts.append(getattr(block, "text", ""))
        return "".join(parts)
    return str(content)


def run_llm(cfg, model: str, system: str, user: str) -> str:
    """One LLM call through LangChain.

    Provider-agnostic: uses the Anthropic- or OpenAI-compatible interface against
    whatever endpoint `llm_base_url` names (the default provider when unset), with
    the user's API key. The client is imported lazily so a scanner-only run never
    imports it.
    """
    if not cfg.llm_api_key:
        raise RuntimeError(
            "No LLM API key: set SMASS_LLM_API_KEY (or ANTHROPIC_API_KEY)"
        )
    from langchain_core.messages import HumanMessage, SystemMessage

    llm = _build_chat(cfg, model)
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
    return _text(resp.content)


def _build_chat(cfg, model: str):
    """Construct the LangChain chat client for the configured interface."""
    if cfg.llm_api == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model,
            api_key=cfg.llm_api_key,
            base_url=cfg.llm_base_url,
            max_tokens=8000,
            timeout=180,
        )

    from langchain_anthropic import ChatAnthropic

    kwargs = dict(model=model, api_key=cfg.llm_api_key, max_tokens=8000, timeout=180)
    if cfg.llm_base_url:
        kwargs["base_url"] = cfg.llm_base_url
    return ChatAnthropic(**kwargs)
