from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: Severity
    file: str
    line: int
    column: int
    match: str
    message: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "match": self.match,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class ScanReport:
    tool: str
    version: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_run: int = 0

    @property
    def summary(self) -> dict:
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            by_severity[f.severity.value] += 1
        return {
            "files_scanned": self.files_scanned,
            "rules_run": self.rules_run,
            "findings": len(self.findings),
            "by_severity": by_severity,
        }

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
