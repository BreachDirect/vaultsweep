import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from vaultsweep.models import Finding, Severity


@dataclass
class RuleMeta:
    rule_id: str
    name: str
    severity: Severity
    description: str
    remediation: str


class Rule(ABC):
    meta: RuleMeta

    @abstractmethod
    def scan_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        ...

    def _finding(
        self,
        file_path: str,
        line_no: int,
        column: int,
        match: str,
        message: str | None = None,
    ) -> Finding:
        display = match if len(match) <= 60 else match[:30] + "…" + match[-8:]
        return Finding(
            rule_id=self.meta.rule_id,
            name=self.meta.name,
            severity=self.meta.severity,
            file=file_path,
            line=line_no,
            column=column,
            match=display,
            message=message or self.meta.description,
            remediation=self.meta.remediation,
        )


class RegexRule(Rule):
    pattern: re.Pattern[str]
    min_length: int = 1

    def scan_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in self.pattern.finditer(line):
            matched = m.group(0)
            if len(matched) < self.min_length:
                continue
            if self._is_false_positive(line, matched):
                continue
            findings.append(
                self._finding(file_path, line_no, m.start() + 1, matched)
            )
        return findings

    def _is_false_positive(self, line: str, matched: str) -> bool:
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return True
        if "example" in line.lower() or "placeholder" in line.lower():
            return True
        return False
