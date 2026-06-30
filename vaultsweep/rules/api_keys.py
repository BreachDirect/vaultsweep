import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

_PATTERNS: list[tuple[str, str, Severity, str, str]] = [
    (
        "API-001",
        "Anthropic API Key",
        Severity.CRITICAL,
        r"sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}",
        "Revoke at console.anthropic.com and use ANTHROPIC_API_KEY env var.",
    ),
    (
        "API-002",
        "GitHub Token",
        Severity.CRITICAL,
        r"ghp_[A-Za-z0-9]{36,}",
        "Revoke at GitHub Settings → Developer settings → Tokens.",
    ),
    (
        "API-003",
        "GitHub OAuth Token",
        Severity.CRITICAL,
        r"gho_[A-Za-z0-9]{36,}",
        "Revoke at GitHub Settings → Developer settings → Tokens.",
    ),
    (
        "API-004",
        "AWS Access Key",
        Severity.HIGH,
        r"AKIA[0-9A-Z]{16}",
        "Rotate in AWS IAM and use instance roles or secrets manager.",
    ),
    (
        "API-005",
        "Generic Bearer Secret",
        Severity.MEDIUM,
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        "Move secrets to environment variables or a secrets manager.",
    ),
]


def _make_rule(
    rule_id: str, name: str, severity: Severity, pattern: str, remediation: str
) -> RegexRule:
    class _Rule(RegexRule):
        meta = RuleMeta(
            rule_id=rule_id,
            name=name,
            severity=severity,
            description=f"{name} detected in source.",
            remediation=remediation,
        )
        compiled = re.compile(pattern)

        def scan_line(self, file_path: str, line_no: int, line: str) -> list:
            findings = []
            for m in self.compiled.finditer(line):
                matched = m.group(0)
                if self._is_false_positive(line, matched):
                    continue
                if "changeme" in matched.lower() or "your_" in matched.lower():
                    continue
                findings.append(self._finding(file_path, line_no, m.start() + 1, matched))
            return findings

    _Rule.pattern = re.compile(pattern)  # type: ignore[attr-defined]
    return _Rule()


API_KEY_RULES = [_make_rule(*p) for p in _PATTERNS]
