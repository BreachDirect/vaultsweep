import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

_DEFAULTS = re.compile(
    r"(?i)(?:password|passwd|secret|api_?key|zap_api_key|token)\s*[=:]\s*['\"]?"
    r"(?:changeme|password|admin|123456|secret|test|default|changeme123)['\"]?",
)


class DefaultCredentialRule(RegexRule):
    meta = RuleMeta(
        rule_id="DEFAULT-001",
        name="Default or Weak Credential",
        severity=Severity.HIGH,
        description="A default or commonly-used credential value was found in config.",
        remediation="Replace with strong unique secrets loaded from environment variables.",
    )
    pattern = _DEFAULTS

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        if ".example" in line or "example.com" in line.lower():
            return True
        return False
