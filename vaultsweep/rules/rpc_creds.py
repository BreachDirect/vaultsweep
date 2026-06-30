import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

# RPC/Horizon URLs with embedded basic auth or API keys in query string
_RPC_CREDS = re.compile(
    r"https?://[^:]+:[^@\s/]+@[^\s\"']+"  # user:pass@host
    r"|https?://[^\s\"']+\?(?:[^\"'\s]*&)?(?:api[_-]?key|token|secret)=[A-Za-z0-9_\-]{8,}",
    re.IGNORECASE,
)


class RpcEmbeddedCredentialRule(RegexRule):
    meta = RuleMeta(
        rule_id="RPC-001",
        name="RPC URL with Embedded Credentials",
        severity=Severity.HIGH,
        description="An RPC or Horizon URL contains embedded credentials or API keys.",
        remediation="Use header-based auth or env vars; never embed secrets in URLs.",
    )
    pattern = _RPC_CREDS

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        if "localhost" in matched or "127.0.0.1" in matched:
            return True
        return False
