import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

# Stellar secret keys: S + 55 base32 chars (A-Z, 2-7)
_STELLAR_SECRET = re.compile(r"\bS[A-Z2-7]{55}\b")


class StellarSecretKeyRule(RegexRule):
    meta = RuleMeta(
        rule_id="STELLAR-001",
        name="Stellar Secret Key Exposed",
        severity=Severity.CRITICAL,
        description="A Stellar secret key (starts with S, 56 chars) was found in source.",
        remediation="Rotate immediately. Store secrets in env vars or a vault — never commit them.",
    )
    pattern = _STELLAR_SECRET
    min_length = 56

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        # Public keys also start with G — secret keys start with S only; already enforced by pattern
        if "SXXXXXXXX" in matched or matched == "S" + "A" * 55:
            return True
        return False
