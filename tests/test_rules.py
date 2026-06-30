from vaultsweep.rules import ALL_RULES, list_rules
from vaultsweep.rules.stellar_secret_key import StellarSecretKeyRule


def test_all_rules_registered():
    assert len(ALL_RULES) >= 6
    assert len(list_rules()) == len(ALL_RULES)


def test_stellar_secret_detection():
    rule = StellarSecretKeyRule()
    # Valid-format test key (not a real secret — random base32)
    line = "SECRET=SCZANGBA5SCTZXW5K3P3AR2R7X5FJCHLL2ULYLMGOSCFW3RXMQ26FICF"
    findings = rule.scan_line("test.env", 1, line)
    assert len(findings) == 1
    assert findings[0].rule_id == "STELLAR-001"


def test_stellar_public_key_not_flagged():
    rule = StellarSecretKeyRule()
    # Public keys start with G, not S
    line = "PUBLIC=GBFXEPGCJ5K6P2UV22VLOS5ERAPZFF7AABLMZCKXGD3KTGXECDSNNFXW"
    assert rule.scan_line("test.env", 1, line) == []
