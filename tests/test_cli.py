from vaultsweep.cli import main


def test_rules_command():
    assert main(["rules"]) == 0


def test_scan_clean_json(capsys):
    code = main(["scan", "fixtures/clean-repo", "--format", "json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"tool": "VaultSweep"' in out


def test_scan_leaky_fail_on_high():
    code = main(["scan", "fixtures/leaky-repo", "--fail-on", "high"])
    assert code == 1
