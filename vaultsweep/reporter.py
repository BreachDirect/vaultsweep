import json

from vaultsweep.models import ScanReport, Severity


def format_text(report: ScanReport) -> str:
    lines = [
        f"VaultSweep v{report.version}",
        f"Target: {report.target}",
        f"Files scanned: {report.summary['files_scanned']}",
        f"Rules run: {report.summary['rules_run']}",
        f"Findings: {report.summary['findings']}",
        "",
    ]
    by = report.summary["by_severity"]
    lines.append(
        f"  critical: {by['critical']}  high: {by['high']}  "
        f"medium: {by['medium']}  low: {by['low']}"
    )
    lines.append("")

    if not report.findings:
        lines.append("✅ No secrets detected.")
        return "\n".join(lines)

    for f in report.findings:
        lines.append(f"[{f.severity.value.upper()}] {f.rule_id} — {f.name}")
        lines.append(f"  {f.file}:{f.line}:{f.column}")
        lines.append(f"  {f.message}")
        lines.append(f"  Match: {f.match}")
        lines.append(f"  Fix: {f.remediation}")
        lines.append("")

    return "\n".join(lines).rstrip()


def format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def exit_code_for_report(report: ScanReport, fail_on: Severity | None) -> int:
    if fail_on is None:
        return 0
    from vaultsweep.scanner import exceeds_threshold

    return 1 if exceeds_threshold(report.findings, fail_on) else 0
