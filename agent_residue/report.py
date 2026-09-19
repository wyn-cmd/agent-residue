"""Render an Audit as text or markdown."""

import datetime

from .rules import SEVERITY_ORDER

SEVERITY_LABEL = ("critical", "high", "medium", "low")


def human_bytes(value):
    step = 1024.0
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < step or unit == "TB":
            if unit == "B":
                return "%d B" % value
            return "%.1f %s" % (size, unit)
        size /= step


def timestamp(value):
    if not value:
        return "unknown"
    return datetime.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")


def effective_severity(finding):
    level = finding.sensitivity
    if finding.secrets and SEVERITY_ORDER[level] > SEVERITY_ORDER["high"]:
        return "high"
    return level


def short_path(path, root):
    prefix = str(root).rstrip("/") + "/"
    if path.startswith(prefix):
        return "~/" + path[len(prefix):]
    return path


def remediation_lines(audit):
    lines = []
    any_secrets = audit.secret_count > 0
    if any_secrets:
        lines.append("Rotate every credential listed above. Deleting the file is not enough on its own.")
    creds = [f for f in audit.sorted_findings() if f.kind == "credentials"]
    if creds:
        lines.append("Move credentials out of plain agent state: %s." % ", ".join(
            short_path(f.path, audit.root) for f in creds[:5]))
    transcripts = [f for f in audit.sorted_findings() if f.kind == "transcripts"]
    if transcripts:
        lines.append("Clear transcript trees before sharing the machine or handing over a disk image: %s." %
                     ", ".join(short_path(f.path, audit.root) for f in transcripts[:5]))
    if not audit.findings:
        lines.append("Nothing found. No agent state under this root matches the rule set.")
    else:
        lines.append("Re-run after a cleanup to confirm the residue is gone.")
    return lines


def render_text(audit):
    out = []
    out.append("Agent residue audit")
    out.append("Root: %s" % audit.root)
    out.append("Scanned: %s" % timestamp(audit.scanned_at))
    out.append("Rules checked: %d" % audit.rule_count)
    out.append("Findings: %d (%d agents, %d files, %s, %d credentials)" % (
        len(audit.findings),
        len(set(f.agent for f in audit.findings)),
        audit.file_count,
        human_bytes(audit.byte_count),
        audit.secret_count))
    counts = audit.severity_counts()
    out.append("")
    out.append("By severity: " + ", ".join("%s %d" % (level, counts[level]) for level in SEVERITY_LABEL))
    if audit.errors:
        out.append("")
        out.append("Errors")
        for error in audit.errors:
            out.append("  %s" % error)
    if audit.findings:
        out.append("")
        for finding in audit.sorted_findings():
            out.append("%-9s %-14s %s" % (effective_severity(finding), finding.agent,
                                          short_path(finding.path, audit.root)))
            out.append("          %s, %d files, %s, last written %s%s" % (
                finding.kind, finding.files, human_bytes(finding.bytes),
                timestamp(finding.newest), ", truncated" if finding.truncated else ""))
            out.append("          %s" % finding.note)
            for secret in finding.secrets:
                out.append("          credential %s at line %d: %s" % (
                    secret["pattern"], secret["line"], secret["masked"]))
    out.append("")
    out.append("Remediation")
    for line in remediation_lines(audit):
        out.append("  - %s" % line)
    return "\n".join(out)


def render_markdown(audit):
    out = []
    out.append("# Agent residue audit")
    out.append("")
    out.append("Root: `%s`  " % audit.root)
    out.append("Scanned: %s  " % timestamp(audit.scanned_at))
    out.append("Rules checked: %d  " % audit.rule_count)
    out.append("Findings: %d (%d agents, %d files, %s, %d credentials)" % (
        len(audit.findings),
        len(set(f.agent for f in audit.findings)),
        audit.file_count,
        human_bytes(audit.byte_count),
        audit.secret_count))
    counts = audit.severity_counts()
    out.append("")
    out.append("Severity: " + ", ".join("**%s** %d" % (level, counts[level]) for level in SEVERITY_LABEL))
    out.append("")
    if audit.findings:
        out.append("| Severity | Agent | Path | Kind | Files | Size | Last written |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for finding in audit.sorted_findings():
            out.append("| %s | %s | `%s` | %s | %d | %s | %s |" % (
                effective_severity(finding), finding.agent,
                short_path(finding.path, audit.root), finding.kind,
                finding.files, human_bytes(finding.bytes), timestamp(finding.newest)))
        out.append("")
        secrets = [(f, s) for f in audit.sorted_findings() for s in f.secrets]
        if secrets:
            out.append("## Credentials in agent state")
            out.append("")
            for finding, secret in secrets:
                out.append("- %s in `%s` line %d: `%s`" % (
                    secret["pattern"], short_path(secret["file"], audit.root),
                    secret["line"], secret["masked"]))
            out.append("")
    if audit.errors:
        out.append("## Errors")
        out.append("")
        for error in audit.errors:
            out.append("- %s" % error)
        out.append("")
    out.append("## Remediation")
    out.append("")
    for line in remediation_lines(audit):
        out.append("- %s" % line)
    return "\n".join(out)
