"""Walk a filesystem root and record what the agent rules find there."""

import re
import time
from pathlib import Path

from .rules import CONTENT_KINDS, RULES, SEVERITY_ORDER, Rule

# Patterns that look like credentials in agent state. A match is reported as a
# masked value only; the raw text never leaves the scanned file.
SECRET_PATTERNS = (
    ("anthropic-api-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai-api-key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{24,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack-token", re.compile(r"xox[abp]-[A-Za-z0-9\-]{10,}")),
    ("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\._\-]{20,}")),
    ("assigned-secret", re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|token|password)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/]{16,})["']""")),
)

SECRET_GROUP = {"assigned-secret": 1}

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 20000


class Finding:
    """One rule that matched something on disk."""

    def __init__(self, rule, path):
        self.rule = rule
        self.path = str(path)
        self.files = 0
        self.bytes = 0
        self.newest = None
        self.secrets = []
        self.truncated = False

    @property
    def agent(self):
        return self.rule.agent

    @property
    def kind(self):
        return self.rule.kind

    @property
    def sensitivity(self):
        return self.rule.sensitivity

    @property
    def note(self):
        return self.rule.note

    def to_dict(self):
        return {
            "agent": self.agent,
            "path": self.path,
            "kind": self.kind,
            "sensitivity": self.sensitivity,
            "note": self.note,
            "files": self.files,
            "bytes": self.bytes,
            "newest": self.newest,
            "truncated": self.truncated,
            "secrets": list(self.secrets),
        }


class Audit:
    """The whole result of one scan."""

    def __init__(self, root, findings, scanned_at=None, rule_count=0, errors=None):
        self.root = str(root)
        self.findings = findings
        self.scanned_at = scanned_at or time.time()
        self.rule_count = rule_count
        self.errors = errors or []

    @property
    def file_count(self):
        return sum(f.files for f in self.findings)

    @property
    def byte_count(self):
        return sum(f.bytes for f in self.findings)

    @property
    def secret_count(self):
        return sum(len(f.secrets) for f in self.findings)

    def severity_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            level = finding.sensitivity
            if finding.secrets and SEVERITY_ORDER[level] > SEVERITY_ORDER["high"]:
                # Anything holding a live credential is at least high.
                level = "high"
            counts[level] = counts.get(level, 0) + 1
        return counts

    def sort_key(self):
        def key(finding):
            level = finding.sensitivity
            if finding.secrets and SEVERITY_ORDER[level] > SEVERITY_ORDER["high"]:
                level = "high"
            return (SEVERITY_ORDER[level], -len(finding.secrets), finding.agent, finding.path)
        return key

    def sorted_findings(self):
        return sorted(self.findings, key=self.sort_key())

    def to_dict(self):
        return {
            "root": self.root,
            "scanned_at": self.scanned_at,
            "rules": self.rule_count,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "totals": {
                "findings": len(self.findings),
                "agents": len(set(f.agent for f in self.findings)),
                "files": self.file_count,
                "bytes": self.byte_count,
                "secrets": self.secret_count,
                "severity": self.severity_counts(),
            },
            "errors": list(self.errors),
        }


def expand(pattern, root):
    """Turn a rule pattern into a concrete path under the scan root."""
    if pattern.startswith("~"):
        return Path(root) / pattern[2:] if pattern.startswith("~/") else Path(root)
    return Path(pattern)


def iter_files(path, max_files=DEFAULT_MAX_FILES):
    """Files under path, following directories but never symlinks."""
    if path.is_file():
        yield path
        return
    count = 0
    for entry in sorted(path.rglob("*")):
        if entry.is_symlink() or not entry.is_file():
            continue
        count += 1
        if count > max_files:
            return
        yield entry


def find_secrets(path, max_bytes=DEFAULT_MAX_FILE_BYTES):
    """Masked credential hits in one file. Raw values are never returned."""
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0:
        return []
    if size > max_bytes:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    text = data.decode("utf-8", errors="replace")
    if not any(marker in text for marker in ("sk-", "AIza", "AKIA", "gh", "xox", "Bearer", "bearer")):
        return []
    hits = []
    for name, pattern in SECRET_PATTERNS:
        group = SECRET_GROUP.get(name, 0)
        for match in pattern.finditer(text):
            raw = match.group(group)
            hits.append({
                "pattern": name,
                "file": str(path),
                "line": text.count("\n", 0, match.start()) + 1,
                "masked": mask(raw),
            })
    return hits


def mask(value):
    """Show enough of a value to identify it, never enough to use it."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * 4


def scan_rule(rule, root, read_contents=True, max_files=DEFAULT_MAX_FILES,
              max_file_bytes=DEFAULT_MAX_FILE_BYTES):
    """Find the rule pattern under root and measure it. None when absent."""
    path = expand(rule.pattern, root)
    if not path.exists() and not path.is_symlink():
        return None
    finding = Finding(rule, path)
    seen = 0
    for entry in iter_files(path, max_files=max_files):
        seen += 1
        if seen > max_files:
            finding.truncated = True
            break
        finding.files += 1
        try:
            stat = entry.stat()
        except OSError:
            continue
        finding.bytes += stat.st_size
        if finding.newest is None or stat.st_mtime > finding.newest:
            finding.newest = stat.st_mtime
        if read_contents and rule.kind in CONTENT_KINDS:
            finding.secrets.extend(find_secrets(entry, max_bytes=max_file_bytes))
    return finding


def scan(root="~", rules=RULES, read_contents=True, agents_filter=None,
         minimal_bytes=0, max_files=DEFAULT_MAX_FILES,
         max_file_bytes=DEFAULT_MAX_FILE_BYTES):
    """Scan a root directory for agent residue and return an Audit."""
    root_path = Path(root).expanduser()
    findings = []
    errors = []
    if not root_path.exists():
        errors.append("scan root does not exist: %s" % root_path)
        return Audit(root_path, findings, rule_count=0, errors=errors)
    selected = rules
    if agents_filter:
        wanted = set(name.lower() for name in agents_filter)
        selected = [r for r in rules if r.agent.lower() in wanted]
    for rule in selected:
        try:
            finding = scan_rule(rule, root_path, read_contents=read_contents,
                                max_files=max_files, max_file_bytes=max_file_bytes)
        except OSError as exc:
            errors.append("%s: %s" % (rule.pattern, exc))
            continue
        if finding is None:
            continue
        if finding.bytes < minimal_bytes and not finding.secrets:
            continue
        findings.append(finding)
    return Audit(root_path, findings, rule_count=len(selected), errors=errors)
