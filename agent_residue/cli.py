"""Command line entry point for agent-residue."""

import argparse
import json
import sys

from . import __version__
from .report import render_markdown, render_text
from .rules import RULES, SEVERITY_ORDER, agents
from .scan import (DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILES, scan)

FAIL_LEVELS = ("critical", "high", "medium", "low", "none")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="agent-residue",
        description="Report the state AI coding agents leave on disk, and the credentials in it.")
    parser.add_argument("--root", default="~",
                        help="directory to scan, default is the current user home")
    parser.add_argument("--agents", default=None,
                        help="comma separated agent names to check, default is all of them")
    parser.add_argument("--json", action="store_true", help="print the audit as JSON")
    parser.add_argument("--markdown", action="store_true", help="print the audit as markdown")
    parser.add_argument("--no-content", action="store_true",
                        help="measure the files but do not read them for credentials")
    parser.add_argument("--min-bytes", type=int, default=0,
                        help="skip findings smaller than this many bytes")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                        help="stop walking a rule after this many files")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES,
                        help="do not read files larger than this when looking for credentials")
    parser.add_argument("--fail-on", choices=FAIL_LEVELS, default="high",
                        help="exit 1 when a finding is at or above this severity, default is high")
    parser.add_argument("--list-rules", action="store_true",
                        help="print the rule set and exit")
    parser.add_argument("--version", action="version", version="agent-residue %s" % __version__)
    return parser


def print_rules():
    for rule in RULES:
        print("%-12s %-24s %-12s %s" % (rule.agent, rule.pattern, rule.kind, rule.sensitivity))
    print("")
    print("Agents covered: %s" % ", ".join(agents()))


def severity_floor(level):
    if level == "none":
        return None
    return SEVERITY_ORDER[level]


def should_fail(audit, fail_on):
    floor = severity_floor(fail_on)
    if floor is None:
        return False
    from .report import effective_severity
    for finding in audit.findings:
        if SEVERITY_ORDER[effective_severity(finding)] <= floor:
            return True
    return False


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print_rules()
        return 0

    agent_filter = None
    if args.agents:
        agent_filter = [part.strip() for part in args.agents.split(",") if part.strip()]
        known = set(name.lower() for name in agents())
        unknown = [name for name in agent_filter if name.lower() not in known]
        if unknown:
            parser.error("unknown agent: %s" % ", ".join(unknown))

    audit = scan(
        root=args.root,
        read_contents=not args.no_content,
        agents_filter=agent_filter,
        minimal_bytes=args.min_bytes,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
    )

    if args.json:
        print(json.dumps(audit.to_dict(), indent=2, sort_keys=False))
    elif args.markdown:
        print(render_markdown(audit))
    else:
        print(render_text(audit))

    return 1 if should_fail(audit, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
