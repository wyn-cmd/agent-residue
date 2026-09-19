# agent-residue

Inventory the state that AI coding agents leave on a machine, and flag the credentials sitting inside it.

Coding agents write a lot to disk: full session transcripts, prompt history, cached indexes, and in several cases the API keys they authenticate with. That state survives uninstalls, gets copied into backups, and travels with any disk image you hand to a colleague or a forensics lab. `agent-residue` walks a set of known agent locations, measures what it finds, reads the text for credential patterns, and prints an audit with a severity and a remediation list.

It scans, it reports. It never prints a secret, and it never deletes anything.

## Install

The tool has no dependencies outside the Python standard library. Python 3.9 or newer.

```
git clone https://github.com/wyn-cmd/agent-residue.git
cd agent-residue
python3 -m pip install .
```

Or run it straight from a checkout without installing:

```
PYTHONPATH=. python3 -m agent_residue --root ~
```

## Usage

```
agent-residue                     # audit the current user home
agent-residue --root /mnt/image   # audit a mounted disk image
agent-residue --json              # machine readable output
agent-residue --markdown          # output for a report or a wiki page
agent-residue --agents "aider,codex cli"
agent-residue --no-content        # sizes only, skip the credential scan
agent-residue --min-bytes 100000  # ignore small leftovers
agent-residue --fail-on critical  # exit 1 only on credentials
agent-residue --list-rules        # show every path pattern that is checked
```

Exit codes are 0 when nothing is found at or above the failure level, 1 when it is, and 2 for a usage error. The default failure level is `high`, so the command drops into a shell prompt or a CI step without extra arguments.

## Example

```
Agent residue audit
Root: /home/analyst
Scanned: 2026-09-19 18:02
Rules checked: 29
Findings: 5 (1 agents, 30 files, 7.7 MB, 3 credentials)

By severity: critical 2, high 2, medium 1, low 0

critical  Hermes         ~/.hermes/.env
          credentials, 1 files, 26.6 KB, last written 2026-09-17 19:42
          API keys read from the environment file for the runtime.
          credential openai-api-key at line 551: sk-b****
          credential google-api-key at line 37: AIza****
high      Hermes         ~/.hermes/logs
          transcripts, 21 files, 7.6 MB, last written 2026-09-19 18:02
          Session logs with prompts, tool calls and command output.

Remediation
  - Rotate every credential listed above. Deleting the file is not enough on its own.
  - Clear transcript trees before sharing the machine or handing over a disk image.
```

## What it checks

Rules cover Claude Code, Codex CLI, Gemini CLI, Cursor, Copilot CLI, Aider, Continue, OpenCode, Cline, Windsurf, and local agent runtimes such as Hermes. Run `agent-residue --list-rules` for the full table. Each rule carries a kind and a sensitivity:

- `credentials` covers files that hold tokens or keys, rated `critical` because a copy of the file is enough to use the account.
- `transcripts` covers session logs, prompt history and chat checkpoints, rated `high` because they hold source code, file contents and business context.
- `index` and `caches` cover editor and model caches, rated `medium` and `low`.
- `settings` covers configuration files, rated `low` unless a credential pattern turns up inside.

Credential patterns cover Anthropic, OpenAI, GitHub, Google, AWS and Slack keys, bearer tokens, and generic `key = "value"` assignments of 16 characters or more. A hit is reported as its first four characters followed by asterisks, the file it lives in, and the line number. The full value is never written to the report.

A finding holding a credential is promoted to `high` even when its kind is normally rated lower.

## Why the paths are hints

Agent versions move their storage around, and every rule is a best effort reading of where each tool keeps its state today. A missing directory means "not found at this path", not "this agent was never used here". If you know a location that is missing from the list, add it to `agent_residue/rules.py`; the rule table is the whole configuration surface.

## Limitations

- The scan reads file contents only for the kinds listed in `CONTENT_KINDS` and stops at 2 MB per file by default. Large transcripts are measured but not searched.
- Walking a rule stops after 20,000 files, and the finding is marked `truncated` when that happens.
- Symlinks are skipped so a scan cannot loop or escape the root.
- Patterns match plain text. A key stored in a binary blob or split across lines will not be found.
- Nothing is deleted or quarantined. Cleanup stays a decision you make with the report in hand.

## Tests

```
python3 -m unittest discover -s tests
```

The suite builds a synthetic home directory with a transcript, a credential file and a configuration file, then checks that findings, byte counts, masking and exit codes behave as documented. It asserts that no raw secret value reaches any output format.

## License

MIT. See `LICENSE`.
