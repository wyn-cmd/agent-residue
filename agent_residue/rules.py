"""Known on-disk locations that AI coding agents write to.

Each rule pairs a path pattern with the kind of data it holds and how
sensitive that data is. The paths come from the agents themselves and move
between releases, so every rule is a best-effort hint that a scan confirms,
not a guarantee that the location still exists.
"""

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


class Rule:
    """One path pattern to look for, and what it means when it is present."""

    __slots__ = ("agent", "pattern", "kind", "sensitivity", "note")

    def __init__(self, agent, pattern, kind, sensitivity, note):
        self.agent = agent
        self.pattern = pattern
        self.kind = kind
        self.sensitivity = sensitivity
        self.note = note

    def __repr__(self):
        return "Rule(%r, %r, %r)" % (self.agent, self.pattern, self.kind)


# Patterns start at the scan root. A leading ~ means "the scan root", so a
# scan of a home directory and a scan of a synthetic test tree behave the same.
RULES = (
    # Claude Code
    Rule("Claude Code", "~/.claude/projects", "transcripts", HIGH,
         "Per-project session transcripts, including prompt and tool output text."),
    Rule("Claude Code", "~/.claude/history.jsonl", "transcripts", HIGH,
         "Command history for the agent prompt line."),
    Rule("Claude Code", "~/.claude/settings.json", "settings", LOW,
         "Agent settings, hooks and allowed commands."),
    Rule("Claude Code", "~/.claude.json", "settings", LOW,
         "Project list and per-project state for the agent."),

    # Codex CLI
    Rule("Codex CLI", "~/.codex/sessions", "transcripts", HIGH,
         "Session rollout files with prompts, diffs and tool calls."),
    Rule("Codex CLI", "~/.codex/history.jsonl", "transcripts", HIGH,
         "Prompt history for the agent."),
    Rule("Codex CLI", "~/.codex/auth.json", "credentials", CRITICAL,
         "Cached authentication material for the agent."),
    Rule("Codex CLI", "~/.codex/config.toml", "settings", LOW,
         "Model and provider configuration."),

    # Gemini CLI
    Rule("Gemini CLI", "~/.gemini/tmp", "transcripts", HIGH,
         "Per-project chat checkpoints and temporary agent state."),
    Rule("Gemini CLI", "~/.gemini/oauth_creds.json", "credentials", CRITICAL,
         "OAuth refresh token for the agent account."),
    Rule("Gemini CLI", "~/.gemini/settings.json", "settings", LOW,
         "Agent settings and enabled extensions."),

    # Cursor
    Rule("Cursor", "~/.cursor", "index", MEDIUM,
         "Editor agent state, rules and local indexes."),
    Rule("Cursor", "~/.config/Cursor/User/globalStorage", "index", MEDIUM,
         "Chat history and workspace storage for the editor agent."),

    # GitHub Copilot CLI
    Rule("Copilot CLI", "~/.config/github-copilot", "credentials", CRITICAL,
         "Stored GitHub tokens used by the agent."),
    Rule("Copilot CLI", "~/.copilot", "transcripts", HIGH,
         "Session history and logs for the agent."),

    # Aider
    Rule("Aider", "~/.aider.chat.history.md", "transcripts", HIGH,
         "Full chat transcript in markdown."),
    Rule("Aider", "~/.aider/caches", "caches", LOW,
         "Model and repo map caches."),
    Rule("Aider", "~/.aider.conf.yml", "settings", LOW,
         "Agent configuration, sometimes holding API keys."),

    # Continue
    Rule("Continue", "~/.continue/sessions", "transcripts", HIGH,
         "Chat sessions with prompts and code."),
    Rule("Continue", "~/.continue/config.json", "settings", LOW,
         "Assistant configuration and model providers."),

    # OpenCode
    Rule("OpenCode", "~/.local/share/opencode", "transcripts", HIGH,
         "Stored sessions and message parts for the agent."),
    Rule("OpenCode", "~/.config/opencode", "settings", LOW,
         "Agent configuration files."),

    # Cline and Windsurf, both inside editor storage trees
    Rule("Cline", "~/.local/share/Code/User/globalStorage/saoudrizwan.claude-dev", "transcripts", HIGH,
         "Task history and API settings kept by the editor extension."),
    Rule("Windsurf", "~/.codeium/windsurf", "transcripts", MEDIUM,
         "Cascade session data and cached context."),

    # Hermes Agent and similar local runtimes
    Rule("Hermes", "~/.hermes/memories", "transcripts", HIGH,
         "Notes and profile the runtime carries between sessions."),
    Rule("Hermes", "~/.hermes/logs", "transcripts", HIGH,
         "Session logs with prompts, tool calls and command output."),
    Rule("Hermes", "~/.hermes/auth.json", "credentials", CRITICAL,
         "Provider credentials held by the runtime."),
    Rule("Hermes", "~/.hermes/.env", "credentials", CRITICAL,
         "API keys read from the environment file for the runtime."),
    Rule("Hermes", "~/.hermes/cron/output", "transcripts", MEDIUM,
         "Saved output of scheduled runs."),
)

# Kinds whose file contents are worth reading for secrets.
CONTENT_KINDS = frozenset(("transcripts", "credentials", "settings", "caches"))


def agents():
    """Agent names in the order rules are defined, without duplicates."""
    seen = []
    for rule in RULES:
        if rule.agent not in seen:
            seen.append(rule.agent)
    return seen
