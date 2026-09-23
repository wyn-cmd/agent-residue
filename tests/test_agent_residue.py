# Tests for scan, masking, and exit codes

import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_residue import cli
from agent_residue.report import render_markdown, render_text
from agent_residue.rules import CRITICAL, HIGH, RULES
from agent_residue.scan import mask, scan

ANTHROPIC_KEY = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF1234"
OPENAI_KEY = "sk-proj-ZZZZYYYYXXXXWWWWVVVVUUUUTTTT0000"


# Create a small fake home tree with agent residue
def build_fake_home(base):
    home = Path(base)
    projects = home / ".claude" / "projects" / "demo"
    projects.mkdir(parents=True)
    (projects / "session.jsonl").write_text(
        '{"type":"user","text":"hello"}\n'
        '{"type":"config","apiKey":"%s"}\n' % ANTHROPIC_KEY,
        encoding="utf-8")

    codex = home / ".codex"
    codex.mkdir(parents=True)
    (codex / "auth.json").write_text(
        json.dumps({"OPENAI_API_KEY": OPENAI_KEY, "tokens": {"access": "x" * 40}}),
        encoding="utf-8")
    (codex / "history.jsonl").write_text('{"cmd":"ls"}\n', encoding="utf-8")

    (home / ".aider.conf.yml").write_text("model: gpt-5\n", encoding="utf-8")

    (home / "notes.txt").write_text("nothing to see\n", encoding="utf-8")
    return home


class MaskTests(unittest.TestCase):
    def test_mask_keeps_four_characters(self):
        self.assertEqual(mask("sk-ant-abcdef"), "sk-a****")

    def test_mask_short_value(self):
        self.assertEqual(mask("abc"), "***")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = build_fake_home(self.tmp.name)
        self.audit = scan(root=str(self.home))

    def tearDown(self):
        self.tmp.cleanup()

    def test_finds_expected_agents(self):
        found = set(f.agent for f in self.audit.findings)
        self.assertIn("Claude Code", found)
        self.assertIn("Codex CLI", found)
        self.assertIn("Aider", found)
        self.assertNotIn("Cursor", found)

    def test_transcript_bytes_are_measured(self):
        claude = [f for f in self.audit.findings if f.agent == "Claude Code"]
        self.assertTrue(claude)
        self.assertGreater(claude[0].bytes, 0)
        self.assertEqual(claude[0].files, 1)

    def test_secrets_are_found(self):
        patterns = set(s["pattern"] for f in self.audit.findings for s in f.secrets)
        self.assertIn("anthropic-api-key", patterns)
        self.assertIn("openai-api-key", patterns)

    def test_raw_secret_never_appears_in_output(self):
        for render in (render_text, render_markdown):
            output = render(self.audit)
            self.assertNotIn(ANTHROPIC_KEY, output)
            self.assertNotIn(OPENAI_KEY, output)
        payload = json.dumps(self.audit.to_dict())
        self.assertNotIn(ANTHROPIC_KEY, payload)
        self.assertNotIn(OPENAI_KEY, payload)

    def test_credential_file_is_critical(self):
        auth = [f for f in self.audit.findings if f.path.endswith("auth.json")]
        self.assertTrue(auth)
        self.assertEqual(auth[0].sensitivity, CRITICAL)

    def test_secret_bearing_finding_is_promoted_to_high(self):
        counts = self.audit.severity_counts()
        self.assertGreaterEqual(counts["critical"] + counts["high"], 2)

    def test_content_scan_can_be_switched_off(self):
        quiet = scan(root=str(self.home), read_contents=False)
        self.assertEqual(quiet.secret_count, 0)
        self.assertGreater(quiet.byte_count, 0)

    def test_agent_filter_limits_work(self):
        filtered = scan(root=str(self.home), agents_filter=["aider"])
        self.assertEqual(set(f.agent for f in filtered.findings), {"Aider"})

    def test_min_bytes_drops_small_findings(self):
        big = scan(root=str(self.home), minimal_bytes=10000)
        self.assertTrue(big.findings)
        self.assertTrue(all(f.secrets for f in big.findings))

    def test_min_bytes_without_content_scan_returns_nothing(self):
        big = scan(root=str(self.home), minimal_bytes=10000, read_contents=False)
        self.assertEqual(big.findings, [])

    def test_missing_root_reports_an_error(self):
        missing = scan(root=str(Path(self.tmp.name) / "nope"))
        self.assertEqual(missing.findings, [])
        self.assertTrue(missing.errors)

    def test_every_rule_pattern_is_relative_or_home(self):
        for rule in RULES:
            self.assertTrue(rule.pattern.startswith("~"), rule.pattern)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = build_fake_home(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_json_output_is_valid(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--root", str(self.home), "--json"])
        payload = json.loads(buf.getvalue())
        self.assertEqual(code, 1)
        self.assertIn("totals", payload)
        self.assertGreaterEqual(payload["totals"]["secrets"], 2)

    def test_fail_on_none_always_exits_zero(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--root", str(self.home), "--fail-on", "none"])
        self.assertEqual(code, 0)
        self.assertIn("Agent residue audit", buf.getvalue())

    def test_clean_root_exits_zero(self):
        import contextlib
        import io
        empty = Path(self.tmp.name) / "empty"
        empty.mkdir()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--root", str(empty)])
        self.assertEqual(code, 0)
        self.assertIn("Findings: 0", buf.getvalue())

    def test_list_rules_runs(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("Claude Code", buf.getvalue())

    def test_unknown_agent_is_rejected(self):
        with self.assertRaises(SystemExit):
            cli.main(["--agents", "nope", "--root", str(self.home)])


if __name__ == "__main__":
    unittest.main()