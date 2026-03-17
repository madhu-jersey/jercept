"""Tests for jercept CLI commands."""
from __future__ import annotations
import sys, types
import pytest
from unittest.mock import MagicMock, patch


def _stub_openai():
    stub = types.ModuleType("openai")
    stub.OpenAI = lambda **k: MagicMock()
    stub.AsyncOpenAI = lambda **k: MagicMock()
    return stub


class TestCmdVersion:
    def test_version_exits_zero(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_version
            rc = cmd_version()
            assert rc == 0

    def test_version_lists_providers(self, capsys):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_version
            cmd_version()
            out = capsys.readouterr().out
            assert "openai" in out.lower()
            assert "anthropic" in out.lower()
            assert "ollama" in out.lower()


class TestCmdLint:
    def test_lint_missing_file_returns_1(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_lint
            rc = cmd_lint(["nonexistent_policy_file.yaml"])
            assert rc == 1

    def test_lint_help_returns_0(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_lint
            rc = cmd_lint(["--help"])
            assert rc == 0

    def test_lint_no_args_returns_0(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_lint
            rc = cmd_lint([])
            assert rc == 0


class TestCmdPreview:
    def test_preview_help_returns_0(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_preview
            rc = cmd_preview(["--help"])
            assert rc == 0

    def test_preview_no_args_returns_0(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_preview
            rc = cmd_preview([])
            assert rc == 0

    def test_preview_fast_extract_hits_regex(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_preview
            # billing request hits fast extractor - no LLM needed
            rc = cmd_preview(["check billing for customer 123"])
            assert rc == 0

    def test_preview_output_shows_allowed(self, capsys):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_preview
            cmd_preview(["check billing for customer 123"])
            out = capsys.readouterr().out
            assert "db.read" in out or "Allowed" in out or "ALLOWED" in out

    def test_preview_parse_provider_flag(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import cmd_preview
            # Should not crash even if LLM not available - billing hits fast extractor
            rc = cmd_preview(["check billing", "--provider", "openai"])
            assert rc == 0


class TestMainDispatch:
    def test_unknown_command_exits_1(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import main
            with patch("sys.argv", ["jercept", "unknowncmd"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_no_args_exits_0(self):
        stub = _stub_openai()
        with patch.dict("sys.modules", {"openai": stub}):
            from jercept.cli import main
            with patch("sys.argv", ["jercept"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
