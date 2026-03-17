"""
Jercept CLI — command-line tools for developers.

Commands:
  jercept preview <request>   Show the IBAC scope for a request
  jercept lint <policy.yaml>  Validate a YAML policy file
  jercept version             Show version info

Install: pip install jercept
The CLI is registered automatically in pyproject.toml [project.scripts].
"""
from __future__ import annotations

import json
import sys
import time


def _colour(text: str, code: str) -> str:
    """Apply ANSI colour if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str) -> str: return _colour(t, "32")
def _red(t: str) -> str:   return _colour(t, "31")
def _yellow(t: str) -> str: return _colour(t, "33")
def _cyan(t: str) -> str:  return _colour(t, "36")
def _bold(t: str) -> str:  return _colour(t, "1")
def _dim(t: str) -> str:   return _colour(t, "2")


def cmd_preview(args: list[str]) -> int:
    """
    Preview the IBAC scope that would be generated for a user request.

    Usage: jercept preview "check billing for customer 123"
           jercept preview "check billing" --provider anthropic
           jercept preview "run script" --provider ollama --model llama3
    """
    if not args or args[0] in ("-h", "--help"):
        print("Usage: jercept preview <request> [--provider openai|anthropic|gemini|ollama]")
        print("                                  [--model <model>] [--api-key <key>]")
        print()
        print("Examples:")
        print('  jercept preview "check billing for customer 123"')
        print('  jercept preview "send email to team" --provider anthropic')
        print('  jercept preview "run the script" --provider ollama --model llama3')
        return 0

    # Parse args
    request = args[0]
    provider = "openai"
    model = None
    api_key = None

    i = 1
    while i < len(args):
        if args[i] == "--provider" and i + 1 < len(args):
            provider = args[i + 1]; i += 2
        elif args[i] == "--model" and i + 1 < len(args):
            model = args[i + 1]; i += 2
        elif args[i] == "--api-key" and i + 1 < len(args):
            api_key = args[i + 1]; i += 2
        else:
            i += 1

    print()
    print(_bold("Jercept Preview"))
    print(_dim("─" * 50))
    print(f"  Request:  {_cyan(request)}")
    print(f"  Provider: {provider}")
    if model:
        print(f"  Model:    {model}")
    print()

    # Try fast extractor first
    try:
        from jercept.core.fast_extractor import try_fast_extract
        t0 = time.perf_counter()
        fast_scope = try_fast_extract(request)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if fast_scope is not None:
            print(_bold("  Extraction tier: ") + _green("Fast regex (no LLM call)"))
            print(f"  Latency:         {_green(f'{elapsed_ms:.1f}ms')}")
            _print_scope(fast_scope)
            return 0
    except Exception as e:
        print(_yellow(f"  Fast extractor error: {e}"))

    # Fall through to LLM
    print(_bold("  Extraction tier: ") + _yellow("LLM (fast regex missed)"))
    print(_dim("  Calling LLM... "), end="", flush=True)

    try:
        from jercept.core.extractor import IntentExtractor
        kwargs: dict = {"use_cache": False, "use_fast_extract": False,
                        "llm_provider": provider}
        if model:
            kwargs["model"] = model
        if api_key:
            kwargs["api_key"] = api_key

        extractor = IntentExtractor(**kwargs)
        t0 = time.perf_counter()
        scope = extractor.extract(request)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(_green("done"))
        print(f"  Latency: {elapsed_ms:.0f}ms")
        _print_scope(scope)
        return 0

    except Exception as e:
        print(_red(f"failed\n\n  Error: {e}"))
        return 1


def _print_scope(scope: object) -> None:
    """Pretty-print an IBACScope."""
    print()
    print(_bold("  Scope:"))

    allowed = getattr(scope, "allowed_actions", [])
    denied = getattr(scope, "denied_actions", [])
    resources = getattr(scope, "allowed_resources", [])
    confidence = getattr(scope, "confidence", 0.0)

    if allowed:
        print(f"    {_green('✓ Allowed actions:')}")
        for a in allowed:
            print(f"        {_green(a)}")
    else:
        print(f"    {_yellow('⚠ No allowed actions (ambiguous request)')}")

    if resources:
        print(f"    {_cyan('● Resources:')}")
        for r in resources:
            print(f"        {_cyan(r)}")
    else:
        print(f"    {_dim('● Resources: (any — no restriction)')}")

    if denied:
        print(f"    {_red('✗ Denied actions:')}")
        for d in denied[:5]:
            print(f"        {_red(d)}")
        if len(denied) > 5:
            print(f"        {_dim(f'... and {len(denied)-5} more')}")

    conf_str = f"{confidence:.0%}"
    conf_colour = _green if confidence >= 0.8 else _yellow if confidence >= 0.6 else _red
    print(f"\n    Confidence: {conf_colour(conf_str)}")
    print()


def cmd_lint(args: list[str]) -> int:
    """
    Lint a YAML policy file for security issues.

    Usage: jercept lint policies/billing.yaml
    """
    if not args or args[0] in ("-h", "--help"):
        print("Usage: jercept lint <policy.yaml>")
        print()
        print("Examples:")
        print("  jercept lint policies/billing.yaml")
        print("  jercept lint policies/devops.yaml")
        return 0

    path = args[0]

    try:
        from jercept.linter import lint_yaml
        result = lint_yaml(path)
        print(result)

        if result.has_errors:
            return 1
        return 0

    except FileNotFoundError:
        print(_red(f"\n  Error: File not found: {path!r}"))
        return 1
    except Exception as e:
        print(_red(f"\n  Error: {e}"))
        return 1


def cmd_version() -> int:
    """Print version and provider info."""
    try:
        from jercept import __version__, __author__
        print(f"\nJercept v{__version__} — {__author__}")
        print("The authorization layer for AI agents.\n")

        print("Supported LLM providers:")
        providers = [
            ("openai",    "OpenAI (gpt-4o-mini, gpt-4o, ...)",   "pip install jercept"),
            ("anthropic", "Anthropic Claude (haiku, sonnet, ...)", "pip install jercept[anthropic]"),
            ("gemini",    "Google Gemini (flash, pro, ...)",       "pip install jercept[gemini]"),
            ("ollama",    "Local Ollama (llama3, mistral, ...)",   "pip install jercept (no key needed)"),
        ]
        for name, desc, install in providers:
            print(f"  {_cyan(name):20s} {desc}")
            print(f"  {'':20s} {_dim(install)}")
            print()
        return 0
    except ImportError:
        print("Jercept is not installed.")
        return 1


def main() -> None:
    """Entry point for the jercept CLI."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("\nUsage: jercept <command> [args]")
        print()
        print("Commands:")
        print(f"  {_cyan('preview')} <request>      Show the IBAC scope for a request")
        print(f"  {_cyan('lint')}    <policy.yaml>  Validate a YAML policy file")
        print(f"  {_cyan('version')}                Show version and provider info")
        print()
        print("Examples:")
        print('  jercept preview "check billing for customer 123"')
        print('  jercept preview "send email" --provider anthropic')
        print('  jercept lint policies/billing.yaml')
        print()
        sys.exit(0)

    command = args[0]
    rest = args[1:]

    if command == "preview":
        sys.exit(cmd_preview(rest))
    elif command == "lint":
        sys.exit(cmd_lint(rest))
    elif command == "version":
        sys.exit(cmd_version())
    else:
        print(_red(f"\n  Unknown command: {command!r}"))
        print("  Run 'jercept --help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
