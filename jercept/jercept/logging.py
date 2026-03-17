"""
Jercept structured logging — JSON-formatted log events for production.

Enables log aggregation in Datadog, CloudWatch, Splunk, and other
log management platforms that require parseable JSON output.

Usage::

    # In your application startup:
    from jercept.logging import configure_structured_logging
    configure_structured_logging()  # all jercept logs now emit JSON

    # Or use the standard logging config:
    import logging
    from jercept.logging import JerceptJsonFormatter
    handler = logging.StreamHandler()
    handler.setFormatter(JerceptJsonFormatter())
    logging.getLogger("jercept").addHandler(handler)
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict


class JerceptJsonFormatter(logging.Formatter):
    """
    JSON log formatter for structured log aggregation.

    Every Jercept log record is emitted as a single-line JSON object
    containing: timestamp, level, event, logger, and any extra fields.

    Example output::

        {"ts": 1710000000.0, "level": "WARNING", "event": "ibac_blocked",
         "action": "db.export", "session_id": "abc123", "risk_score": 0.9,
         "logger": "jercept.core.enforcer"}
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        data: Dict[str, Any] = {
            "ts":     record.created,
            "level":  record.levelname,
            "event":  self._classify(record),
            "msg":    record.getMessage(),
            "logger": record.name,
        }

        # Extract structured fields from well-known log message patterns
        msg = record.getMessage()
        if "IBAC BLOCKED" in msg:
            data["event"] = "ibac_blocked"
            self._extract_kv(msg, data, ["action", "resource", "fn", "intent"])
        elif "IBAC allowed" in msg:
            data["event"] = "ibac_allowed"
            self._extract_kv(msg, data, ["action", "resource", "fn"])
        elif "IBAC AUTO-EXPANDED" in msg:
            data["event"] = "ibac_auto_expanded"
            self._extract_kv(msg, data, ["action", "resource", "fn"])
        elif "Injection detected" in msg or "scan_input" in msg:
            data["event"] = "injection_detected"
        elif "IBACScope WARNING" in msg:
            data["event"] = "scope_wildcard_warning"
        elif "AUTO mode used without" in msg:
            data["event"] = "auto_no_policy_warning"
        elif "LLM granted dangerous" in msg:
            data["event"] = "llm_jailbreak_suspected"

        # Include exception info if present
        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)

        return json.dumps(data, default=str)

    def _classify(self, record: logging.LogRecord) -> str:
        """Derive a short event name from the log record."""
        msg = record.getMessage()
        if "BLOCKED" in msg: return "ibac_blocked"
        if "allowed" in msg: return "ibac_allowed"
        if "EXPANDED" in msg: return "scope_expanded"
        if "injection" in msg.lower(): return "injection_scan"
        return "jercept_log"

    def _extract_kv(
        self,
        msg: str,
        data: Dict[str, Any],
        keys: list[str],
    ) -> None:
        """Extract key=value pairs from log message into data dict."""
        import re
        for key in keys:
            m = re.search(rf"{key}='([^']*)'", msg) or re.search(rf"{key}=(\S+)", msg)
            if m:
                data[key] = m.group(1).strip("'\"")


def configure_structured_logging(
    level: int = logging.WARNING,
    stream: Any = None,
) -> None:
    """
    Configure all jercept loggers to emit structured JSON.

    Call this once at application startup before any agents are created.

    Args:
        level: Minimum log level (default: WARNING).
               Set to logging.INFO to also see permitted calls and expansions.
               Set to logging.DEBUG for full trace output.
        stream: Output stream (default: stderr via StreamHandler).

    Example::

        import logging
        from jercept.logging import configure_structured_logging

        # Production: warnings and above as JSON
        configure_structured_logging(level=logging.WARNING)

        # Development: everything
        configure_structured_logging(level=logging.DEBUG)
    """
    import sys
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JerceptJsonFormatter())
    handler.setLevel(level)

    root = logging.getLogger("jercept")
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False  # Don't double-log via root logger
