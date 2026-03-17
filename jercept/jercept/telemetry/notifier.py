"""
Jercept WebhookNotifier — real-time attack alerts.

Sends a POST to a configurable URL whenever an agent session
records a blocked action (was_attacked=True). Runs on a daemon
thread so it never blocks agent execution.

Usage::

    from jercept.telemetry.notifier import WebhookNotifier

    notifier = WebhookNotifier(url="https://hooks.slack.com/services/T.../...")
    notifier.notify(enforcer, scope)   # non-blocking, never raises
"""
from __future__ import annotations

import logging
import time
from threading import Thread
from typing import Any, Dict, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

HTTP_TIMEOUT: float = 5.0


class WebhookNotifier:
    """
    Fire-and-forget webhook sender for attack alert notifications.

    When an agent session has blocked actions, this notifier POSTs a
    structured JSON payload to the configured URL. Compatible with Slack
    incoming webhooks, PagerDuty, Discord, and any HTTP endpoint.

    The request always runs on a daemon thread. If it fails for any
    reason, the exception is silently swallowed — alerts must never
    crash the agent.

    Args:
        url: The webhook URL to POST to.
        min_risk_score: Only fire if scan risk_score >= this threshold.
                        Default 0.0 — fires on any blocked action.
        include_intent: Whether to include the raw user intent string
                        in the payload. Set False if the intent may
                        contain sensitive data. Default True.

    Example::

        notifier = WebhookNotifier(url="https://hooks.slack.com/...")
        notifier.notify(enforcer, scope)

        # Slack-compatible rich payload is sent automatically.
    """

    def __init__(
        self,
        url: str,
        min_risk_score: float = 0.0,
        include_intent: bool = True,
    ) -> None:
        if not url or not url.startswith(("http://", "https://")):
            raise ValueError(
                f"WebhookNotifier requires a valid http(s):// URL, got {url!r}"
            )
        self.url = url
        self.min_risk_score = min_risk_score
        self.include_intent = include_intent

    def notify(
        self,
        enforcer: Any,
        scope: Any,
        scan_result: Optional[Any] = None,
    ) -> None:
        """
        Send an alert if the session had any blocked actions.

        No-op if nothing was blocked. Always non-blocking.

        Args:
            enforcer: IBACEnforcer after the agent run.
            scope: IBACScope for the session.
            scan_result: Optional ScanResult from injection scanner.
        """
        blocked = [
            e for e in getattr(enforcer, "audit_log", [])
            if not e.get("permitted", True)
        ]
        if not blocked:
            return

        risk_score = getattr(scan_result, "risk_score", 0.0) if scan_result else 0.0
        if risk_score < self.min_risk_score:
            return

        payload = self._build_payload(blocked, scope, scan_result)
        thread = Thread(target=self._post, args=(payload,), daemon=True)
        thread.start()

    def _build_payload(
        self,
        blocked: list,
        scope: Any,
        scan_result: Optional[Any],
    ) -> Dict[str, Any]:
        """Build the JSON payload to POST."""
        blocked_actions = [e.get("action", "unknown") for e in blocked]
        intent = getattr(scope, "raw_intent", "") if self.include_intent else "[redacted]"
        confidence = getattr(scope, "confidence", 0.0)

        payload: Dict[str, Any] = {
            "alert_type": "ibac_scope_violation",
            "session_id": str(uuid4()),
            "ts": time.time(),
            "blocked_count": len(blocked),
            "blocked_actions": blocked_actions,
            "intent": intent,
            "confidence": confidence,
        }

        if scan_result is not None:
            payload["scan"] = {
                "risk_score": getattr(scan_result, "risk_score", 0.0),
                "matched_patterns": getattr(scan_result, "matched_patterns", []),
                "is_suspicious": getattr(scan_result, "is_suspicious", False),
            }

        # Slack-compatible text block for instant readability
        payload["text"] = (
            f":rotating_light: *Jercept blocked attack* "
            f"| actions: `{', '.join(blocked_actions)}` "
            f"| intent: _{intent[:80]}_"
        )

        return payload

    def _post(self, payload: Dict[str, Any]) -> None:
        """HTTP POST on daemon thread. All exceptions silently swallowed."""
        try:
            import httpx
            response = httpx.post(
                self.url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=HTTP_TIMEOUT,
            )
            logger.debug(
                "Webhook alert sent — status=%d blocked=%s",
                response.status_code,
                payload.get("blocked_actions"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Webhook notify failed (silenced): %s", exc)
