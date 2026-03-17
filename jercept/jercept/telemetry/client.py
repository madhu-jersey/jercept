"""
Jercept TelemetryClient module.

Sends security event data to the Jercept dashboard asynchronously via a
bounded background queue. A single persistent sender thread drains the queue
at a controlled rate — no unbounded thread creation, no backpressure issues.

PERF FIX: Previous implementation spawned a new daemon thread per event
(unbounded thread creation under load). Now uses a single worker thread
with a bounded queue (max 200 events). When the queue is full, new events
are dropped and logged — telemetry must never impact the agent.
"""
from __future__ import annotations

import logging
import os
import queue
import time
from threading import Thread
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

TELEMETRY_ENDPOINT: str = "https://api.jercept.com/v1/events"
SDK_VERSION: str = "1.2.0"
HTTP_TIMEOUT: float = 3.0
_QUEUE_MAX: int = 200          # max events before backpressure drops
_SENTINEL = object()           # signals the worker to stop


class TelemetryClient:
    """
    Fire-and-forget telemetry sender for Jercept dashboard integration.

    Uses a single persistent background worker thread draining a bounded
    queue — no per-event thread spawning. The queue holds at most
    ``_QUEUE_MAX`` events; extras are dropped with a logged warning so
    telemetry never blocks or crashes the agent.

    Attributes:
        enabled: ``True`` if an API key is configured.

    Example::

        telemetry = TelemetryClient(api_key="jercept_live_xxxx")
        event = telemetry.build_event(enforcer, scope)
        telemetry.send(event)   # non-blocking, never raises
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Initialise the telemetry client and start the background worker.

        Args:
            api_key: Jercept API key (``"jercept_live_"`` prefix).
                Falls back to the ``JERCEPT_API_KEY`` environment variable.
        """
        self.api_key: Optional[str] = api_key or os.getenv("JERCEPT_API_KEY")
        self.enabled: bool = bool(self.api_key)
        self._queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAX)
        self._dropped: int = 0

        if not self.enabled:
            logger.debug(
                "TelemetryClient: no API key — telemetry disabled. "
                "Set JERCEPT_API_KEY or pass api_key= to enable."
            )
            return

        # Single persistent worker thread — no per-event thread spawning
        self._worker = Thread(
            target=self._drain,
            name="jercept-telemetry",
            daemon=True,
        )
        self._worker.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, event: Dict[str, Any]) -> None:
        """
        Enqueue a telemetry event for background delivery.

        Non-blocking. Drops the event with a warning if the queue is full.
        Never raises. Telemetry must not impact agent performance.

        Args:
            event: Event payload, typically from :meth:`build_event`.
        """
        if not self.enabled:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 50 == 1:
                logger.warning(
                    "TelemetryClient: queue full (%d events dropped). "
                    "Dashboard may be unreachable.",
                    self._dropped,
                )

    def build_event(self, enforcer: Any, scope: Any) -> Dict[str, Any]:
        """
        Build a complete telemetry event from an enforcer's audit log.

        Args:
            enforcer: :class:`~jercept.core.enforcer.IBACEnforcer` after run.
            scope: :class:`~jercept.core.scope.IBACScope` for the session.

        Returns:
            JSON-serialisable dict with all session security data.
        """
        audit_log: List[Dict] = list(getattr(enforcer, "audit_log", []))
        total_calls   = len(audit_log)
        blocked_calls = sum(1 for e in audit_log if not e.get("permitted", True))
        allowed_calls = total_calls - blocked_calls

        return {
            "session_id":   str(uuid4()),
            "raw_intent":   scope.raw_intent,
            "confidence":   scope.confidence,
            "scope":        scope.to_dict(),
            "events":       audit_log,
            "summary": {
                "total_calls":   total_calls,
                "blocked_calls": blocked_calls,
                "allowed_calls": allowed_calls,
            },
            "ts":           time.time(),
            "sdk_version":  SDK_VERSION,
        }

    def shutdown(self, timeout: float = 2.0) -> None:
        """
        Gracefully flush the queue and stop the worker thread.

        Call this on process shutdown to send any remaining events.
        Safe to call even if telemetry is disabled.

        Args:
            timeout: Seconds to wait for the worker to finish.
        """
        if not self.enabled:
            return
        try:
            self._queue.put(self._sentinel, timeout=0.5)
            self._worker.join(timeout=timeout)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _drain(self) -> None:
        """
        Background worker — dequeues and POSTs events continuously.

        Runs as a daemon thread; exits cleanly when the sentinel is received
        or on process exit. All HTTP errors are silently swallowed.
        """
        while True:
            try:
                event = self._queue.get(timeout=1.0)
                if event is self._sentinel:
                    break
                self._post(event)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.debug("TelemetryClient worker error (silenced): %s", exc)

    def _post(self, event: Dict[str, Any]) -> None:
        """
        Perform the HTTP POST to the Jercept API. All exceptions are silenced.

        Args:
            event: The event payload to send.
        """
        try:
            import urllib.request, json as _json
            data = _json.dumps(event, default=str).encode()
            req = urllib.request.Request(
                TELEMETRY_ENDPOINT,
                data=data,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type":  "application/json",
                    "X-Jercept-SDK": SDK_VERSION,
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
            logger.debug(
                "Telemetry sent — session=%s", event.get("session_id", "?")
            )
        except Exception as exc:
            logger.debug("Telemetry POST failed (silenced): %s", exc)
