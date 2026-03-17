"""
Tests for csm.telemetry.notifier.WebhookNotifier — v0.4.0.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from jercept.telemetry.notifier import WebhookNotifier
from jercept.core.scope import IBACScope
from jercept.core.enforcer import IBACEnforcer


def _make_scope(intent: str = "check billing") -> IBACScope:
    return IBACScope(
        allowed_actions=["db.read"],
        allowed_resources=["customer.*"],
        denied_actions=["db.export"],
        raw_intent=intent,
        confidence=0.95,
        ambiguous=False,
    )


def _make_enforcer_with_blocked(scope: IBACScope) -> IBACEnforcer:
    """Return an enforcer that has one blocked action in its audit log."""
    enforcer = IBACEnforcer(scope)
    enforcer.audit_log.append({
        "ts": time.time(),
        "action": "db.export",
        "resource": "customers",
        "permitted": False,
        "fn_name": "export_all",
    })
    return enforcer


def _make_clean_enforcer(scope: IBACScope) -> IBACEnforcer:
    """Return an enforcer with only permitted actions."""
    enforcer = IBACEnforcer(scope)
    enforcer.audit_log.append({
        "ts": time.time(),
        "action": "db.read",
        "resource": "customer#123",
        "permitted": True,
        "fn_name": "read_billing",
    })
    return enforcer


class TestWebhookNotifierInit:
    def test_valid_https_url(self):
        n = WebhookNotifier(url="https://hooks.example.com/abc")
        assert n.url == "https://hooks.example.com/abc"

    def test_valid_http_url(self):
        n = WebhookNotifier(url="http://localhost:8080/webhook")
        assert n.url.startswith("http://")

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="valid http"):
            WebhookNotifier(url="not-a-url")

    def test_empty_url_raises(self):
        with pytest.raises(ValueError):
            WebhookNotifier(url="")

    def test_defaults(self):
        n = WebhookNotifier(url="https://example.com/wh")
        assert n.min_risk_score == 0.0
        assert n.include_intent is True

    def test_custom_min_risk_score(self):
        n = WebhookNotifier(url="https://example.com/wh", min_risk_score=0.8)
        assert n.min_risk_score == 0.8

    def test_include_intent_false(self):
        n = WebhookNotifier(url="https://example.com/wh", include_intent=False)
        assert n.include_intent is False


class TestNotifyNoBlock:
    """notify() must be a no-op when nothing was blocked."""

    def test_no_op_when_nothing_blocked(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_clean_enforcer(scope)
        with patch.object(n, "_post") as mock_post:
            n.notify(enforcer, scope)
            mock_post.assert_not_called()

    def test_no_op_empty_audit_log(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = IBACEnforcer(scope)  # empty audit log
        with patch.object(n, "_post") as mock_post:
            n.notify(enforcer, scope)
            mock_post.assert_not_called()


class TestNotifyFiresOnBlock:
    """notify() must fire _post when blocked actions exist."""

    def test_fires_on_blocked_action(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        with patch("threading.Thread") as mock_thread:
            mock_instance = MagicMock()
            mock_thread.return_value = mock_instance
            n.notify(enforcer, scope)
            mock_thread.assert_called_once()
            mock_instance.start.assert_called_once()

    def test_thread_is_daemon(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            n.notify(enforcer, scope)
            _, kwargs = mock_thread.call_args
            assert kwargs.get("daemon") is True


class TestPayloadContents:
    """_build_payload must produce correct structure."""

    def test_payload_has_required_fields(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope("check billing for customer 123")
        enforcer = _make_enforcer_with_blocked(scope)
        blocked = [e for e in enforcer.audit_log if not e.get("permitted")]
        payload = n._build_payload(blocked, scope, None)

        assert payload["alert_type"] == "ibac_scope_violation"
        assert "session_id" in payload
        assert "ts" in payload
        assert payload["blocked_count"] == 1
        assert "db.export" in payload["blocked_actions"]
        assert "intent" in payload
        assert "text" in payload  # Slack-compatible field

    def test_intent_included_by_default(self):
        n = WebhookNotifier(url="https://example.com/wh", include_intent=True)
        scope = _make_scope("check billing for customer 123")
        enforcer = _make_enforcer_with_blocked(scope)
        blocked = [e for e in enforcer.audit_log if not e.get("permitted")]
        payload = n._build_payload(blocked, scope, None)
        assert "check billing" in payload["intent"]

    def test_intent_redacted_when_disabled(self):
        n = WebhookNotifier(url="https://example.com/wh", include_intent=False)
        scope = _make_scope("check billing for customer 123")
        enforcer = _make_enforcer_with_blocked(scope)
        blocked = [e for e in enforcer.audit_log if not e.get("permitted")]
        payload = n._build_payload(blocked, scope, None)
        assert payload["intent"] == "[redacted]"

    def test_scan_result_included_when_provided(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        blocked = [e for e in enforcer.audit_log if not e.get("permitted")]

        scan = MagicMock()
        scan.risk_score = 0.9
        scan.matched_patterns = ["role_override"]
        scan.is_suspicious = True

        payload = n._build_payload(blocked, scope, scan)
        assert "scan" in payload
        assert payload["scan"]["risk_score"] == 0.9
        assert "role_override" in payload["scan"]["matched_patterns"]

    def test_slack_text_mentions_blocked_action(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        blocked = [e for e in enforcer.audit_log if not e.get("permitted")]
        payload = n._build_payload(blocked, scope, None)
        assert "db.export" in payload["text"]


class TestMinRiskScoreFilter:
    """notify() must respect min_risk_score threshold."""

    def test_fires_when_score_above_threshold(self):
        n = WebhookNotifier(url="https://example.com/wh", min_risk_score=0.5)
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        scan = MagicMock()
        scan.risk_score = 0.9
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            n.notify(enforcer, scope, scan_result=scan)
            mock_thread.assert_called_once()

    def test_no_op_when_score_below_threshold(self):
        n = WebhookNotifier(url="https://example.com/wh", min_risk_score=0.8)
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        scan = MagicMock()
        scan.risk_score = 0.3  # below threshold
        with patch("threading.Thread") as mock_thread:
            n.notify(enforcer, scope, scan_result=scan)
            mock_thread.assert_not_called()


class TestNeverRaises:
    """_post and notify must never raise regardless of httpx failures."""

    def test_post_swallows_httpx_error(self):
        n = WebhookNotifier(url="https://example.com/wh")
        with patch("httpx.post", side_effect=Exception("network error")):
            n._post({"alert_type": "test"})   # must not raise

    def test_notify_swallows_all_errors(self):
        n = WebhookNotifier(url="https://example.com/wh")
        scope = _make_scope()
        enforcer = _make_enforcer_with_blocked(scope)
        # Even if _post throws, notify must not propagate
        with patch.object(n, "_post", side_effect=RuntimeError("boom")):
            # notify() fires in a thread; the thread swallows it
            # Just verify notify itself doesn't raise
            n.notify(enforcer, scope)
