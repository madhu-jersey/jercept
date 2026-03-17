"""
Unit tests for csm.decorators — @ibac_tool and get_declared_actions.
"""
from __future__ import annotations

import pytest
from jercept.decorators import ibac_tool, get_declared_actions, IBAC_ACTION_ATTR


class TestIbacToolDecorator:
    def test_sets_single_action(self):
        @ibac_tool("db.read")
        def tool_fn(): pass
        assert getattr(tool_fn, IBAC_ACTION_ATTR) == ["db.read"]

    def test_sets_multiple_actions(self):
        @ibac_tool("db.write", "email.send")
        def tool_fn(): pass
        assert getattr(tool_fn, IBAC_ACTION_ATTR) == ["db.write", "email.send"]

    def test_function_still_callable(self):
        @ibac_tool("db.read")
        def tool_fn(x): return x * 2
        assert tool_fn(5) == 10

    def test_invalid_action_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown IBAC action"):
            @ibac_tool("invalid.action")
            def bad(): pass

    def test_no_actions_raises_value_error(self):
        with pytest.raises(ValueError):
            @ibac_tool()
            def bad(): pass

    def test_all_valid_actions_accepted(self):
        valid = [
            "db.read", "db.write", "db.export", "db.delete",
            "file.read", "file.write", "file.upload", "file.download",
            "email.read", "email.send", "api.call", "web.browse", "code.execute",
        ]
        for action in valid:
            @ibac_tool(action)
            def fn(): pass
            assert get_declared_actions(fn) == [action]

    def test_preserves_function_name(self):
        @ibac_tool("db.read")
        def my_special_tool(): pass
        assert my_special_tool.__name__ == "my_special_tool"

    def test_preserves_docstring(self):
        @ibac_tool("db.read")
        def tool_fn():
            """Read customer data."""
        assert tool_fn.__doc__ == "Read customer data."


class TestGetDeclaredActions:
    def test_returns_none_for_plain_function(self):
        def plain(): pass
        assert get_declared_actions(plain) is None

    def test_returns_none_for_lambda(self):
        assert get_declared_actions(lambda: None) is None

    def test_returns_list_for_decorated_function(self):
        @ibac_tool("db.read")
        def tool_fn(): pass
        assert get_declared_actions(tool_fn) == ["db.read"]

    def test_returns_none_for_none_input(self):
        assert get_declared_actions(None) is None

    def test_first_action_is_primary(self):
        @ibac_tool("db.export", "file.write")
        def tool_fn(): pass
        actions = get_declared_actions(tool_fn)
        assert actions[0] == "db.export"
