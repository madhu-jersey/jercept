"""
Tests for architecture and code quality fixes applied in v1.2.0.
"""
from __future__ import annotations
import json
import sys
import types
from unittest.mock import MagicMock

import pytest

stub = types.ModuleType("openai")
stub.OpenAI = MagicMock; stub.AsyncOpenAI = MagicMock
sys.modules.setdefault("openai", stub)


# ── ConversationScope persistence ────────────────────────────────────────────
class TestConversationScopePersistence:
    def setup_method(self):
        from jercept.core.conversation import ConversationScope, ExpansionMode
        from jercept.core.scope import IBACScope
        self.CS  = ConversationScope
        self.EM  = ExpansionMode
        self.IS  = IBACScope

    def _base_scope(self, **kw):
        return self.IS(allowed_actions=("db.read",), denied_actions=(),
                       allowed_resources=(), raw_intent="test", confidence=0.9, **kw)

    def test_to_dict_returns_serialisable(self):
        s = self.CS("book flight", expansion_mode=self.EM.CONFIRM)
        s.begin_turn(self._base_scope())
        d = s.to_dict()
        json.dumps(d)           # must not raise

    def test_from_dict_restores_turn(self):
        s = self.CS("test", expansion_mode=self.EM.DENY)
        s.begin_turn(self._base_scope())
        s.begin_turn(self._base_scope())
        d = s.to_dict()
        r = self.CS.from_dict(d)
        assert r.turn == s.turn

    def test_from_dict_restores_initial_request(self):
        s = self.CS("check billing for customer 123", expansion_mode=self.EM.DENY)
        d = s.to_dict()
        r = self.CS.from_dict(d)
        assert r.initial_request == "check billing for customer 123"

    def test_from_dict_restores_approved_actions(self):
        from jercept.core.conversation import ScopeExpansionRequest
        s = self.CS("book", expansion_mode=self.EM.CONFIRM)
        s.begin_turn(self._base_scope())
        try:
            s.handle_expansion("email.send", None, "tool")
        except ScopeExpansionRequest as req:
            s.approve(req)
        d = s.to_dict()
        r = self.CS.from_dict(d)
        assert "email.send" in r.approved_actions

    def test_from_dict_restores_current_scope(self):
        s = self.CS("test", expansion_mode=self.EM.DENY)
        s.begin_turn(self._base_scope())
        d = s.to_dict()
        r = self.CS.from_dict(d)
        assert r.current_scope is not None
        assert "db.read" in r.current_scope.allowed_actions

    def test_round_trip_json(self):
        """Full round-trip through JSON serialisation."""
        s = self.CS("check billing", expansion_mode=self.EM.DENY)
        s.begin_turn(self._base_scope())
        raw = json.dumps(s.to_dict())
        r = self.CS.from_dict(json.loads(raw))
        assert r.initial_request == "check billing"
        assert r.current_scope is not None


# ── VALID_ACTIONS DRY fix ─────────────────────────────────────────────────────
class TestValidActionsDRY:
    def test_policy_imports_valid_actions_from_scope(self):
        """policy.py must NOT redefine VALID_ACTIONS — import from scope.py."""
        from jercept.policy import VALID_ACTIONS as policy_va
        from jercept.core.scope import VALID_ACTIONS as scope_va
        assert policy_va == scope_va, "DRY violation: VALID_ACTIONS differs"

    def test_all_actions_sorted_from_valid_actions(self):
        from jercept.policy import ALL_ACTIONS
        from jercept.core.scope import VALID_ACTIONS
        assert set(ALL_ACTIONS) == VALID_ACTIONS


# ── Docstring coverage ────────────────────────────────────────────────────────
class TestDocstringCoverage:
    def test_100_percent_docstrings(self):
        import ast, os
        missing = []
        for root, dirs, files in os.walk("jercept"):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                if not f.endswith(".py"): continue
                src = open(os.path.join(root, f)).read()
                try:
                    tree = ast.parse(src)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith("_") and not ast.get_docstring(node):
                            missing.append(f"{f}:{node.name}")
        assert not missing, f"Missing docstrings: {missing}"


# ── Cross-language vectors ────────────────────────────────────────────────────
class TestCrossLanguageVectors:
    VECTORS = [
        ("db.read",            "customer#123", ["db.read"],  [],            ["customer.*"], True),
        ("db.export",          None,           ["db.*"],     ["db.export"], [],             False),
        ("db.write",           None,           ["db.*"],     [],            [],             True),
        ("db.read",            "admin#1",      ["db.read"],  [],            ["customer.*"], False),
        ("DB.READ",            None,           ["db.read"],  [],            [],             True),
        (None,                 None,           ["db.read"],  [],            [],             False),
        ("",                   None,           ["db.read"],  [],            [],             False),
        ("   ",                None,           ["db.read"],  [],            [],             False),
        ("db.read;db.export",  None,           ["db.read"],  [],            [],             False),
        ("code.execute",       None,           ["db.read"],  [],            [],             False),
        ("db.delete",          "customer#123", ["db.*"],     ["db.delete"], ["customer.*"], False),
        ("db.read",            None,           [],           [],            [],             False),
    ]

    @pytest.mark.parametrize("action,resource,allowed,denied,resources,expected", VECTORS)
    def test_cross_language_vector(self, action, resource, allowed, denied, resources, expected):
        from jercept.core.scope import IBACScope
        scope = IBACScope(allowed_actions=allowed, denied_actions=denied,
                          allowed_resources=resources)
        assert scope.permits(action, resource) == expected


# ── Migration runner ──────────────────────────────────────────────────────────
class TestMigrationRunner:
    def test_migration_file_exists(self):
        import os
        assert os.path.exists(
            "jercept-dashboard/backend/migrations/run.py"
        ), "migration runner missing"

    def test_migrations_list_has_all_versions(self):
        import sys, importlib.util
        spec = importlib.util.spec_from_file_location(
            "run",
            "jercept-dashboard/backend/migrations/run.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        versions = [v for v, _, _ in m.MIGRATIONS]
        assert "0001" in versions
        assert "0002" in versions  # scope visualizer columns
        assert "0003" in versions  # webhooks
        assert len(versions) >= 4

    def test_dry_run_does_not_raise(self, tmp_path):
        import os, importlib.util
        db_path = str(tmp_path / "test.db")
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        spec = importlib.util.spec_from_file_location(
            "run",
            "jercept-dashboard/backend/migrations/run.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        rc = m.run(dry_run=True)
        assert rc == 0
        os.environ.pop("DATABASE_URL", None)


# ── CORS configuration ────────────────────────────────────────────────────────
class TestCORSConfig:
    def test_no_wildcard_in_main(self):
        content = open("jercept-dashboard/backend/main.py").read()
        assert 'allow_origins=["*"]' not in content

    def test_env_var_driven_cors(self):
        content = open("jercept-dashboard/backend/main.py").read()
        assert "ALLOWED_ORIGINS" in content
        assert 'os.getenv("ALLOWED_ORIGINS"' in content

    def test_api_version_middleware(self):
        content = open("jercept-dashboard/backend/main.py").read()
        assert "X-API-Version" in content
        assert "add_api_version_header" in content


# ── sys.path management ───────────────────────────────────────────────────────
class TestSysPathManagement:
    def test_main_py_configures_sys_path(self):
        content = open("jercept-dashboard/backend/main.py").read()
        assert "sys.path" in content
        assert "_BACKEND" in content or "BACKEND_DIR" in content or "backend" in content.lower()
