# Changelog

## [1.2.0] — 2026-03-17

### Security Fixes
- **CRITICAL**: `IBACScope` fields changed from `List[str]` to `tuple[str,...]` — true immutability enforced
- **CRITICAL**: Fast extractor never grants `db.export`, `db.delete`, or `file.download` — hard FORBIDDEN set
- **CRITICAL**: `ConversationScope` AUTO mode without explicit policy now applies a safe default ceiling
- **HIGH**: LLM output cross-validated against fast extractor — jailbroken LLM cannot grant unexpected permissions
- **HIGH**: ReDoS fixed — base64 pattern capped, all `.{0,N}` spans reduced, 50K input: 3900ms → 32ms
- **HIGH**: Injection scanner extended: full-width Unicode, soft hyphens, RAG injection, authority claims
- CORS wildcard removed — `ALLOWED_ORIGINS` env var required in production
- `/v1/keys` rate-limited to 10/hour per IP
- Event batch capped at 500 items — DoS via batch flooding blocked
- Webhook URLs encrypted at rest with Fernet (set `JERCEPT_ENCRYPTION_KEY`)
- XSS: `escapeHtml()` added to all user-controlled fields in dashboard frontend
- API key moved from `localStorage` to `sessionStorage`

### Performance Fixes
- `IBACScope.permits()`: regex patterns pre-compiled once at construction — 10,000 `re.compile()` calls eliminated per session
- `IBACEnforcer.audit_log`: `list.pop(0)` O(n) replaced with `collections.deque(maxlen=1000)` O(1)
- Dashboard `scope_timeline`: O(n²) nested loop replaced with O(n) `defaultdict` single pass
- `TelemetryClient`: unbounded per-event daemon threads replaced with single bounded-queue worker
- `IntentCache._make_key()`: `@lru_cache(maxsize=512)` eliminates re.sub on hot paths
- `IBACPolicy.apply()`: `@cached_property` for ceiling denial list — computed once per policy instance

### Bug Fixes
- `datetime.utcnow()` (deprecated in Python 3.12) replaced with `datetime.now(timezone.utc)`
- `protect.py` module docstring updated from v0.3.0 to v1.2.0
- `email: str` in `/v1/keys` replaced with `email: EmailStr`
- Dashboard `scope_timeline` fixed: corrupted duplicate function removed, clean rewrite
- `events.py` route: corrupted duplicate section removed, clean rewrite with all field validators

### Architecture
- `ConversationScope.to_dict()` / `from_dict()` added — sessions now serialisable for Redis/DB persistence
- Versioned migration runner (`migrations/run.py`) with `_jercept_migrations` tracking table
- `VALID_ACTIONS` DRY violation fixed — `policy.py` imports from `scope.py` instead of redefining
- `sys.path` management in `main.py` — dashboard works regardless of working directory
- `X-API-Version: v1` header added to all responses via middleware
- Cross-language test vectors (`tests/test_cross_language_vectors.py` ↔ `jercept-js/tests/cross_language_vectors.test.js`)
- `crypto.py` module with Fernet field-level encryption for sensitive dashboard data

### Code Quality
- Docstring coverage: 91% → **100%** (82/82 public functions)
- Type hint coverage: **100%** (unchanged)
- Tests: 475 → **500** (+25 new tests for all fixes)
- JS SDK version bumped to 1.2.0

---

## [1.0.0] — 2026-03-17 — Production Release

### Breaking changes
- Version bumped from 0.1.0 to 1.0.0
- `ScanResult` now has a `truncated` field (additive — no breakage)
- `protect_agent()` now accepts `llm_provider` and `**provider_kwargs`

### New features

**Multi-LLM provider support** — No longer requires OpenAI.
- `llm_provider="anthropic"` — Anthropic Claude (haiku, sonnet, opus)
- `llm_provider="gemini"` — Google Gemini (flash, pro)
- `llm_provider="ollama"` — Local Ollama (llama3, mistral, phi3 — no API key)
- `llm_provider="openai"` — OpenAI (default, unchanged)

**Policy linter** — Catch dangerous configs before deploy.
- `from jercept.linter import lint_policy, lint_yaml`
- `IBACPolicy.lint()` — 9 rules covering wildcards, conflicts, low confidence
- `jercept lint policies/billing.yaml` — CLI command

**CLI** — Developer experience tools.
- `jercept preview "check billing for customer 123"` — show scope without running
- `jercept lint policies/billing.yaml` — validate policy files
- `jercept version` — show version and all supported providers

**Expanded injection detection** — From 5 to 10 pattern groups.
- base64_obfuscation — detects base64-encoded injection strings
- indirect_injection — ChatML tags, INST tags, markdown heading injection
- prompt_chaining — multi-hop attack patterns
- permission_escalation — sudo, admin escalation, role claim attacks
- social_engineering — "for testing purposes", emergency override patterns

**LLM extraction retry** — 3 retries with exponential backoff (0.5s, 1s, 2s).
Auth errors are not retried. Prevents transient API failures from crashing agents.

**Markdown fence stripping** — Extracts JSON from providers that wrap it in ```json fences.

### Bug fixes

**Wildcard danger warning** — `IBACScope(allowed_actions=["db.*"])` now logs a
WARNING listing which dangerous actions (db.export, db.delete, code.execute,
file.download) are implicitly included. Pass them in denied_actions to suppress.

**Input length cap** — All inputs truncated to 10,000 chars before scanning.
Prevents DoS via huge inputs. Truncation is flagged in ScanResult.truncated.
100K char input: 51ms → <5ms.

**9 missing docstrings** — All ProtectedAgent properties now have docstrings.

**Duplicate protect_agent code removed** — protect.py had a stale duplicate
function body from v0.3. Removed.

### v0.1.0 — 2026-03-17 — Initial release

- IBAC core (IBACScope, IBACEnforcer, IntentExtractor 3-tier pipeline)
- Multi-turn ConversationScope (ExpansionMode AUTO/CONFIRM/DENY)
- IBACPolicy with from_dict() and from_yaml()
- AsyncIntentExtractor (non-blocking)
- Injection scanner with homoglyph normalisation
- Semantic scanner (optional LLM classifier)
- @ibac_tool decorator
- Adapters: LangChain, OpenAI Agents SDK, CrewAI, AutoGen, LlamaIndex, MCP
- SaaS dashboard backend (FastAPI + rate limiting + webhooks)
- 321 tests across 18 files
