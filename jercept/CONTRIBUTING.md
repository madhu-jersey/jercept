# Contributing to Jercept

Thank you for your interest in Jercept. This guide gets you from zero to running tests in under 5 minutes.

---

## Local development setup

```bash
# 1. Clone
git clone https://github.com/jercept/jercept
cd jercept

# 2. Create a virtual environment (Python 3.11 or 3.12)
python3.11 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install the package + dev dependencies in editable mode
pip install -e ".[dev]"

# 4. Run the full test suite
pytest tests/ -v

# 5. Run the demo (requires OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
python examples/demo_attack_blocked.py
```

---

## Running specific tests

```bash
# One file
pytest tests/test_scope.py -v

# One test
pytest tests/test_scope.py::TestIBACScope::test_permits_basic -v

# All security fixes
pytest tests/test_security_fixes.py -v

# Cross-language vectors
pytest tests/test_cross_language_vectors.py -v

# With coverage
pytest tests/ --cov=jercept --cov-report=term-missing
```

---

## CLI (after `pip install -e .`)

```bash
# Preview what scope a request would generate
jercept preview "check billing for customer 123"
jercept preview "send email to marketing" --provider anthropic
jercept preview "run the script" --provider ollama --model llama3

# Lint a policy YAML
jercept lint policies/billing.yaml

# Version info
jercept version
```

---

## Project structure

```
jercept/                  Python SDK
├── core/
│   ├── scope.py          IBACScope — the permission boundary
│   ├── enforcer.py       IBACEnforcer — runtime tool-call gating
│   ├── extractor.py      IntentExtractor — 3-tier LLM pipeline
│   ├── fast_extractor.py Regex tier (~1ms, zero LLM cost)
│   ├── injection_scanner.py 12-group injection detection
│   ├── conversation.py   ConversationScope — multi-turn sessions
│   └── providers.py      OpenAI / Anthropic / Gemini / Ollama
├── adapters/             LangChain / OpenAI Agents / CrewAI / AutoGen / LlamaIndex / MCP
├── policy.py             IBACPolicy — enterprise policy ceilings
├── linter.py             Policy linter — 9 lint rules
├── cli.py                jercept preview / lint / version
├── logging.py            Structured JSON logging
└── telemetry/            Dashboard telemetry (fire-and-forget)

jercept-dashboard/        SaaS dashboard backend + frontend
├── backend/
│   ├── main.py           FastAPI app
│   ├── auth.py           API key hashing (SHA-256, never plaintext)
│   ├── crypto.py         Fernet field encryption
│   ├── models.py         SQLAlchemy models
│   ├── database.py       Async PostgreSQL / SQLite
│   ├── migrations/       Versioned migration runner
│   └── routes/           events / dashboard / keys / webhooks
└── frontend/             Vanilla JS single-page dashboard

jercept-js/               TypeScript/JavaScript SDK
├── src/
│   ├── scope.ts          IBACScope — identical logic to Python
│   ├── scanner.ts        Injection scanner
│   ├── fast-extractor.ts Regex tier
│   ├── extractor.ts      LLM tier (OpenAI/Anthropic/Gemini/Ollama)
│   ├── enforcer.ts       IBACEnforcer
│   ├── linter.ts         Policy linter
│   └── protect.ts        protectAgent() — main entry point
└── tests/
    └── cross_language_vectors.test.js  Parity tests with Python SDK

tests/                    Python test suite (493 tests)
examples/                 Runnable demos
```

---

## Making a change

1. **Write the test first.** Every change needs a test in `tests/`.
2. **Run the test** to confirm it fails: `pytest tests/test_your_file.py -v`
3. **Implement the fix.**
4. **Run all tests** to confirm nothing broke: `pytest tests/ -v`
5. **Open a PR** targeting `main`.

---

## Security issues

Please report security vulnerabilities privately to **security@jercept.com** — do not open a public GitHub issue. We aim to respond within 48 hours.

See [SECURITY.md](SECURITY.md) for our full disclosure policy.

---

## Code standards

- **Type hints**: 100% coverage required on all public functions
- **Docstrings**: All public functions must have docstrings
- **Tests**: All new code must have tests — no untested paths in core/
- **No hardcoded secrets**: Use environment variables
- **No `datetime.utcnow()`**: Use `datetime.now(timezone.utc)` (Python 3.12 deprecation)
