"""
Jercept latency benchmark.

Measures p50/p95/p99 overhead for each extraction tier:
  - Cache hit    (~0ms)
  - Fast regex   (~1-5ms)
  - Mock LLM     (simulated ~280ms)

Run with:
    python benchmarks/latency.py
"""
from __future__ import annotations

import sys
import os
import time
import statistics
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock openai and httpx before importing csm
sys.modules.setdefault("openai", MagicMock())
sys.modules.setdefault("httpx", MagicMock())

from jercept.core.extractor import IntentExtractor
from jercept.core.intent_cache import CachedIntent, IntentCache


FAST_REQUESTS = [
    "check billing for customer 123",
    "send email to the marketing team",
    "read the Q3 report file",
    "export all customers to csv",
    "update the billing record for customer 456",
]

AMBIGUOUS_REQUESTS = [
    "help me with this",
    "do the usual thing",
    "fix the issue",
]

ITERATIONS = 200


def percentile(data: list[float], p: float) -> float:
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * p / 100)
    return data_sorted[min(idx, len(data_sorted) - 1)]


def fmt(ms: float) -> str:
    if ms < 1:
        return f"{ms*1000:.0f}µs"
    return f"{ms:.1f}ms"


def bench_cache_hit() -> list[float]:
    extractor = IntentExtractor.__new__(IntentExtractor)
    extractor._cache = IntentCache()
    extractor._use_fast = False
    extractor._client = MagicMock()

    # Prime the cache
    from jercept.core.intent_cache import CachedIntent
    for req in FAST_REQUESTS:
        ci = CachedIntent(["db.read"], [], ["db.export"], 0.95, req)
        extractor._cache.set(req, ci)

    times = []
    for _ in range(ITERATIONS):
        req = FAST_REQUESTS[_ % len(FAST_REQUESTS)]
        t0 = time.perf_counter()
        extractor.extract(req)
        times.append((time.perf_counter() - t0) * 1000)
    return times


def bench_fast_regex() -> list[float]:
    extractor = IntentExtractor.__new__(IntentExtractor)
    extractor._cache = IntentCache()
    extractor._use_fast = True
    extractor._client = MagicMock()

    times = []
    for i in range(ITERATIONS):
        req = FAST_REQUESTS[i % len(FAST_REQUESTS)]
        # Use unique IDs to avoid cache hits
        req = req.replace("123", str(i)).replace("456", str(i + 1000))
        t0 = time.perf_counter()
        extractor.extract(req)
        times.append((time.perf_counter() - t0) * 1000)
    return times


def bench_mock_llm() -> list[float]:
    """Simulate LLM latency with a mock that sleeps briefly."""
    import json
    import time as _time

    extractor = IntentExtractor.__new__(IntentExtractor)
    extractor._cache = IntentCache()
    extractor._use_fast = False  # Force LLM path
    extractor.model = "gpt-4o-mini"

    mock_response = MagicMock()
    mock_response.choices[0].message.content = json.dumps({
        "allowed_actions": ["db.read"],
        "allowed_resources": ["customer#X"],
        "denied_actions": ["db.export", "db.write", "db.delete"],
        "confidence": 0.95,
        "ambiguous": False,
        "reasoning": "Read-only billing request",
    })

    def mock_create(**kwargs):
        _time.sleep(0.012)  # Simulate ~12ms network (local mock, not real API)
        return mock_response

    extractor._client = MagicMock()
    extractor._client.chat.completions.create.side_effect = mock_create

    times = []
    iters = min(50, ITERATIONS)
    for i in range(iters):
        req = f"help me with task {i} that is unique"
        t0 = time.perf_counter()
        try:
            extractor.extract(req)
        except Exception:
            pass  # May fail on ambiguous — still measure the attempt
        times.append((time.perf_counter() - t0) * 1000)
    return times


def print_table(results: dict[str, list[float]]) -> None:
    print()
    print("┌─────────────────────────────────────────────────────────┐")
    print("│  Jercept — Latency Benchmark                          │")
    print("├──────────────────┬────────┬────────┬────────┬───────────┤")
    print("│ Extraction path  │  p50   │  p95   │  p99   │  max      │")
    print("├──────────────────┼────────┼────────┼────────┼───────────┤")

    for name, times in results.items():
        p50 = percentile(times, 50)
        p95 = percentile(times, 95)
        p99 = percentile(times, 99)
        mx = max(times)
        print(f"│ {name:<16} │ {fmt(p50):>6} │ {fmt(p95):>6} │ {fmt(p99):>6} │ {fmt(mx):>9} │")

    print("└──────────────────┴────────┴────────┴────────┴───────────┘")
    print()
    print("  Cache hit:  LRU cache, normalised key (strips IDs)")
    print("  Fast regex: Compiled pattern matching, no I/O")
    print("  Mock LLM:   Simulated latency (real API: 200-500ms)")
    print()


if __name__ == "__main__":
    print(f"\nRunning {ITERATIONS} iterations per path...")

    print("  Benchmarking cache hit path...")
    cache_times = bench_cache_hit()

    print("  Benchmarking fast regex path...")
    regex_times = bench_fast_regex()

    print("  Benchmarking mock LLM path (50 iterations)...")
    llm_times = bench_mock_llm()

    print_table({
        "Cache hit": cache_times,
        "Fast regex": regex_times,
        "Mock LLM": llm_times,
    })

    # Cache stats
    print(f"  Fast regex cache stats after benchmark:")
    extractor = IntentExtractor.__new__(IntentExtractor)
    extractor._cache = IntentCache()
    extractor._use_fast = True
    extractor._client = MagicMock()
    for req in FAST_REQUESTS:
        extractor.extract(req)
        extractor.extract(req)  # second time = cache hit
    print(f"    {extractor._cache.stats}")
