"""Tests for RecursiveQueue signature, worker lifecycle, and parameter discovery."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from jseye.core.dedupe import DedupeEngine
from jseye.core.recursive_queue import RecursiveQueue
from jseye.core.scope import ScopeEngine


def test_recursive_queue_initialization_flexibility():
    scope = ScopeEngine("https://example.com")
    dedupe = DedupeEngine()

    # Positional args
    q1 = RecursiveQueue(scope, dedupe, concurrency=10, timeout=5)
    assert q1.concurrency == 10
    assert q1.scope == scope

    # Keyword args (as passed by crawler)
    q2 = RecursiveQueue(
        scope_engine=scope,
        dedupe_engine=dedupe,
        max_depth=3,
        max_requests=100,
        threads=15,
        headless=True
    )
    assert q2.concurrency == 15
    assert q2.max_depth == 3
    assert q2.headless is True


@pytest.mark.asyncio
async def test_start_crawl_alias_and_return_structure():
    scope = ScopeEngine("https://example.com")
    dedupe = DedupeEngine()

    queue = RecursiveQueue(
        scope_engine=scope,
        dedupe_engine=dedupe,
        threads=5,
        timeout=2
    )

    # Mock empty seed crawl
    res = await queue.start_crawl([])
    assert "js_files" in res
    assert "endpoints" in res
    assert "parameters" in res
    assert "stats" in res
    assert isinstance(res["js_files"], list)
    assert isinstance(res["endpoints"], list)
    assert isinstance(res["parameters"], list)


def test_extract_params_from_url():
    scope = ScopeEngine("https://example.com")
    queue = RecursiveQueue(scope=scope)

    queue._extract_params_from_url("https://example.com/search?q=test&filter=active&page=1")
    assert "q" in queue.parameters
    assert "filter" in queue.parameters
    assert "page" in queue.parameters


@pytest.mark.asyncio
async def test_worker_task_done_single_call_on_exception():
    scope = ScopeEngine("https://example.com")
    dedupe = DedupeEngine()
    queue_engine = RecursiveQueue(scope=scope, dedupe=dedupe)

    async_queue = asyncio.Queue()
    await async_queue.put(("https://example.com/fail", 0))

    session_mock = MagicMock()

    # Patch _process_url to raise an exception
    with patch.object(queue_engine, "_process_url", side_effect=RuntimeError("Network error")):
        worker_task = asyncio.create_task(queue_engine._worker(session_mock, async_queue))
        # Wait for queue to be marked done. If task_done() is called more than once,
        # ValueError: task_done() called too many times would be raised.
        await async_queue.join()
        worker_task.cancel()
        await asyncio.gather(worker_task, return_exceptions=True)

    # Verification: queue.join() succeeded without task_done() overflow
    assert async_queue.empty()

