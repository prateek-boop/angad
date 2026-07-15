"""Bounded daemon worker pool for blocking model and network operations.

Keras inference is already serialized by ``ThreatDetectionModel``'s own lock
(see ml_engine/model.py), so this pool does not need ``workers=1`` to keep TF
safe — that would just re-serialize everything behind a second, redundant
bottleneck. Sizing it for real concurrency lets Tier 1-4 network evidence
(reputation/redirect/HTML/visual fetches, each up to several seconds) run in
parallel with each other and with the (internally serialized) model call.
Daemon workers do not make interpreter shutdown depend on asyncio's default
executor.
"""

from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import Callable

import config


class WorkerPoolBusy(RuntimeError):
    pass


class DaemonWorkerPool:
    def __init__(self, workers: int = 4, max_queue: int = 100):
        if workers < 1 or max_queue < 1:
            raise ValueError("workers and max_queue must be positive")
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._worker_count = workers
        self._threads = []
        self._start_lock = threading.Lock()

    def _ensure_started(self) -> None:
        if self._threads:
            return
        with self._start_lock:
            if self._threads:
                return
            for index in range(self._worker_count):
                thread = threading.Thread(
                    target=self._worker,
                    name=f"shieldnet-api-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)

    def _worker(self) -> None:
        while True:
            callback, function, args, kwargs = self._queue.get()
            result = None
            error = None
            try:
                result = function(*args, **kwargs)
            except BaseException as exc:
                error = exc
            finally:
                self._queue.task_done()
            callback(result, error)

    async def run(self, function: Callable, *args, **kwargs):
        self._ensure_started()
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()

        def deliver(result, error) -> None:
            def _set() -> None:
                if future.done():
                    return
                if error is not None:
                    future.set_exception(error)
                else:
                    future.set_result(result)

            loop.call_soon_threadsafe(_set)

        try:
            self._queue.put_nowait((deliver, function, args, kwargs))
        except queue.Full as exc:
            raise WorkerPoolBusy("ShieldNet worker queue is full") from exc
        return await future


# Scale API throughput horizontally too (multiple worker processes/replicas);
# each process keeps its own model and its own bounded queue.
worker_pool = DaemonWorkerPool(workers=config.API_WORKER_POOL_SIZE)
