"""Bounded daemon worker pool for blocking model and network operations.

The pool is deliberately small: Keras inference is serialized by its model
wrapper while network evidence can use the remaining workers. Daemon workers
do not make interpreter shutdown depend on asyncio's default executor.
"""

from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import Callable


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
            result_queue, function, args, kwargs = self._queue.get()
            result = None
            error = None
            try:
                result = function(*args, **kwargs)
            except BaseException as exc:
                error = exc
            finally:
                self._queue.task_done()
            result_queue.put((result, error))

    async def run(self, function: Callable, *args, **kwargs):
        self._ensure_started()
        result_queue: queue.Queue = queue.Queue(maxsize=1)
        try:
            self._queue.put_nowait((result_queue, function, args, kwargs))
        except queue.Full as exc:
            raise WorkerPoolBusy("ShieldNet worker queue is full") from exc
        while True:
            try:
                result, error = result_queue.get_nowait()
                if error is not None:
                    raise error
                return result
            except queue.Empty:
                await asyncio.sleep(0.002)


# TensorFlow 2.21's CPU runtime is stable when one initialized model is served
# from one worker thread. Scale API throughput with multiple worker processes;
# each process keeps its own model and bounded queue.
worker_pool = DaemonWorkerPool(workers=1)
