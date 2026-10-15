"""In-process background-job store shared by the long-running report tools.

``scm_asbuilt_report``, ``scm_drift_check``, ``scm_config_index`` and
``scm_panorama_migrate`` start a daemon thread and hand back a short job id;
their ``*_result`` tools read it back. One store per job kind, all built here:

* Finished jobs expire after an hour. A running job is never pruned, because
  its thread still writes to it, and :meth:`JobStore.update` on a job that
  has gone is a no-op rather than a ``KeyError`` in that thread.
* :meth:`JobStore.get` returns a copy, so a reader never sees a half-written
  update.
* The result tools take no tenant, so the store never lists its ids: a
  not-found answer naming other jobs would hand one tenant's job ids (and so
  its reports) to whoever asks about another.

This module is excluded from ``scm_reload`` so jobs survive a hot reload: the
store instances below are the same objects before and after.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any

JOB_TTL = 3600  # seconds a finished job is kept


class JobStore:
    """Thread-safe ``job id -> metadata`` map with expiry of finished jobs."""

    def __init__(self, ttl: float = JOB_TTL) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.ttl = ttl

    def create(self, **meta: Any) -> str:
        """Prune, then add a running job; returns its id."""
        self.prune()
        job_id = uuid.uuid4().hex[:8]
        with self._lock:
            while job_id in self._jobs:
                job_id = uuid.uuid4().hex[:8]
            self._jobs[job_id] = {
                "status": "running",
                "started_at": time.time(),
                "result": None,
                "error": None,
                **meta,
            }
        return job_id

    def get(self, job_id: str) -> dict[str, Any]:
        """A copy of the job, or ``{}`` when unknown or expired."""
        with self._lock:
            return dict(self._jobs.get(job_id, {}))

    def update(self, job_id: str, **fields: Any) -> None:
        """Merge *fields* into the job; a no-op when it is gone."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.update(fields)

    def prune(self, now: float | None = None) -> None:
        """Drop finished jobs older than the TTL; running jobs are kept."""
        cutoff = (time.time() if now is None else now) - self.ttl
        with self._lock:
            for jid in [
                j
                for j, meta in self._jobs.items()
                if meta["started_at"] < cutoff and meta["status"] != "running"
            ]:
                del self._jobs[jid]

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()

    def __contains__(self, job_id: object) -> bool:
        with self._lock:
            return job_id in self._jobs

    def __len__(self) -> int:
        with self._lock:
            return len(self._jobs)


def not_found(kind: str, job_id: str) -> str:
    """The unknown-id answer. It never names other jobs (see the module docstring)."""
    return f"{kind} `{job_id}` not found (finished jobs expire after 1 hour)."


ASBUILT_JOBS = JobStore()
DRIFT_JOBS = JobStore()
INDEX_JOBS = JobStore()
MIGRATE_JOBS = JobStore()
