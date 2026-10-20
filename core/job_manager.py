"""Unified durable job lifecycle manager for all LD-BP operations.

Durable asynchronous jobs for pool creation, pool deletion,
node operations, link modifications, and migrations with crash recovery.
"""
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from core.storage import atomic_update, load_data

JOB_STATUS_ACTIVE = {"queued", "running"}
JOB_STATUS_TERMINAL = {"succeeded", "failed", "rollback_failed"}

class DurableJobManager:
    """Manages persistent jobs across restarts and asynchronous web/CLI requests."""

    @staticmethod
    def create_job(job_type: str, target_id: str, params: Optional[dict] = None) -> dict:
        job_id = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        job = {
            "job_id": job_id,
            "job_type": job_type,
            "target_id": target_id,
            "status": "queued",
            "step": "job_created",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "params": params or {},
            "steps_completed": [],
        }

        def _update(data: dict):
            jobs = data.setdefault("persistent_jobs", {})
            jobs[job_id] = job

        atomic_update(_update)
        return job

    @staticmethod
    def update_job(
        job_id: str,
        status: Optional[str] = None,
        step: Optional[str] = None,
        error: Optional[str] = None,
        completed_step: Optional[str] = None,
    ) -> Optional[dict]:
        updated_job = None
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        def _update(data: dict):
            nonlocal updated_job
            jobs = data.setdefault("persistent_jobs", {})
            if job_id not in jobs:
                return
            j = jobs[job_id]
            if status:
                j["status"] = status
            if step:
                j["step"] = step
            if error is not None:
                j["error"] = error
            if completed_step and completed_step not in j.get("steps_completed", []):
                j.setdefault("steps_completed", []).append(completed_step)
            j["updated_at"] = now
            updated_job = dict(j)

        atomic_update(_update)
        return updated_job

    @staticmethod
    def get_job(job_id: str) -> Optional[dict]:
        data = load_data()
        return data.get("persistent_jobs", {}).get(job_id)

    @staticmethod
    def list_jobs(active_only: bool = False) -> List[dict]:
        data = load_data()
        jobs = list(data.get("persistent_jobs", {}).values())
        if active_only:
            return [j for j in jobs if j.get("status") in JOB_STATUS_ACTIVE]
        return jobs

    @staticmethod
    def recover_on_restart() -> List[dict]:
        """Detects jobs interrupted by daemon restarts and marks them with recovery guidance."""
        interrupted = []
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        def _update(data: dict):
            jobs = data.setdefault("persistent_jobs", {})
            for jid, j in jobs.items():
                if j.get("status") in JOB_STATUS_ACTIVE:
                    j["status"] = "failed"
                    j["error"] = "Interrupted by system/daemon restart before completion"
                    j["step"] = "interrupted_restart_recovery"
                    j["updated_at"] = now
                    interrupted.append(dict(j))

        atomic_update(_update)
        return interrupted
