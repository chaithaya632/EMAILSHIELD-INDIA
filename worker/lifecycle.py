"""
worker/lifecycle.py
Independent OS Process Lifecycle Management for EMAILSHIELD INDIA Sentinel Worker.

Architectural Invariants:
1. The worker runs as an independent OS process (python -m worker).
2. Polling is NEVER executed inside Streamlit.
3. No Streamlit background threads are used.
4. Process liveness is strictly verified via OS PID checks.
"""

import os
import sys
import time
import signal
import subprocess
from typing import Tuple, Optional, Dict, Any

from worker.health import get_worker_runtime_info, is_pid_alive
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.lifecycle")


def get_worker_status() -> Dict[str, Any]:
    """Returns current worker process runtime info."""
    return get_worker_runtime_info()


def start_worker_process() -> Tuple[bool, str, Optional[int]]:
    """
    Ensures the independent Sentinel worker process (python -m worker) is running.
    If already running and healthy, returns immediately.
    Otherwise launches python -m worker as an independent detached OS process.
    """
    info = get_worker_runtime_info()
    if info.get("worker_process_alive"):
        pid = info.get("pid")
        logger.info("Worker process already running with PID %s.", pid)
        return True, f"Worker already running (PID: {pid})", pid

    # Clean up any stale lease from previous stopped process
    try:
        from worker.db import LocalWorkerDBClient
        loc = LocalWorkerDBClient()
        with loc._lock:
            for w in loc.workers.values():
                w["lease_owner"] = None
                w["lease_expires_at"] = None
                w["lease_token_hash"] = None
                w["actual_state"] = "STOPPED"
        loc._save_to_disk()
    except Exception:
        pass

    proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(proj_root, "data", "local")
    os.makedirs(log_dir, exist_ok=True)
    worker_log_file = os.path.join(log_dir, "worker.log")

    cmd = [sys.executable, "-m", "worker"]

    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        log_f = open(worker_log_file, "a", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=proj_root,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags
        )
        pid = proc.pid
        logger.info("Spawned independent worker process with PID %d.", pid)

        # Wait up to 3 seconds for worker to start and report running status
        start_time = time.time()
        while time.time() - start_time < 3.0:
            time.sleep(0.3)
            info = get_worker_runtime_info()
            if info.get("worker_process_alive"):
                return True, f"Worker started successfully (PID: {info.get('pid', pid)})", info.get("pid", pid)

        if is_pid_alive(pid):
            return True, f"Worker process alive (PID: {pid})", pid
        return False, "Worker process exited immediately. Check data/local/worker.log for details.", None

    except Exception as e:
        logger.error("Failed to launch worker process: %s", e)
        return False, f"Failed to start worker process: {str(e)}", None


def stop_worker_process() -> Tuple[bool, str]:
    """
    Gracefully halts the independent Sentinel worker process.
    """
    info = get_worker_runtime_info()
    pid = info.get("pid")
    if not pid or not info.get("worker_process_alive"):
        return True, "Worker process is not running."

    logger.info("Stopping worker process (PID: %d)...", pid)

    try:
        if sys.platform == "win32":
            # On Windows, SIGTERM might not be caught; attempt gentle terminate first, then taskkill
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
            time.sleep(0.5)
            if is_pid_alive(pid):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        else:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            if is_pid_alive(pid):
                os.kill(pid, signal.SIGKILL)

        # Update local runtime status
        runtime_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "local", "sentinel_worker_runtime.json"
        )
        if os.path.exists(runtime_path):
            import json
            try:
                with open(runtime_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["status"] = "STOPPED"
                data["pid"] = None
                with open(runtime_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

        try:
            from worker.db import LocalWorkerDBClient
            loc = LocalWorkerDBClient()
            with loc._lock:
                for w in loc.workers.values():
                    w["lease_owner"] = None
                    w["lease_expires_at"] = None
                    w["lease_token_hash"] = None
                    w["actual_state"] = "STOPPED"
            loc._save_to_disk()
        except Exception:
            pass

        return True, f"Worker process (PID {pid}) stopped."
    except Exception as e:
        logger.warning("Error stopping worker process %d: %s", pid, e)
        return False, f"Error stopping worker: {str(e)}"
