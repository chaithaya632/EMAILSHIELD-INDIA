"""
worker/__main__.py
Executable package entrypoint for EMAILSHIELD Sentinel External Worker:
    python -m worker
"""

from worker.service import WorkerService

if __name__ == "__main__":
    WorkerService.run_cli()
