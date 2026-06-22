"""Background scheduler for periodic tasks — threat intel sync, enrichment, cleanup."""
import asyncio
import time
import logging
from typing import Callable

logger = logging.getLogger("sentinelai.scheduler")


class Scheduler:
    def __init__(self):
        self._tasks: list[dict] = []
        self._running = False

    def schedule(self, name: str, func: Callable, interval_seconds: int, initial_delay: int = 0):
        self._tasks.append({
            "name": name,
            "func": func,
            "interval": interval_seconds,
            "initial_delay": initial_delay,
            "last_run": 0,
        })
        logger.info(f"Scheduled: {name} (every {interval_seconds}s)")

    async def start(self):
        self._running = True
        logger.info(f"Scheduler started with {len(self._tasks)} tasks")
        while self._running:
            now = time.time()
            for task in self._tasks:
                elapsed = now - task["last_run"]
                delay = task["initial_delay"] if task["last_run"] == 0 else task["interval"]
                if elapsed >= delay:
                    try:
                        if asyncio.iscoroutinefunction(task["func"]):
                            await task["func"]()
                        else:
                            task["func"]()
                        task["last_run"] = now
                        logger.debug(f"Task executed: {task['name']}")
                    except Exception as e:
                        logger.error(f"Task {task['name']} failed: {e}")
            await asyncio.sleep(10)

    def stop(self):
        self._running = False
        logger.info("Scheduler stopped")


scheduler = Scheduler()


async def _sync_threat_intel():
    """Periodically refresh threat intelligence cache."""
    try:
        from services.cache_service import cache_delete
        cache_delete("geoip:")
        cache_delete("intel:")
    except Exception:
        pass


async def _cleanup_old_data():
    """Clean up old broadcast queue entries."""
    from app import broadcast_queue
    while len(broadcast_queue) > 500:
        broadcast_queue.pop()


def setup_scheduler():
    """Register all background tasks."""
    scheduler.schedule("threat_intel_sync", _sync_threat_intel, interval_seconds=3600, initial_delay=60)
    scheduler.schedule("cleanup", _cleanup_old_data, interval_seconds=300, initial_delay=120)
