"""
Lightweight in-process scheduler for automatic detection + correlation.

Deliberately not a scheduling library (APScheduler, Celery, etc.) - the
job is "run this synchronous code every N seconds, forever, one cycle at
a time," which a plain asyncio loop does with less machinery and a
*stronger* overlap guarantee than a wall-clock-scheduled job: the loop
only sleeps again after a cycle fully finishes, so there is no case where
two cycles run concurrently to begin with.

Reuses app.detection.query_loader.load_rules, app.detection.executor.
execute_rule, app.detection.alert_generator.generate_alerts, and
app.correlation.engine.run_correlation exactly as they already exist -
nothing about those modules changes. Duplicate-alert prevention is
already handled by generate_alerts' own _duplicate_exists check, and
run_correlation already only considers alerts not yet linked to an
incident, so repeated cycles are safe by construction.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.correlation.engine import run_correlation
from app.detection.alert_generator import generate_alerts
from app.detection.executor import RuleExecutionError, execute_rule
from app.detection.query_loader import load_rules

logger = logging.getLogger("app.scheduler")


def _run_cycle_sync() -> None:
    """One full detection + correlation pass. Runs on a worker thread."""
    logger.info("Automatic detection/correlation cycle starting")

    rules = load_rules()
    total_alerts = 0

    for rule in rules:
        try:
            response = execute_rule(rule)
        except RuleExecutionError as exc:
            logger.error("Rule %r failed to execute: %s", rule.get("name"), exc)
            continue

        try:
            new_alerts = generate_alerts(rule, response)
        except Exception:
            logger.exception("Rule %r failed while generating alerts", rule.get("name"))
            continue

        total_alerts += len(new_alerts)

    try:
        new_incidents = run_correlation()
    except Exception:
        logger.exception("Correlation pass failed")
        new_incidents = []

    logger.info(
        "Cycle complete: %d rule(s) evaluated, %d alert(s) created, %d incident(s) created",
        len(rules),
        total_alerts,
        len(new_incidents),
    )


async def _scheduler_loop() -> None:
    interval = settings.detection_interval_seconds
    logger.info("Automatic detection/correlation scheduler started (interval=%ss)", interval)
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(_run_cycle_sync)
        except Exception:
            # Belt-and-suspenders: _run_cycle_sync already catches per-rule
            # and correlation errors, but a truly unexpected failure here
            # must not kill the loop - just log and try again next interval.
            logger.exception("Unexpected error in scheduler cycle")


@asynccontextmanager
async def lifespan(app: FastAPI):
    task: asyncio.Task | None = None

    if settings.enable_scheduler:
        task = asyncio.create_task(_scheduler_loop())
    else:
        logger.info("Automatic detection/correlation scheduler disabled (ENABLE_SCHEDULER=false)")

    yield

    if task is not None:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
