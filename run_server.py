"""
GÖZCÜ — Dashboard Launcher.

Starts the full application:
  1. Initializes the pipeline
  2. Starts the dashboard server
  3. Optionally feeds demo logs on startup

Usage:
    python run_server.py
    python run_server.py --demo                  (auto-feed sample logs)
    python run_server.py --stream <filepath>     (stream logs from file)
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from gozcu.config import Config
from gozcu.main import GozcuPipeline, DEMO_LOGS
from gozcu.dashboard.server import DashboardServer
from gozcu.ingestion.file_streamer import FileStreamer
from gozcu.models.enums import SourceType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-30s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gozcu.launcher")


async def run(demo_mode: bool = False, stream_file: str | None = None) -> None:
    """Start the dashboard and pipeline."""
    # hocaya not: butun sistemi (dashboard, log okuyucular, yapay zeka motoru) ayni anda, asenkron olarak ayaga kaldirdigim orkestrasyon merkezi burasi.
    config = Config()
    pipeline = GozcuPipeline(config)
    dashboard = DashboardServer(pipeline, config)

    # Start dashboard
    runner = await dashboard.start()
    logger.info(f"Dashboard: http://localhost:{config.DASHBOARD_PORT}")
    logger.info(f"Simulation mode: {config.SIMULATION_MODE}")

    # Start pipeline workers
    worker_tasks = await pipeline.start(num_workers=3)

    # Feed demo logs if requested
    if demo_mode:
        logger.info("Demo mode: feeding sample logs...")
        await asyncio.sleep(1)  # Let server settle
        for raw, stype, ip in DEMO_LOGS:
            await pipeline.submit(raw, stype, ip)
        logger.info(f"Submitted {len(DEMO_LOGS)} demo logs to queue")
        
    # Start file streaming if requested
    stream_task = None
    if stream_file:
        logger.info(f"Stream mode: setting up FileStreamer for {stream_file}...")
        # Determine SourceType based on file extension heuristically or default to SYSLOG
        stype = SourceType.WEB_LOG if str(stream_file).endswith('.jsonl') else SourceType.SYSLOG
        streamer = FileStreamer(filepath=stream_file, source_type=stype, delay_seconds=2.0)
        stream_task = asyncio.create_task(streamer.stream_to_pipeline(pipeline))

    # Keep running
    try:
        logger.info("GOZCU is running. Press Ctrl+C to stop.")
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down...")
    finally:
        if stream_task:
            stream_task.cancel()
        await pipeline.stop(worker_tasks)
        await runner.cleanup()
        logger.info("GOZCU stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="GÖZCÜ Dashboard Launcher")
    parser.add_argument("--demo", action="store_true", help="Auto-feed sample logs for demo")
    parser.add_argument("--stream", type=str, help="Stream logs continuously from the specified file")
    args = parser.parse_args()

    try:
        asyncio.run(run(demo_mode=args.demo, stream_file=args.stream))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
