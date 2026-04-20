"""
GÖZCÜ — Main Entry Point.

Initializes all components, wires them together, and runs the
async event processing pipeline. In demo mode, feeds sample logs
through the full pipeline to demonstrate the system.

Usage:
    python -m gozcu.main
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from typing import Optional

from gozcu.config import Config
from gozcu.models import (
    TelemetryEvent, ThreatAssessment, Decision,
    SourceType, DecisionState,
)
from gozcu.ingestion.log_ingestor import LogIngestor
from gozcu.ai.pre_filter import PreFilterEngine
from gozcu.ai.response_cache import ResponseCache
from gozcu.ai.reasoning_engine import ReasoningEngine
from gozcu.decision.whitelist import WhitelistManager
from gozcu.decision.action_executor import ActionExecutor
from gozcu.decision.state_machine import DecisionStateMachine
from gozcu.audit.audit_trail import AuditTrail

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-30s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gozcu.main")


class GozcuPipeline:
    """
    Main application pipeline.

    Wires all components together and processes events through:
    Ingest → Analyze → Decide (if high-risk) → Audit
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._queue: asyncio.Queue[tuple[str, SourceType, str]] = asyncio.Queue(maxsize=1000)
        self._running = False
        self._broadcast_fn = None  # Will be set by dashboard

        # Initialize components
        self._ingestor = LogIngestor()
        self._pre_filter = PreFilterEngine(enabled=config.PRE_FILTER_ENABLED)
        self._cache = ResponseCache(
            ttl_seconds=config.CACHE_TTL_SECONDS,
            max_size=config.CACHE_MAX_SIZE,
            high_risk_threshold=config.HIGH_RISK_THRESHOLD,
        )
        self._engine = ReasoningEngine(
            api_key=config.LLM_API_KEY,
            model=config.LLM_MODEL,
            base_url=config.LLM_BASE_URL,
            pre_filter=self._pre_filter,
            cache=self._cache,
        )

        self._whitelist = WhitelistManager()
        self._whitelist.load(config.WHITELIST_PATH)

        self._executor = ActionExecutor(
            whitelist=self._whitelist,
            simulation_mode=config.SIMULATION_MODE,
        )

        self._audit = AuditTrail(log_path=config.AUDIT_LOG_PATH)

        self._state_machine = DecisionStateMachine(
            executor=self._executor,
            audit=self._audit,
            timeout_seconds=config.DECISION_TIMEOUT,
            confidence_threshold=config.AUTONOMOUS_CONFIDENCE_THRESHOLD,
        )

        # Event/decision stores for dashboard
        self._events: list[dict] = []
        self._assessments: dict[str, ThreatAssessment] = {}

    def set_broadcast(self, fn) -> None:
        """Set the WebSocket broadcast function (called by dashboard)."""
        self._broadcast_fn = fn
        self._state_machine._broadcast = fn

    async def submit(self, raw_data: str, source_type: SourceType, source_ip: str = "0.0.0.0") -> None:
        """Submit a raw log entry to the processing queue."""
        await self._queue.put((raw_data, source_type, source_ip))

    async def process_event(self, raw_data: str, source_type: SourceType, source_ip: str = "0.0.0.0") -> Optional[dict]:
        """
        Process a single event through the full pipeline.

        Returns a summary dict of the processing result.
        """
        # Step 1: Ingest
        event = await self._ingestor.ingest(raw_data, source_type, source_ip)
        if event is None:
            return None

        # Step 2: Analyze
        assessment = await self._engine.analyze(event)
        self._assessments[event.event_id] = assessment

        # Build event summary
        summary = {
            "event_id": event.event_id,
            "source_type": event.source_type.value,
            "source_ip": event.source_ip,
            "timestamp": event.timestamp,
            "threat_score": assessment.threat_score,
            "confidence": assessment.confidence,
            "category": assessment.category.value,
            "reasoning": assessment.reasoning,
            "source": assessment.source,
            "normalized_data": event.normalized_data,
        }
        self._events.append(summary)

        # Broadcast new event to dashboard
        if self._broadcast_fn:
            try:
                await self._broadcast_fn({"type": "new_event", **summary})
            except Exception:
                pass

        # Step 3: Decision (only for high-risk events)
        if assessment.is_high_risk:
            logger.warning(
                f"HIGH RISK EVENT: score={assessment.threat_score}, "
                f"category={assessment.category.value}, ip={event.source_ip}",
            )
            decision = Decision(event_id=event.event_id)
            
            # Start countdown as a background task to prevent blocking the worker pipeline
            asyncio.create_task(
                self._state_machine.start_countdown(
                    decision, assessment, source_ip=event.source_ip,
                )
            )
            
            summary["decision"] = {
                "decision_id": decision.decision_id,
                "state": decision.state.value,
                "resolved_by": decision.resolved_by,
                "action_taken": decision.action_taken,
            }
        else:
            # Low-risk: log to audit as MONITOR
            await self._audit.log_decision(
                event_id=event.event_id,
                decision_id="N/A",
                action="MONITOR",
                actor="GOZCU:AUTO_LOW_RISK",
                threat_score=assessment.threat_score,
                confidence=assessment.confidence,
                ai_reasoning=assessment.reasoning,
                outcome="Low risk - monitoring only",
            )

        return summary

    async def _worker(self) -> None:
        """Background worker that processes events from the queue."""
        while self._running:
            try:
                raw_data, source_type, source_ip = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0,
                )
                await self.process_event(raw_data, source_type, source_ip)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.exception(f"Worker error: {e}")

    async def start(self, num_workers: int = 3) -> list[asyncio.Task]:
        """Start background workers."""
        self._running = True
        tasks = []
        for i in range(num_workers):
            tasks.append(asyncio.create_task(self._worker()))
        logger.info(f"Pipeline started with {num_workers} workers")
        return tasks

    async def stop(self, tasks: list[asyncio.Task]) -> None:
        """Gracefully stop the pipeline."""
        self._running = False
        # Wait for queue to drain
        if not self._queue.empty():
            logger.info("Waiting for queue to drain...")
            await self._queue.join()
        # Cancel workers
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Close AI engine session
        await self._engine.close()
        logger.info("Pipeline stopped")

    def get_stats(self) -> dict:
        """Aggregate stats from all components."""
        return {
            "ingestion": self._ingestor.get_stats(),
            "pipeline": self._engine.get_pipeline_stats(),
            "whitelist": self._whitelist.get_summary(),
            "audit": self._audit.get_stats(),
            "events_processed": len(self._events),
            "active_decisions": self._state_machine.get_active_decisions(),
            "simulation_mode": self._config.SIMULATION_MODE,
        }

    def get_events(self) -> list[dict]:
        """Return all processed events."""
        return list(self._events)

    def get_active_decisions(self) -> list[dict]:
        """Return active pending decisions."""
        return self._state_machine.get_active_decisions()

    def approve_decision(self, decision_id: str, analyst: str) -> bool:
        """Approve a pending decision."""
        return self._state_machine.approve(decision_id, analyst)

    def reject_decision(self, decision_id: str, analyst: str) -> bool:
        """Reject a pending decision."""
        return self._state_machine.reject(decision_id, analyst)

    async def get_audit_history(self) -> list[dict]:
        """Return audit records from disk."""
        return await self._audit.get_all_from_disk()


# --- Demo Mode -------------------------------------------------

DEMO_LOGS = [
    # 1. Health check (pre-filter will catch)
    ('{"remote_addr":"10.0.0.1","method":"GET","uri":"/health","status":200,"http_user_agent":"kube-probe/1.28"}',
     SourceType.WEB_LOG, "10.0.0.1"),

    # 2. Static file (pre-filter will catch)
    ('{"remote_addr":"192.168.1.20","method":"GET","uri":"/assets/logo.png","status":200,"http_user_agent":"Mozilla/5.0"}',
     SourceType.WEB_LOG, "192.168.1.20"),

    # 3. Normal login (low risk — goes to LLM)
    ('{"remote_addr":"192.168.1.30","method":"POST","uri":"/api/login","status":200,"http_user_agent":"Mozilla/5.0"}',
     SourceType.WEB_LOG, "192.168.1.30"),

    # 4. SQL injection attempt (high risk)
    ('{"remote_addr":"45.33.32.156","method":"GET","uri":"/search?q=1\' OR 1=1--","status":200,"http_user_agent":"sqlmap/1.5"}',
     SourceType.WEB_LOG, "45.33.32.156"),

    # 5. Brute force (high risk — syslog)
    ('<38>1 2026-04-17T04:00:00Z webserver sshd 5432 AUTH Failed password for admin from 203.0.113.50 port 22',
     SourceType.SYSLOG, "203.0.113.50"),

    # 6. Repeated event (cache should catch on 2nd call)
    ('{"remote_addr":"192.168.1.30","method":"POST","uri":"/api/login","status":200,"http_user_agent":"Mozilla/5.0"}',
     SourceType.WEB_LOG, "192.168.1.30"),
]


async def run_demo() -> None:
    """Run GÖZCÜ in demo mode with sample logs."""
    config = Config()

    print("=" * 65)
    print("  GOZCU - Autonomous SOC - Demo Mode")
    print("=" * 65)
    print(f"  LLM: {config.LLM_BASE_URL} ({config.LLM_MODEL})")
    print(f"  Simulation: {config.SIMULATION_MODE}")
    print(f"  Decision Timeout: {config.DECISION_TIMEOUT}s")
    print(f"  Confidence Threshold: {config.AUTONOMOUS_CONFIDENCE_THRESHOLD}")
    print("=" * 65)
    print()

    pipeline = GozcuPipeline(config)

    for i, (raw, stype, ip) in enumerate(DEMO_LOGS, 1):
        print(f"\n{'-' * 50}")
        print(f"[LOG {i}/{len(DEMO_LOGS)}] Type={stype.value}, IP={ip}")
        print(f"{'-' * 50}")

        result = await pipeline.process_event(raw, stype, ip)
        if result is None:
            print("  -> Skipped (empty)")
            continue

        source_label = result["source"].upper()
        print(f"  Category:  {result['category']}")
        print(f"  Score:     {result['threat_score']}/100")
        print(f"  Confidence:{result['confidence']}")
        print(f"  Source:    {source_label}")
        print(f"  Reasoning: {result['reasoning'][:80]}")

        if "decision" in result:
            d = result["decision"]
            print(f"  DECISION:  {d['state']} (by {d['resolved_by']})")

    # Print stats
    stats = pipeline.get_stats()
    print(f"\n{'=' * 65}")
    print("  PIPELINE STATS")
    print(f"{'=' * 65}")
    pf = stats["pipeline"]["pre_filter"]
    cache = stats["pipeline"]["cache"]
    print(f"  Events processed: {stats['events_processed']}")
    print(f"  Pre-filtered:     {pf['filtered']}/{pf['checked']}")
    print(f"  Cache hits:       {cache['hits']}")
    print(f"  LLM calls:        {stats['pipeline']['engine']['llm_calls']}")
    print(f"  LLM errors:       {stats['pipeline']['engine']['llm_errors']}")
    print(f"  Audit records:    {stats['audit']['total_records']}")
    print(f"{'=' * 65}")

    await pipeline._engine.close()


def main() -> None:
    """Entry point."""
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
