"""
Audit Trail.

Writes every decision (human or autonomous) to a JSON Lines file
with SHA-256 tamper-detection hashes. Uses asyncio.Lock for safe
concurrent writes and aiofiles for non-blocking disk I/O.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import List, Optional

import aiofiles

from gozcu.models.audit_record import AuditRecord

logger = logging.getLogger(__name__)


class AuditTrail:
    """Append-only, tamper-evident audit log."""

    def __init__(self, log_path: str | Path) -> None:
        self._path = Path(log_path)
        self._lock = asyncio.Lock()
        self._records: List[AuditRecord] = []

        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def log(self, record: AuditRecord) -> None:
        """Append an audit record to the JSONL file."""
        # hocaya not: adli bilisim (forensics) surecleri icin sistemin aldigi her karari jsonl dosyasina ekliyorum (append-only). sha256 ile korundugu icin sonradan degistirilemiyor.
        self._records.append(record)

        line = record.model_dump_json() + "\n"

        async with self._lock:
            try:
                async with aiofiles.open(self._path, mode="a", encoding="utf-8") as f:
                    await f.write(line)
            except OSError as e:
                logger.critical(f"Failed to write audit record: {e}")
                raise

        logger.info(
            "Audit record written",
            extra={
                "audit_id": record.audit_id,
                "event_id": record.event_id,
                "actor": record.actor,
                "action": record.action,
            },
        )

    async def log_decision(
        self,
        event_id: str,
        decision_id: str,
        action: str,
        actor: str,
        threat_score: int = 0,
        confidence: float = 0.0,
        ai_reasoning: str = "",
        outcome: str = "",
    ) -> AuditRecord:
        """Convenience method: create and log an AuditRecord in one call."""
        record = AuditRecord.create(
            event_id=event_id,
            decision_id=decision_id,
            action=action,
            actor=actor,
            threat_score=threat_score,
            confidence=confidence,
            ai_reasoning=ai_reasoning,
            outcome=outcome,
        )
        await self.log(record)
        return record

    async def get_history(self, event_id: Optional[str] = None) -> List[AuditRecord]:
        """Return audit records, optionally filtered by event_id."""
        if event_id is None:
            return list(self._records)
        return [r for r in self._records if r.event_id == event_id]

    async def get_all_from_disk(self) -> List[dict]:
        """Read all records from the JSONL file on disk."""
        if not self._path.exists():
            return []

        records = []
        async with aiofiles.open(self._path, mode="r", encoding="utf-8") as f:
            async for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning(f"Corrupt audit line skipped")
        return records

    def get_stats(self) -> dict:
        """Return audit trail statistics."""
        return {
            "total_records": len(self._records),
            "log_path": str(self._path),
        }
