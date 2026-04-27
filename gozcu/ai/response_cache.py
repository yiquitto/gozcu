"""
Response Cache (TTL-based).

Caches LLM analysis results keyed by (source_ip + event_type + path) to
avoid redundant API calls for repeated similar events. High-risk results
(threat_score >= threshold) are NEVER cached to prevent evasion.

Pipeline position: Pre-Filter → [2] Cache → LLM
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, Dict, Optional

from cachetools import TTLCache

from gozcu.models.telemetry_event import TelemetryEvent
from gozcu.models.threat_assessment import ThreatAssessment

logger = logging.getLogger(__name__)


class ResponseCache:
    """
    TTL-based cache for LLM threat analysis results.

    Key: SHA-256 of (source_ip + event_type + normalized_path)
    Constraint: Results with threat_score >= high_risk_threshold are never cached.
    """

    def __init__(
        self,
        ttl_seconds: int = 300,
        max_size: int = 1024,
        high_risk_threshold: int = 70,
    ) -> None:
        self._cache: TTLCache = TTLCache(maxsize=max_size, ttl=ttl_seconds)
        self._lock = asyncio.Lock()
        self._high_risk_threshold = high_risk_threshold
        self._ip_to_keys: Dict[str, set] = {}  # source_ip -> set of cache keys
        self._stats = {"hits": 0, "misses": 0, "stores": 0, "skipped_high_risk": 0}

    @staticmethod
    def _build_key(event: TelemetryEvent) -> str:
        """Build a cache key from event characteristics."""
        # ayni logu defalarca llm'e gondermemek icin ip, tip ve path uzerinden sha256 hash olusturup benzersiz bir cache anahtari (key) uretiyorum.
        nd = event.normalized_data
        path = nd.get("path", "") or nd.get("uri", "") or nd.get("message", "")
        event_type = nd.get("format", event.source_type.value)
        raw_key = f"{event.source_ip}|{event_type}|{path}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    async def get(self, event: TelemetryEvent) -> Optional[ThreatAssessment]:
        """
        Look up a cached assessment for the given event.

        Returns the cached ThreatAssessment on HIT, None on MISS.
        """
        key = self._build_key(event)
        async with self._lock:
            cached = self._cache.get(key)

        if cached is not None:
            self._stats["hits"] += 1
            logger.debug("Cache HIT", extra={"event_id": event.event_id})
            # Return a copy with updated event_id and source marker
            return ThreatAssessment(
                event_id=event.event_id,
                category=cached.category,
                threat_score=cached.threat_score,
                confidence=cached.confidence,
                reasoning=f"Cache HIT — {cached.reasoning}",
                recommended_action=cached.recommended_action,
                source="cache",
                raw_llm_response=cached.raw_llm_response,
            )

        self._stats["misses"] += 1
        return None

    async def put(self, event: TelemetryEvent, assessment: ThreatAssessment) -> None:
        """
        Store an assessment in the cache.

        High-risk results (threat_score >= threshold) are NEVER cached.
        """
        # hocaya not: eger risk skoru yuksekse bunu ASLA cache'e almiyorum. saldirganin cache zehirleme (cache poisoning) yontemiyle tespit mekanizmasini atlatmasini engelliyorum.
        if assessment.threat_score >= self._high_risk_threshold:
            self._stats["skipped_high_risk"] += 1
            logger.debug(
                "Skipping cache store — high risk",
                extra={"event_id": event.event_id, "threat_score": assessment.threat_score},
            )
            return

        key = self._build_key(event)
        async with self._lock:
            self._cache[key] = assessment
            # Track key -> IP mapping for invalidation
            ip = event.source_ip
            if ip not in self._ip_to_keys:
                self._ip_to_keys[ip] = set()
            self._ip_to_keys[ip].add(key)
        self._stats["stores"] += 1

    async def invalidate(self, source_ip: str) -> int:
        """
        Invalidate all cached entries for a specific source IP.

        Returns the number of entries removed.
        """
        removed = 0
        async with self._lock:
            keys = self._ip_to_keys.pop(source_ip, set())
            for k in keys:
                if k in self._cache:
                    del self._cache[k]
                    removed += 1
        if removed:
            logger.info(f"Invalidated {removed} cache entries for IP {source_ip}")
        return removed

    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total * 100) if total > 0 else 0.0
        return {
            **self._stats,
            "current_size": len(self._cache),
            "hit_rate_percent": round(hit_rate, 1),
        }
