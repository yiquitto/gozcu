"""
Reasoning Engine — AI Pipeline Orchestrator.

Orchestrates the 3-stage threat analysis pipeline:
  [1] Pre-Filter → [2] Cache Lookup → [3] LLM API Call

Each stage can short-circuit, avoiding unnecessary downstream work.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import aiohttp

from gozcu.models.telemetry_event import TelemetryEvent
from gozcu.models.threat_assessment import ThreatAssessment
from gozcu.ai.pre_filter import PreFilterEngine
from gozcu.ai.response_cache import ResponseCache
from gozcu.ai.prompt_templates import SYSTEM_PROMPT, build_user_prompt
from gozcu.ai.output_validator import validate_llm_output

logger = logging.getLogger(__name__)

# Defaults
_DEFAULT_TIMEOUT = 60  # seconds
_MAX_RETRIES = 3
_MAX_CONCURRENT = 5


class ReasoningEngine:
    """
    3-stage AI analysis pipeline orchestrator.

    Stage 1: Pre-Filter (rule-based, instant)
    Stage 2: Cache Lookup (TTL-based, instant)
    Stage 3: LLM API Call (async, with retry and rate limiting)
    # burasi sistemin en zeki kismi. 3 asamali bir zeka hatti kurdum:
    # 1. pre-filter (basit kurallar)
    # 2. cache (daha once gorduysek hizlica hatirla)
    # 3. gercek llm (eger yukaridaki ikisinden gecemediyse yapay zekaya sor)
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        pre_filter: PreFilterEngine,
        cache: ResponseCache,
        timeout: int = _DEFAULT_TIMEOUT,
        max_concurrent: int = _MAX_CONCURRENT,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._pre_filter = pre_filter
        self._cache = cache
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._session: Optional[aiohttp.ClientSession] = None
        self._stats = {"pre_filtered": 0, "cache_hits": 0, "llm_calls": 0, "llm_errors": 0}

    async def _get_session(self) -> aiohttp.ClientSession:
        """Lazy-initialize the aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            )
        return self._session

    async def analyze(
        self,
        event: TelemetryEvent,
        force_analysis: bool = False,
    ) -> ThreatAssessment:
        """
        Analyze a TelemetryEvent through the 3-stage pipeline.

        Args:
            event: The telemetry event to analyze.
            force_analysis: If True, bypass Pre-Filter and Cache.

        Returns:
            ThreatAssessment with classification results.
        """
        # Stage 1: Pre-Filter
        if not force_analysis:
            pf_result = self._pre_filter.check(event)
            if pf_result is not None:
                self._stats["pre_filtered"] += 1
                logger.debug("Pipeline: Pre-Filter HIT", extra={"event_id": event.event_id})
                return pf_result

        # Stage 2: Cache Lookup
        if not force_analysis:
            cached = await self._cache.get(event)
            if cached is not None:
                self._stats["cache_hits"] += 1
                logger.debug("Pipeline: Cache HIT", extra={"event_id": event.event_id})
                return cached

        # Stage 3: LLM API Call
        logger.debug("Pipeline: calling LLM", extra={"event_id": event.event_id})
        assessment = await self._call_llm(event)

        # Store in cache (high-risk filtering handled by cache itself)
        await self._cache.put(event, assessment)

        return assessment

    async def _call_llm(self, event: TelemetryEvent) -> ThreatAssessment:
        """Call the LLM API with retry and rate limiting."""
        # burasi yerel yapay zekaya baglandigim fonksiyon.
        # timeout suresini 60 saniyeye cikardim ki sistem agir ataklari analiz ederken patlamasin.
        user_prompt = build_user_prompt(event)
        payload = {
            "model": self._model,
            "messages": [
                {"role": "user", "content": f"{SYSTEM_PROMPT}\n\n{user_prompt}"},
            ],
            "temperature": 0.1,
            "max_tokens": 300,
        }

        last_error: Optional[Exception] = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with self._semaphore:
                    session = await self._get_session()
                    url = f"{self._base_url}/chat/completions"

                    async with session.post(url, json=payload) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            logger.warning(
                                f"LLM API returned {resp.status} (attempt {attempt})",
                                extra={"event_id": event.event_id, "body": body[:200]},
                            )
                            last_error = Exception(f"HTTP {resp.status}: {body[:200]}")
                            if attempt < _MAX_RETRIES:
                                await asyncio.sleep(2 ** attempt)
                                continue
                            break

                        data = await resp.json()
                        raw_content = data["choices"][0]["message"]["content"]

                        self._stats["llm_calls"] += 1
                        return validate_llm_output(raw_content, event.event_id)

            except asyncio.TimeoutError:
                # eger yapay zeka zamaninda cevap veremezse sistemi durdurmamasi icin timeout hatasini yakaliyorum.
                logger.warning(
                    f"LLM API timeout (attempt {attempt}/{_MAX_RETRIES})",
                    extra={"event_id": event.event_id},
                )
                last_error = asyncio.TimeoutError()
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(2 ** attempt)

            except aiohttp.ClientError as e:
                logger.error(
                    f"LLM API connection error: {e} (attempt {attempt}/{_MAX_RETRIES})",
                    extra={"event_id": event.event_id},
                )
                last_error = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(2 ** attempt)

            except Exception as e:
                logger.exception(
                    f"Unexpected LLM error: {e}",
                    extra={"event_id": event.event_id},
                )
                last_error = e
                break

        # All retries failed — return safe fallback
        self._stats["llm_errors"] += 1
        reason = f"LLM unavailable after {_MAX_RETRIES} attempts: {last_error}"
        return ThreatAssessment.benign_fallback(event.event_id, reason)

    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Aggregate stats from all pipeline stages."""
        return {
            "engine": dict(self._stats),
            "pre_filter": self._pre_filter.get_stats(),
            "cache": self._cache.get_stats(),
        }

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
