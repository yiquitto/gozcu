"""
LLM Output Validator.

Validates and parses the raw LLM response into a ThreatAssessment.
Handles malformed JSON, out-of-range values, and invalid categories
with safe fallback defaults.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from gozcu.models.enums import ThreatCategory
from gozcu.models.threat_assessment import ThreatAssessment

logger = logging.getLogger(__name__)

# Valid category values for quick lookup
_VALID_CATEGORIES = {c.value for c in ThreatCategory}

# Regex to extract JSON from markdown-wrapped responses
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def validate_llm_output(
    raw_response: str,
    event_id: str,
) -> ThreatAssessment:
    """
    Parse and validate LLM output into a ThreatAssessment.

    Attempts multiple extraction strategies and falls back to BENIGN
    with confidence=0.0 if all parsing fails.
    """
    if not raw_response or not raw_response.strip():
        logger.warning("Empty LLM response", extra={"event_id": event_id})
        return ThreatAssessment.benign_fallback(event_id, "Empty LLM response")

    # Try to extract JSON
    data = _extract_json(raw_response)
    if data is None:
        logger.warning("Could not extract JSON from LLM response", extra={"event_id": event_id})
        return ThreatAssessment.benign_fallback(
            event_id,
            f"JSON parse failed: {raw_response[:100]}",
        )

    # Validate and extract fields
    category = _validate_category(data.get("category", ""))
    threat_score = _validate_score(data.get("threat_score", 0))
    confidence = _validate_confidence(data.get("confidence", 0.0))
    reasoning = str(data.get("reasoning", ""))[:500]
    recommended_action = str(data.get("recommended_action", "MONITOR"))[:100]

    return ThreatAssessment(
        event_id=event_id,
        category=category,
        threat_score=threat_score,
        confidence=confidence,
        reasoning=reasoning,
        recommended_action=recommended_action,
        source="llm",
        raw_llm_response=raw_response[:1000],
    )


def _extract_json(text: str) -> Optional[dict]:
    """Try multiple strategies to extract a JSON object from text."""
    text = text.strip()

    # Strategy 1: Direct JSON parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code block
    match = _JSON_BLOCK_RE.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find first JSON object in text
    match = _JSON_OBJECT_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def _validate_category(raw: str) -> ThreatCategory:
    """Validate category string, default to BENIGN."""
    upper = str(raw).upper().strip()
    if upper in _VALID_CATEGORIES:
        return ThreatCategory(upper)
    logger.debug(f"Invalid category '{raw}', defaulting to BENIGN")
    return ThreatCategory.BENIGN


def _validate_score(raw) -> int:
    """Validate threat score, clamp to 0-100."""
    try:
        score = int(raw)
        return max(0, min(100, score))
    except (ValueError, TypeError):
        return 0


def _validate_confidence(raw) -> float:
    """Validate confidence, clamp to 0.0-1.0."""
    try:
        conf = float(raw)
        return max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        return 0.0
