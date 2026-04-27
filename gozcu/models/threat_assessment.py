"""
ThreatAssessment Model.

Represents the AI analysis result for a single TelemetryEvent.
Produced by one of three sources: pre_filter, cache, or llm.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gozcu.models.enums import ThreatCategory


class ThreatAssessment(BaseModel):
    """AI-generated threat analysis for a telemetry event."""
    # hocaya not: yapay zekanin (llm) dondurdugu analiz sonucunu (json) bu kati veri modeline (pydantic) oturtuyorum. eger llm skorlari sacmalarsa (mesela 150 verirse) @field_validator ile kendim 0-100 arasina (clamp) hapsediyorum.

    model_config = ConfigDict(frozen=True)

    # Identity — links back to the originating event
    event_id: str = Field(..., description="UUID of the assessed TelemetryEvent")

    # Classification
    category: ThreatCategory = Field(default=ThreatCategory.BENIGN)
    threat_score: int = Field(
        default=0,
        description="Threat severity score (0=benign, 100=critical). Clamped by validator.",
    )
    confidence: float = Field(
        default=0.0,
        description="AI confidence level (0.0=unknown, 1.0=certain). Clamped by validator.",
    )

    # Reasoning
    reasoning: str = Field(
        default="",
        description="AI explanation of the classification",
    )
    recommended_action: str = Field(
        default="MONITOR",
        description="Suggested mitigation action",
    )

    # Provenance — which pipeline stage produced this result
    source: Literal["pre_filter", "cache", "llm"] = Field(
        default="llm",
        description="Pipeline stage that generated this assessment",
    )

    # Debug
    raw_llm_response: str = Field(
        default="",
        description="Raw LLM API response text for debugging",
    )

    @field_validator("threat_score")
    @classmethod
    def clamp_threat_score(cls, v: int) -> int:
        """Ensure threat_score stays within 0-100 range."""
        return max(0, min(100, v))

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        """Ensure confidence stays within 0.0-1.0 range."""
        return max(0.0, min(1.0, v))

    @property
    def is_high_risk(self) -> bool:
        """Check if this assessment exceeds the high-risk threshold (70)."""
        return self.threat_score >= 70

    @classmethod
    def benign_fallback(cls, event_id: str, reason: str, source: str = "llm") -> ThreatAssessment:
        """Create a safe fallback assessment when analysis fails."""
        return cls(
            event_id=event_id,
            category=ThreatCategory.BENIGN,
            threat_score=0,
            confidence=0.0,
            reasoning=reason,
            recommended_action="MONITOR",
            source=source,
        )
