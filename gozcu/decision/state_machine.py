"""
Decision State Machine — The 30-Second Rule.

Manages the lifecycle of high-risk decisions:
  PENDING → APPROVED (analyst) | REJECTED (analyst) | AUTONOMOUS | EXPIRED

When a high-risk event is detected, a 30-second countdown starts.
If the analyst responds in time, they control the outcome.
If the timer expires AND confidence > 0.90, the system acts autonomously.
If confidence <= 0.90, the decision expires without action.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional

from gozcu.models.decision import Decision
from gozcu.models.threat_assessment import ThreatAssessment
from gozcu.decision.action_executor import ActionExecutor, ActionResult
from gozcu.audit.audit_trail import AuditTrail

logger = logging.getLogger(__name__)


# Type for WebSocket broadcast callback
BroadcastFn = Callable[[dict], Coroutine[Any, Any, None]]


class DecisionStateMachine:
    """
    Orchestrates the 30-second decision countdown.

    For each high-risk event, creates a Decision, starts a timer,
    and waits for analyst input or timeout.
    """

    def __init__(
        self,
        executor: ActionExecutor,
        audit: AuditTrail,
        timeout_seconds: int = 30,
        confidence_threshold: float = 0.90,
        broadcast: Optional[BroadcastFn] = None,
    ) -> None:
        self._executor = executor
        self._audit = audit
        self._timeout = timeout_seconds
        self._confidence_threshold = confidence_threshold
        self._broadcast = broadcast

        # Active decisions keyed by decision_id
        self._active: Dict[str, _ActiveDecision] = {}
        self._history: List[Decision] = []

    async def start_countdown(
        self,
        decision: Decision,
        assessment: ThreatAssessment,
        source_ip: str = "0.0.0.0",
    ) -> Decision:
        """
        Start the 30-second countdown for a pending decision.

        Returns the finalized Decision after resolution.
        """
        resolved_event = asyncio.Event()
        active = _ActiveDecision(
            decision=decision,
            assessment=assessment,
            resolved_event=resolved_event,
            source_ip=source_ip,
        )
        self._active[decision.decision_id] = active

        logger.info(
            f"Countdown started: {self._timeout}s",
            extra={
                "decision_id": decision.decision_id,
                "event_id": decision.event_id,
                "threat_score": assessment.threat_score,
                "confidence": assessment.confidence,
            },
        )

        # Notify dashboard
        await self._notify("new_decision", {
            "decision_id": decision.decision_id,
            "event_id": decision.event_id,
            "threat_score": assessment.threat_score,
            "confidence": assessment.confidence,
            "recommended_action": assessment.recommended_action,
            "reasoning": assessment.reasoning,
            "timeout_seconds": self._timeout,
        })

        # Start countdown in background
        countdown_task = asyncio.create_task(
            self._countdown_loop(active)
        )

        # Wait for either analyst action or timeout
        try:
            await asyncio.wait_for(
                resolved_event.wait(),
                timeout=self._timeout,
            )
            # Analyst responded — cancel countdown ticks
            countdown_task.cancel()
        except asyncio.TimeoutError:
            # Timer expired
            countdown_task.cancel()
            await self._handle_timeout(active)

        # Cleanup
        self._active.pop(decision.decision_id, None)
        self._history.append(decision)

        # Log to audit trail
        await self._audit.log_decision(
            event_id=decision.event_id,
            decision_id=decision.decision_id,
            action=decision.action_taken or "NONE",
            actor=decision.resolved_by,
            threat_score=assessment.threat_score,
            confidence=assessment.confidence,
            ai_reasoning=assessment.reasoning,
            outcome=f"State: {decision.state.value}",
        )

        await self._notify("decision_update", {
            "decision_id": decision.decision_id,
            "state": decision.state.value,
            "resolved_by": decision.resolved_by,
            "action_taken": decision.action_taken,
        })

        return decision

    def approve(self, decision_id: str, analyst: str) -> bool:
        """Analyst approves the recommended action."""
        active = self._active.get(decision_id)
        if active is None or active.decision.is_resolved:
            return False

        active.decision.approve(analyst)
        active.resolved_event.set()

        logger.info(
            f"Decision APPROVED by {analyst}",
            extra={"decision_id": decision_id},
        )
        return True

    def reject(self, decision_id: str, analyst: str) -> bool:
        """Analyst rejects the recommended action."""
        active = self._active.get(decision_id)
        if active is None or active.decision.is_resolved:
            return False

        active.decision.reject(analyst)
        active.resolved_event.set()

        logger.info(
            f"Decision REJECTED by {analyst}",
            extra={"decision_id": decision_id},
        )
        return True

    async def _countdown_loop(self, active: _ActiveDecision) -> None:
        """Send countdown ticks every second to the dashboard."""
        try:
            for remaining in range(self._timeout, 0, -1):
                if active.decision.is_resolved:
                    return
                await self._notify("countdown_tick", {
                    "decision_id": active.decision.decision_id,
                    "remaining": remaining,
                })
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    async def _handle_timeout(self, active: _ActiveDecision) -> None:
        """Handle timeout — autonomous action or expiry based on confidence."""
        decision = active.decision
        assessment = active.assessment

        if assessment.confidence >= self._confidence_threshold:
            # High confidence — take autonomous action
            action = assessment.recommended_action
            logger.warning(
                f"AUTONOMOUS ACTION: {action} (confidence={assessment.confidence})",
                extra={
                    "decision_id": decision.decision_id,
                    "event_id": decision.event_id,
                },
            )

            # Execute via ActionExecutor (with whitelist protection)
            target = self._extract_target(active)
            result = await self._executor.execute(action, target)

            decision.mark_autonomous(action)
        else:
            # Low confidence — expire without action
            logger.info(
                f"Decision EXPIRED (confidence={assessment.confidence} < {self._confidence_threshold})",
                extra={"decision_id": decision.decision_id},
            )
            decision.mark_expired()

    @staticmethod
    def _extract_target(active: _ActiveDecision) -> str:
        """Extract the action target (source IP) from the active decision."""
        return active.source_ip

    async def _notify(self, msg_type: str, data: dict) -> None:
        """Broadcast a message to the dashboard via WebSocket."""
        if self._broadcast:
            try:
                await self._broadcast({"type": msg_type, **data})
            except Exception as e:
                logger.debug(f"Broadcast failed: {e}")

    def get_active_decisions(self) -> List[dict]:
        """Return all currently active (pending) decisions."""
        return [
            {
                "decision_id": a.decision.decision_id,
                "event_id": a.decision.event_id,
                "state": a.decision.state.value,
                "threat_score": a.assessment.threat_score,
                "confidence": a.assessment.confidence,
                "reasoning": a.assessment.reasoning,
            }
            for a in self._active.values()
        ]

    def get_history(self) -> List[Decision]:
        """Return all resolved decisions."""
        return list(self._history)


class _ActiveDecision:
    """Internal wrapper for a decision being tracked by the state machine."""

    __slots__ = ("decision", "assessment", "resolved_event", "source_ip")

    def __init__(
        self,
        decision: Decision,
        assessment: ThreatAssessment,
        resolved_event: asyncio.Event,
        source_ip: str = "0.0.0.0",
    ) -> None:
        self.decision = decision
        self.assessment = assessment
        self.resolved_event = resolved_event
        self.source_ip = source_ip
