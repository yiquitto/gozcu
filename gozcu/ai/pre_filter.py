"""
Pre-Filter Rule Engine.

Catches known-benign log patterns BEFORE they reach the LLM API,
eliminating unnecessary API calls. Only patterns that are definitively
harmless are filtered — when in doubt, the event passes through to the LLM.

Pipeline position: [1] Pre-Filter → Cache → LLM
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from gozcu.models.enums import ThreatCategory
from gozcu.models.telemetry_event import TelemetryEvent
from gozcu.models.threat_assessment import ThreatAssessment

logger = logging.getLogger(__name__)


# Built-in rule sets — each is (rule_name, field_to_check, compiled_regex)
# hocaya not: basit statik dosya isteklerini (css, js) yapay zekaya gonderip bosuna api maliyeti (token) yakmamak icin burada regex ile onceden yakaliyorum.
_STATIC_FILE_EXTENSIONS = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|svg|map|webp|avif)(\?.*)?$",
    re.IGNORECASE,
)
_HEALTH_CHECK_PATHS = re.compile(
    r"^/(health|healthz|ready|readyz|ping|status|metrics|favicon\.ico)/?$",
    re.IGNORECASE,
)
_INFRASTRUCTURE_MESSAGES = re.compile(
    r"(NTP\s+sync|DHCP\s+(lease|renew|ack)|DNS\s+recursive\s+query|keepalive|heartbeat)",
    re.IGNORECASE,
)
_MONITORING_AGENTS = re.compile(
    r"(Prometheus|Datadog[\s-]Agent|UptimeRobot|Nagios|Zabbix|Grafana|kube-probe|ELB-HealthChecker)",
    re.IGNORECASE,
)


class PreFilterEngine:
    """
    Rule-based pre-filter that marks known-benign events without calling the LLM.

    Returns a ThreatAssessment(BENIGN, score=0, confidence=1.0) for matches,
    or None to let the event proceed to the next pipeline stage.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._custom_rules: List[Tuple[str, str, re.Pattern]] = []
        self._stats = {"checked": 0, "filtered": 0, "passed": 0}

    def check(self, event: TelemetryEvent) -> Optional[ThreatAssessment]:
        """
        Check if an event matches any known-benign pattern.

        Returns a BENIGN ThreatAssessment if matched, None otherwise.
        """
        # sisteme gelen her log once bu filtreden geciyor. eger zararli degilse yapay zekaya hic gitmeden direkt 'zararsiz' isaretlenip sistem yuku hafifletiliyor.
        self._stats["checked"] += 1

        if not self._enabled:
            self._stats["passed"] += 1
            return None

        nd = event.normalized_data

        # Rule 1: Static file requests
        path = nd.get("path", "") or nd.get("uri", "")
        if path and _STATIC_FILE_EXTENSIONS.search(path):
            return self._make_benign(event, "static_file_request")

        # Rule 2: Health check endpoints
        if path and _HEALTH_CHECK_PATHS.match(path):
            return self._make_benign(event, "health_check_endpoint")

        # Rule 3: Infrastructure messages
        message = nd.get("message", "")
        if message and _INFRASTRUCTURE_MESSAGES.search(message):
            return self._make_benign(event, "infrastructure_routine")

        # Rule 4: Known monitoring agents
        ua = nd.get("user_agent", "")
        if ua and _MONITORING_AGENTS.search(ua):
            return self._make_benign(event, "monitoring_agent")

        # Rule 5: Custom rules
        for rule_name, field, pattern in self._custom_rules:
            value = nd.get(field, "")
            if value and pattern.search(str(value)):
                return self._make_benign(event, rule_name)

        self._stats["passed"] += 1
        return None

    def add_rule(self, name: str, field: str, pattern: str) -> None:
        """Add a custom pre-filter rule at runtime."""
        compiled = re.compile(pattern, re.IGNORECASE)
        self._custom_rules.append((name, field, compiled))
        logger.info(f"Custom pre-filter rule added: {name} on field '{field}'")

    def get_stats(self) -> Dict[str, Any]:
        """Return pre-filter statistics."""
        return dict(self._stats)

    def _make_benign(self, event: TelemetryEvent, rule_name: str) -> ThreatAssessment:
        """Create a BENIGN assessment for a filtered event."""
        self._stats["filtered"] += 1
        logger.debug(
            f"Pre-filter matched: {rule_name}",
            extra={"event_id": event.event_id},
        )
        return ThreatAssessment(
            event_id=event.event_id,
            category=ThreatCategory.BENIGN,
            threat_score=0,
            confidence=1.0,
            reasoning=f"Pre-Filter: matched rule '{rule_name}'",
            recommended_action="NONE",
            source="pre_filter",
        )
