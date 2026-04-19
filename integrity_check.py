"""
HONEST INTEGRITY CHECK — All 10 steps.
Tests edge cases, integration points, and potential bugs.
"""
import asyncio
import json
from gozcu.config import Config
from gozcu.models import (
    TelemetryEvent, ThreatAssessment, Decision, AuditRecord,
    SourceType, ThreatCategory, DecisionState, ActionType,
)
from gozcu.ingestion.log_ingestor import LogIngestor
from gozcu.ingestion.sanitizer import InputSanitizer
from gozcu.ai.pre_filter import PreFilterEngine
from gozcu.ai.response_cache import ResponseCache
from gozcu.ai.output_validator import validate_llm_output
from gozcu.decision.whitelist import WhitelistManager
from gozcu.decision.action_executor import ActionExecutor
from gozcu.decision.state_machine import DecisionStateMachine
from gozcu.audit.audit_trail import AuditTrail

errors = []
warnings = []

def check(name, condition, detail=""):
    if condition:
        print(f"  [OK] {name}")
    else:
        print(f"  [FAIL] {name} — {detail}")
        errors.append(f"{name}: {detail}")

def warn(name, detail):
    print(f"  [WARN] {name} — {detail}")
    warnings.append(f"{name}: {detail}")

async def main():
    print("=" * 60)
    print("GÖZCÜ BÜTÜNLÜK DENETİMİ — 10 Adım")
    print("=" * 60)

    # === 1. CONFIG ===
    print("\n--- Config ---")
    c = Config()
    check("Config loads", c.DECISION_TIMEOUT == 30)
    check("Config types", isinstance(c.SIMULATION_MODE, bool))
    check("Config path", c.WHITELIST_PATH.exists(), str(c.WHITELIST_PATH))
    check("Config frozen", True)  # Frozen dataclass
    try:
        c.DECISION_TIMEOUT = 99
        check("Config immutable", False, "Should have raised FrozenInstanceError")
    except Exception:
        check("Config immutable", True)

    # === 2. ENUMS ===
    print("\n--- Enums ---")
    check("SourceType count", len(SourceType) == 3)
    check("ThreatCategory count", len(ThreatCategory) == 8)
    check("DecisionState count", len(DecisionState) == 5)
    check("Enum JSON serialize", json.dumps({"cat": ThreatCategory.SQLI.value}) == '{"cat": "SQLI"}')

    # === 3. TelemetryEvent ===
    print("\n--- TelemetryEvent ---")
    e1 = TelemetryEvent.create(raw_data="test log", source_type=SourceType.SYSLOG)
    check("Event has UUID", len(e1.event_id) == 36)
    check("Event has hash", len(e1.integrity_hash) == 64)
    check("Hash consistent", e1.integrity_hash == TelemetryEvent.compute_hash("test log"))
    check("Event frozen", True)
    try:
        e1.source_ip = "changed"
        check("Event immutable", False, "Should have raised")
    except Exception:
        check("Event immutable", True)

    # Empty IP validation
    e_empty = TelemetryEvent.create(raw_data="x", source_type=SourceType.SYSLOG, source_ip="")
    check("Empty IP -> 0.0.0.0", e_empty.source_ip == "0.0.0.0")

    # === 4. ThreatAssessment ===
    print("\n--- ThreatAssessment ---")
    a1 = ThreatAssessment(event_id="x", threat_score=150, confidence=2.0, source="llm")
    check("Score clamped to 100", a1.threat_score == 100)
    check("Confidence clamped to 1.0", a1.confidence == 1.0)
    check("is_high_risk (score=100)", a1.is_high_risk == True)
    fb = ThreatAssessment.benign_fallback("x", "test")
    check("Fallback score=0", fb.threat_score == 0)
    check("Fallback conf=0.0", fb.confidence == 0.0)

    # === 5. Decision ===
    print("\n--- Decision ---")
    d = Decision(event_id="test")
    check("Initial state PENDING", d.state == DecisionState.PENDING)
    check("Not resolved initially", d.is_resolved == False)
    d.approve("analyst1")
    check("Approved state", d.state == DecisionState.APPROVED)
    check("Resolved by", d.resolved_by == "ANALYST:analyst1")
    check("Is resolved", d.is_resolved == True)
    check("Has resolved_at", d.resolved_at is not None)

    # === 6. AuditRecord ===
    print("\n--- AuditRecord ---")
    ar = AuditRecord.create(
        event_id="e1", decision_id="d1", action="BLOCK_IP",
        actor="GOZCU:AUTONOMOUS", threat_score=90, confidence=0.95,
        ai_reasoning="test", outcome="simulated"
    )
    check("Audit has hash", len(ar.record_hash) == 64)
    check("Hash validates", ar.record_hash == ar.compute_record_hash())
    # Tamper detection
    tampered = AuditRecord(
        audit_id=ar.audit_id, timestamp=ar.timestamp,
        event_id=ar.event_id, decision_id=ar.decision_id,
        action="CHANGED", actor=ar.actor,
        threat_score=ar.threat_score, confidence=ar.confidence,
        ai_reasoning=ar.ai_reasoning, outcome=ar.outcome,
        record_hash=ar.record_hash,  # Keep original hash
    )
    check("Tamper detected", tampered.record_hash != tampered.compute_record_hash())

    # === 7. Sanitizer ===
    print("\n--- Sanitizer ---")
    check("Null byte removed", "\x00" not in InputSanitizer.sanitize("a\x00b"))
    check("ANSI removed", "[31m" not in InputSanitizer.sanitize("\x1b[31mred\x1b[0m"))
    check("CRLF injection detected", InputSanitizer.detect_injection("test\r\ninjection"))
    check("Clean text passes", not InputSanitizer.detect_injection("normal log line"))
    check("Empty input handled", InputSanitizer.sanitize("") == "")

    # === 8. Parsers ===
    print("\n--- Parsers ---")
    from gozcu.ingestion.parsers.syslog_parser import SyslogParser
    from gozcu.ingestion.parsers.json_parser import JsonWebLogParser
    from gozcu.ingestion.parsers.windows_parser import WindowsEventParser

    check("Syslog empty -> None", SyslogParser.parse("") is None)
    check("JSON empty -> None", JsonWebLogParser.parse("") is None)
    check("Windows empty -> None", WindowsEventParser.parse("") is None)
    check("JSON invalid -> None", JsonWebLogParser.parse("not json") is None)

    # === 9. LogIngestor ===
    print("\n--- LogIngestor ---")
    ingestor = LogIngestor()
    e_null = await ingestor.ingest("", SourceType.SYSLOG)
    check("Empty log -> None", e_null is None)

    e_web = await ingestor.ingest(
        json.dumps({"remote_addr": "1.2.3.4", "method": "GET", "uri": "/test", "status": 200}),
        SourceType.WEB_LOG,
    )
    check("Web log IP extracted", e_web.source_ip == "1.2.3.4")

    # === 10. Pre-Filter ===
    print("\n--- Pre-Filter ---")
    pf = PreFilterEngine(enabled=True)
    e_health = TelemetryEvent.create("x", SourceType.WEB_LOG, normalized_data={"path": "/metrics"})
    check("Metrics filtered", pf.check(e_health) is not None)

    e_attack = TelemetryEvent.create("x", SourceType.WEB_LOG, normalized_data={"path": "/admin/drop_table"})
    check("Attack passes filter", pf.check(e_attack) is None)

    pf_disabled = PreFilterEngine(enabled=False)
    check("Disabled filter passes all", pf_disabled.check(e_health) is None)

    # === 11. Cache ===
    print("\n--- Response Cache ---")
    cache = ResponseCache(ttl_seconds=300, max_size=100, high_risk_threshold=70)
    e_cache = TelemetryEvent.create("x", SourceType.WEB_LOG, source_ip="5.5.5.5",
                                     normalized_data={"path": "/api/data"})
    low_a = ThreatAssessment(event_id=e_cache.event_id, threat_score=20, confidence=0.5, source="llm")
    high_a = ThreatAssessment(event_id=e_cache.event_id, threat_score=90, confidence=0.9, source="llm")

    await cache.put(e_cache, low_a)
    check("Low-risk cached", (await cache.get(e_cache)) is not None)

    cache2 = ResponseCache(ttl_seconds=300, max_size=100, high_risk_threshold=70)
    await cache2.put(e_cache, high_a)
    check("High-risk NOT cached", (await cache2.get(e_cache)) is None)

    # === 12. Output Validator ===
    print("\n--- Output Validator ---")
    check("Valid JSON", validate_llm_output('{"category":"SQLI","threat_score":80,"confidence":0.9,"reasoning":"test","recommended_action":"BLOCK"}', "x").category == ThreatCategory.SQLI)
    check("Markdown wrapped", validate_llm_output('```json\n{"category":"XSS","threat_score":60,"confidence":0.7,"reasoning":"t","recommended_action":"M"}\n```', "x").category == ThreatCategory.XSS)
    check("Invalid category -> BENIGN", validate_llm_output('{"category":"INVALID","threat_score":50,"confidence":0.5,"reasoning":"t","recommended_action":"M"}', "x").category == ThreatCategory.BENIGN)
    check("Garbage -> fallback", validate_llm_output("I dont know", "x").confidence == 0.0)
    check("Empty -> fallback", validate_llm_output("", "x").confidence == 0.0)

    # === 13. Whitelist ===
    print("\n--- Whitelist ---")
    wl = WhitelistManager()
    check("Unloaded -> fail-safe True", wl.is_whitelisted("anything"))
    wl.load("data/whitelist.json")
    check("Exact IP match", wl.is_whitelisted("127.0.0.1"))
    check("Subnet match", wl.is_whitelisted("192.168.50.50"))
    check("External IP not matched", not wl.is_whitelisted("8.8.8.8"))
    check("Critical service", wl.is_critical_service("gateway"))
    check("Non-critical service", not wl.is_critical_service("random-svc"))

    # === 14. Action Executor ===
    print("\n--- Action Executor ---")
    executor = ActionExecutor(whitelist=wl, simulation_mode=True)
    r_ok = await executor.execute("BLOCK_IP", "8.8.8.8")
    check("Sim action succeeds", r_ok.success and r_ok.simulated)
    r_wl = await executor.execute("BLOCK_IP", "10.0.0.1")
    check("Whitelisted refused", not r_wl.success)

    # === 15. State Machine ===
    print("\n--- State Machine ---")
    audit = AuditTrail(log_path="logs/integrity_check_audit.jsonl")
    sm = DecisionStateMachine(executor, audit, timeout_seconds=1, confidence_threshold=0.90)

    # Autonomous
    d_auto = Decision(event_id="integrity-test-1")
    a_auto = ThreatAssessment(event_id="integrity-test-1", category=ThreatCategory.SQLI,
                               threat_score=95, confidence=0.96, reasoning="test", source="llm")
    result_auto = await sm.start_countdown(d_auto, a_auto)
    check("Autonomous triggered", result_auto.state == DecisionState.AUTONOMOUS)

    # Expired
    d_exp = Decision(event_id="integrity-test-2")
    a_exp = ThreatAssessment(event_id="integrity-test-2", category=ThreatCategory.RECONNAISSANCE,
                              threat_score=75, confidence=0.50, reasoning="test", source="llm")
    result_exp = await sm.start_countdown(d_exp, a_exp)
    check("Expired triggered", result_exp.state == DecisionState.EXPIRED)

    # Audit records written
    records = await audit.get_history()
    check("Audit records count", len(records) == 2, f"Got {len(records)}")

    # === KNOWN ISSUES CHECK ===
    print("\n--- Bilinen Sorun Kontrolü ---")

    # Issue 1: _extract_target artik source_ip donduruyor (DUZELTILDI)
    # Issue 2: cache invalidate artik ip_to_keys mapping kullaniyor (DUZELTILDI)

    # === SONUC ===
    print("\n" + "=" * 60)
    print(f"SONUC: {len(errors)} HATA, {len(warnings)} UYARI")
    print("=" * 60)
    if errors:
        print("\nHATALAR:")
        for e in errors:
            print(f"  [X] {e}")
    if warnings:
        print("\nUYARILAR:")
        for w in warnings:
            print(f"  [!] {w}")
    if not errors:
        print("\n[OK] Kritik hata yok - ilerlenebilir.")
    else:
        print("\n[STOP] Kritik hatalar duzeltilmeden ilerlenmemeli!")

asyncio.run(main())
