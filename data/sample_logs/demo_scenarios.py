"""
Demo Scenarios for GÖZCÜ Pipeline Testing.

Provides structured test scenarios that exercise every layer of the pipeline:
Pre-Filter, Cache, LLM Analysis, Decision State Machine, and Whitelist.

Usage:
    python -m data.sample_logs.demo_scenarios
    OR imported by main.py / tests
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from gozcu.config import Config
from gozcu.models.enums import SourceType
from gozcu.main import GozcuPipeline


# --- Scenario Definitions ---

SCENARIOS = [
    {
        "name": "Pre-Filter: Health Check",
        "description": "Kubernetes probe - should be filtered WITHOUT calling LLM",
        "raw": '{"remote_addr":"10.0.0.5","method":"GET","uri":"/healthz","status":200,"http_user_agent":"kube-probe/1.28"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "10.0.0.5",
        "expected_source": "pre_filter",
        "expected_category": "BENIGN",
    },
    {
        "name": "Pre-Filter: Static Asset",
        "description": "CSS file request - should be filtered WITHOUT calling LLM",
        "raw": '{"remote_addr":"192.168.1.30","method":"GET","uri":"/assets/app.min.css","status":200,"http_user_agent":"Mozilla/5.0"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "192.168.1.30",
        "expected_source": "pre_filter",
        "expected_category": "BENIGN",
    },
    {
        "name": "Pre-Filter: Monitoring Agent",
        "description": "Prometheus scrape - should be filtered by user-agent rule",
        "raw": '{"remote_addr":"10.0.0.1","method":"GET","uri":"/metrics","status":200,"http_user_agent":"Prometheus/2.45"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "10.0.0.1",
        "expected_source": "pre_filter",
        "expected_category": "BENIGN",
    },
    {
        "name": "LLM Analysis: Normal Login",
        "description": "Legitimate login - should reach LLM, expect low threat score",
        "raw": '{"remote_addr":"192.168.1.30","method":"POST","uri":"/api/login","status":200,"http_user_agent":"Mozilla/5.0 (Windows NT 10.0)"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "192.168.1.30",
        "expected_source": "llm",
        "expected_category": None,  # Depends on LLM
    },
    {
        "name": "LLM Analysis: SQL Injection",
        "description": "Clear SQLi attempt with sqlmap - expect HIGH threat score",
        "raw": '{"remote_addr":"45.33.32.156","method":"GET","uri":"/search?q=1\' OR 1=1--","status":200,"http_user_agent":"sqlmap/1.5.12"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "45.33.32.156",
        "expected_source": "llm",
        "expected_category": "SQLI",
    },
    {
        "name": "LLM Analysis: Brute Force (Syslog)",
        "description": "5 failed SSH logins from same IP in 10 seconds",
        "raw": "<38>1 2026-04-17T03:12:01Z firewall sshd 4821 AUTH Failed password for root from 203.0.113.50 port 22",
        "source_type": SourceType.SYSLOG,
        "source_ip": "203.0.113.50",
        "expected_source": "llm",
        "expected_category": "BRUTE_FORCE",
    },
    {
        "name": "Cache: Repeated Event",
        "description": "Same IP+path as scenario 4 - should return CACHE HIT",
        "raw": '{"remote_addr":"192.168.1.30","method":"POST","uri":"/api/login","status":200,"http_user_agent":"Mozilla/5.0 (Windows NT 10.0)"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "192.168.1.30",
        "expected_source": "cache",
        "expected_category": None,
    },
    {
        "name": "Syslog: Infrastructure Routine",
        "description": "NTP sync message - should be filtered by pre-filter",
        "raw": "<46>1 2026-04-17T03:30:00Z dns-server named 53 INFO NTP sync completed successfully",
        "source_type": SourceType.SYSLOG,
        "source_ip": "10.0.0.2",
        "expected_source": "pre_filter",
        "expected_category": "BENIGN",
    },
    {
        "name": "LLM Analysis: Path Traversal",
        "description": "Directory traversal attempt to read /etc/passwd",
        "raw": '{"remote_addr":"45.33.32.156","method":"GET","uri":"/admin/../../../etc/passwd","status":403,"http_user_agent":"Nikto/2.1.6"}',
        "source_type": SourceType.WEB_LOG,
        "source_ip": "45.33.32.156",
        "expected_source": "llm",
        "expected_category": "RECONNAISSANCE",
    },
    {
        "name": "LLM Analysis: Data Exfiltration",
        "description": "Unusual outbound traffic spike from internal host",
        "raw": "<29>1 2026-04-17T03:25:00Z core-switch kernel 0 ALERT Unusual outbound traffic spike to 185.220.101.1:443 - 500MB in 30s from 192.168.1.100",
        "source_type": SourceType.SYSLOG,
        "source_ip": "192.168.1.100",
        "expected_source": "llm",
        "expected_category": "DATA_EXFILTRATION",
    },
]


async def run_scenarios() -> None:
    """Run all demo scenarios and print results."""
    config = Config()
    pipeline = GozcuPipeline(config)

    print("=" * 65)
    print("  GOZCU - Demo Scenarios")
    print("=" * 65)
    print(f"  Total scenarios: {len(SCENARIOS)}")
    print(f"  LLM available: {config.LLM_BASE_URL}")
    print("=" * 65)

    passed = 0
    failed = 0

    for i, scenario in enumerate(SCENARIOS, 1):
        print(f"\n[{i}/{len(SCENARIOS)}] {scenario['name']}")
        print(f"  {scenario['description']}")

        result = await pipeline.process_event(
            scenario["raw"],
            scenario["source_type"],
            scenario["source_ip"],
        )

        if result is None:
            print("  -> SKIPPED (empty)")
            continue

        actual_source = result["source"]
        expected_source = scenario["expected_source"]
        source_match = actual_source == expected_source

        print(f"  Source:   {actual_source.upper()} (expected: {expected_source.upper()}) {'OK' if source_match else 'MISMATCH'}")
        print(f"  Category: {result['category']}, Score: {result['threat_score']}/100")
        print(f"  Reasoning: {result['reasoning'][:70]}")

        if "decision" in result:
            d = result["decision"]
            print(f"  DECISION: {d['state']} by {d['resolved_by']}")

        if source_match:
            passed += 1
        else:
            failed += 1

    # Summary
    stats = pipeline.get_stats()
    pf = stats["pipeline"]["pre_filter"]
    cache = stats["pipeline"]["cache"]

    print(f"\n{'=' * 65}")
    print(f"  RESULTS: {passed} passed, {failed} mismatched source")
    print(f"  Pre-filtered: {pf['filtered']}/{pf['checked']}")
    print(f"  Cache hits: {cache['hits']}")
    print(f"  LLM calls: {stats['pipeline']['engine']['llm_calls']}")
    print(f"  Audit records: {stats['audit']['total_records']}")
    print(f"{'=' * 65}")

    await pipeline._engine.close()


if __name__ == "__main__":
    asyncio.run(run_scenarios())
