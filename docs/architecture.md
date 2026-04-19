# GÖZCÜ — Sistem Mimarisi

> Tüm bileşenlerin birbirleriyle nasıl etkileştiğini tanımlar.

---

## Üst Düzey Veri Akışı

```
[Log Kaynakları]         [AI Katmanı]              [Karar Katmanı]           [Çıktı]
  Syslog ──┐           ┌─ Pre-Filter ──→ BENIGN    ┌─ APPROVED (Analist)     Audit Trail
  WinEvent ┼→ Ingestor → Cache ──→ Cached Result   → REJECTED (Analist)   → Dashboard
  WebLog ──┘    │       └─ LLM API ──→ Assessment   └─ AUTONOMOUS/EXPIRED    WebSocket
                │                          │                │
           TelemetryEvent            ThreatAssessment    Decision
           (UUID + SHA-256)          (Score + Confidence) (30s Timer)
```

---

## Bileşen Detayları

### A. Ingestion Layer (`gozcu/ingestion/`)

**Görev**: Ham logları normalize edip `TelemetryEvent` üretmek.

**Akış**: `Raw Data → Sanitizer → Parser Selection → Normalization → UUID + SHA-256 → Queue`

| Parser | Kaynak | Çıktı Alanları |
|--------|--------|----------------|
| `SyslogParser` | RFC5424 Syslog | facility, severity, hostname, message |
| `WindowsEventParser` | Windows XML | event_id, provider, level, message |
| `JsonWebLogParser` | JSON web log | method, path, status_code, user_agent, ip |

**Sanitizer Kuralları**:
- Null byte (`\x00`) temizleme
- ANSI escape kodları temizleme
- UTF-8 doğrulama
- Log injection pattern tespiti

---

### B. AI Reasoning Layer (`gozcu/ai/`)

**Görev**: Event'leri tehdit açısından analiz etmek.

**3 Aşamalı Pipeline**:

```
TelemetryEvent
     │
     ▼
[1] Pre-Filter ──match──→ BENIGN (score=0, confidence=1.0) ──→ DONE
     │ no match
     ▼
[2] Cache ──HIT──→ Önceki ThreatAssessment ──→ DONE
     │ MISS
     ▼
[3] LLM API ──→ Yeni ThreatAssessment ──→ Cache'e yaz ──→ DONE
```

**Pre-Filter Kuralları**:
- Statik dosya istekleri: `.css`, `.js`, `.png`, `.jpg`, `.ico`, `.woff`, `.svg`
- Health check: `/health`, `/healthz`, `/ready`, `/ping`, `/status`, `/metrics`
- Altyapı: NTP sync, DHCP lease, DNS recursive
- Monitoring: `Prometheus/`, `Datadog Agent/`, `UptimeRobot/`

**Cache Kuralları**:
- Key: `sha256(source_ip + event_type + normalized_path)`
- TTL: 300 saniye (5 dakika)
- Max size: 1024 entry
- `threat_score >= 70` olan sonuçlar cache'lenmez
- `invalidate(ip)` ile analist müdahalesi sonrası temizleme

**LLM Entegrasyonu**:
- OpenAI uyumlu API (LM Studio/Ollama varsayılan)
- Strict JSON çıktı formatı
- 3 retry, exponential backoff
- 10 saniye timeout
- Semaphore(5) rate limiting

---

### C. Decision Layer (`gozcu/decision/`)

**Görev**: Yüksek riskli olaylarda 30 saniyelik karar mekanizması.

**State Machine**:

```
                  ┌─────────┐
                  │ PENDING │ ← threat_score >= 70
                  └────┬────┘
                       │
     ┌────────────┬────┴────┬────────────┐
     ▼            ▼         ▼            │
 APPROVED    REJECTED    (30s timeout)   │
 (Analist)   (Analist)      │            │
                        ┌───┴───┐        │
                        │conf>90│        │
                        └───┬───┘        │
                      ┌─────┴─────┐      │
                      ▼           ▼      │
                 AUTONOMOUS    EXPIRED   │
                 (Aksiyon al)  (Bekle)   │
                      │                  │
                      ▼                  │
               Whitelist check ──fail──→─┘ (iptal)
                      │ pass
                      ▼
               ActionExecutor
```

**Eşikler** (config'den):
- `HIGH_RISK_THRESHOLD = 70` → Decision oluştur
- `AUTONOMOUS_CONFIDENCE_THRESHOLD = 0.90` → Otonom aksiyon
- `DECISION_TIMEOUT = 30` → Countdown süresi

**Aksiyonlar** (simülasyon modunda):
- `NULL_ROUTE` — IP null-routing
- `BLOCK_IP` — Firewall kuralı
- `RESTART_SERVICE` — Servis restart
- `QUARANTINE` — Process/dosya karantina

---

### D. Audit Layer (`gozcu/audit/`)

**Görev**: Her kararı tamper-proof şekilde kaydetmek.

**Format**: JSON Lines (`.jsonl`) — her satır bir AuditRecord.

**İçerik**: event_id, decision_id, action, actor, threat_score, confidence, ai_reasoning, outcome, hash.

**Actor formatı**: `"ANALYST:username"` veya `"GOZCU:AUTONOMOUS"`

---

### E. Dashboard (`gozcu/dashboard/` + `static/`)

**Görev**: Gerçek zamanlı SOC arayüzü.

**Teknoloji**: `aiohttp` web server + WebSocket.

**Bölümler**:
1. **Canlı Event Akışı** — Yeni olaylar gerçek zamanlı
2. **Bekleyen Kararlar** — Countdown timer ile approve/reject
3. **Audit Geçmişi** — Tüm kararların log'u
4. **Pipeline İstatistikleri** — Pre-filter, cache, LLM oranları
5. **Sistem Durumu** — Bağlantı, LLM sağlığı

**WebSocket Mesaj Tipleri**:
- `new_event` — Yeni TelemetryEvent
- `new_decision` — Yeni karar bekleniyor (countdown başlat)
- `decision_update` — Karar durumu değişti
- `stats_update` — Pipeline istatistikleri
- `countdown_tick` — Her saniye kalan süre

---

## Veri Modelleri (Özet)

```python
TelemetryEvent:
  event_id: str (UUID)
  timestamp: str (ISO-8601)
  source_type: SourceType (SYSLOG | WINDOWS_EVENT | WEB_LOG)
  source_ip: str
  raw_data: str
  normalized_data: dict
  integrity_hash: str (SHA-256)
  ingestion_timestamp: str

ThreatAssessment:
  event_id: str (UUID)
  category: ThreatCategory (RECONNAISSANCE | SQLI | BRUTE_FORCE | ...)
  threat_score: int (0-100)
  confidence: float (0.0-1.0)
  reasoning: str
  recommended_action: str
  source: str ("pre_filter" | "cache" | "llm")

Decision:
  decision_id: str (UUID)
  event_id: str
  state: DecisionState (PENDING | APPROVED | REJECTED | AUTONOMOUS | EXPIRED)
  created_at: str
  resolved_at: Optional[str]
  resolved_by: str
  action_taken: Optional[str]
  timeout_seconds: int = 30

AuditRecord:
  audit_id: str (UUID)
  timestamp: str
  event_id: str
  decision_id: str
  action: str
  actor: str
  threat_score: int
  confidence: float
  ai_reasoning: str
  outcome: str
  record_hash: str (SHA-256)
```

---

## Konfigürasyon Parametreleri

| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `LLM_API_KEY` | — | LLM API anahtarı |
| `LLM_BASE_URL` | `http://localhost:1234/v1` | LLM endpoint |
| `LLM_MODEL` | `local-model` | Model adı |
| `DECISION_TIMEOUT` | `30` | Countdown süresi (saniye) |
| `AUTONOMOUS_CONFIDENCE_THRESHOLD` | `0.90` | Otonom aksiyon eşiği |
| `HIGH_RISK_THRESHOLD` | `70` | Yüksek risk eşiği |
| `SIMULATION_MODE` | `True` | Simülasyon modu |
| `CACHE_TTL_SECONDS` | `300` | Cache TTL (5 dk) |
| `CACHE_MAX_SIZE` | `1024` | Max cache entry |
| `PRE_FILTER_ENABLED` | `True` | Ön filtre aktif |
| `DASHBOARD_PORT` | `8080` | Dashboard portu |
