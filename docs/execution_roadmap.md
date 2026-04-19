# GÖZCÜ — Adım Adım Yürütme Yol Haritası

> **Amaç**: 9 fazı token taşması olmadan, her adımı tek seferde tamamlayarak
> projeyi eksiksiz bitirmek.
>
> **Kural**: Her adım bağımsız, test edilebilir ve bir öncekinin üzerine inşa eder.
> Kullanıcı her adımdan sonra "devam" diyerek sonraki adıma geçer.

---

## Genel Bakış (16 Adım)

```
 TEMEL        KATMANLAR          ENTEGRASYON      ARAYÜZ
 ─────        ─────────          ───────────      ──────
 Adım 1       Adım 5            Adım 11          Adım 13
 Adım 2       Adım 6            Adım 12          Adım 14
 Adım 3       Adım 7                              Adım 15
 Adım 4       Adım 8                              Adım 16
              Adım 9
              Adım 10
```

---

## BÖLÜM 1: TEMEL (Adım 1-4)

### Adım 1 — Proje İskeleti & Config
**Dosyalar**: `requirements.txt`, `.env.example`, `.gitignore`, `gozcu/__init__.py`, `gozcu/config.py`
**Kapsam**:
- `requirements.txt` oluştur
- `.env.example` oluştur
- `.gitignore` oluştur
- `gozcu/__init__.py` (boş)
- `gozcu/config.py` — dotenv ile tüm parametreleri yükle
- `data/whitelist.json` oluştur

**Test**: `python -c "from gozcu.config import Config; c = Config(); print(c.DECISION_TIMEOUT)"`
**Tahmini**: Küçük — tek seferde rahat biter.

---

### Adım 2 — Veri Modelleri (Enum'lar)
**Dosyalar**: `gozcu/models/__init__.py`, `gozcu/models/enums.py`
**Kapsam**:
- `SourceType` enum (SYSLOG, WINDOWS_EVENT, WEB_LOG)
- `ThreatCategory` enum (RECONNAISSANCE, SQLI, BRUTE_FORCE, XSS, PRIVILEGE_ESCALATION, DATA_EXFILTRATION, MALWARE, BENIGN)
- `DecisionState` enum (PENDING, APPROVED, REJECTED, AUTONOMOUS, EXPIRED)
- `ActionType` enum (NULL_ROUTE, BLOCK_IP, RESTART_SERVICE, QUARANTINE)

**Test**: `python -c "from gozcu.models.enums import ThreatCategory; print(ThreatCategory.SQLI.value)"`
**Tahmini**: Çok küçük.

---

### Adım 3 — Veri Modelleri (Pydantic — Bölüm A)
**Dosyalar**: `gozcu/models/telemetry_event.py`, `gozcu/models/threat_assessment.py`
**Kapsam**:
- `TelemetryEvent` BaseModel — tüm alanlar, validator'lar, `compute_hash()` metodu
- `ThreatAssessment` BaseModel — tüm alanlar, `source` field ("pre_filter"/"cache"/"llm")

**Test**: Bir TelemetryEvent oluştur, hash doğrula. Bir ThreatAssessment oluştur, JSON serialize et.
**Tahmini**: Küçük-orta.

---

### Adım 4 — Veri Modelleri (Pydantic — Bölüm B)
**Dosyalar**: `gozcu/models/decision.py`, `gozcu/models/audit_record.py`
**Kapsam**:
- `Decision` BaseModel — state, timer, resolved_by alanları (frozen=False çünkü state değişir)
- `AuditRecord` BaseModel — tüm alanlar, `compute_record_hash()` metodu
- `models/__init__.py` güncelle — tüm modelleri re-export et

**Test**: Decision state değiştir, AuditRecord hash doğrula.
**Tahmini**: Küçük-orta.

---

## BÖLÜM 2: KATMANLAR (Adım 5-10)

### Adım 5 — Ingestion: Sanitizer & Parsers
**Dosyalar**: `gozcu/ingestion/__init__.py`, `gozcu/ingestion/sanitizer.py`, `gozcu/ingestion/parsers/__init__.py`, `gozcu/ingestion/parsers/syslog_parser.py`, `gozcu/ingestion/parsers/windows_parser.py`, `gozcu/ingestion/parsers/json_parser.py`
**Kapsam**:
- `InputSanitizer` — null byte, ANSI, encoding temizleme
- `SyslogParser` — RFC5424 regex parse
- `WindowsEventParser` — XML parse
- `JsonWebLogParser` — JSON parse
- Her parser `parse(raw: str) -> dict` döndürür

**Test**: Her parser'a örnek veri ver, çıktıyı kontrol et.
**Tahmini**: Orta.

---

### Adım 6 — Ingestion: LogIngestor
**Dosyalar**: `gozcu/ingestion/log_ingestor.py`
**Kapsam**:
- `LogIngestor` sınıfı
- Parser seçimi (source_type'a göre)
- Sanitize → Parse → Normalize → UUID → SHA-256 → TelemetryEvent
- `async ingest()` metodu
- Hatalı loglar için MALFORMED etiketleme

**Test**: Örnek syslog ver, TelemetryEvent al, hash doğrula.
**Tahmini**: Küçük-orta.

---

### Adım 7 — AI: Pre-Filter & Response Cache
**Dosyalar**: `gozcu/ai/__init__.py`, `gozcu/ai/pre_filter.py`, `gozcu/ai/response_cache.py`
**Kapsam**:
- `PreFilterEngine` — kural kümeleri, `check()`, `add_rule()`, `get_stats()`
- `ResponseCache` — TTLCache, `get()`, `put()`, `invalidate()`, `get_stats()`
- High-risk cache bypass kuralı

**Test**: Health check logu pre-filter'dan geç, cache put/get/expire test et.
**Tahmini**: Orta.

---

### Adım 8 — AI: Prompt Templates & Output Validator & Reasoning Engine
**Dosyalar**: `gozcu/ai/prompt_templates.py`, `gozcu/ai/output_validator.py`, `gozcu/ai/reasoning_engine.py`
**Kapsam**:
- `SYSTEM_PROMPT`, `USER_PROMPT_TEMPLATE`, `build_user_prompt(event)`
- `validate_llm_output()` — JSON parse, schema kontrol, fallback
- `ReasoningEngine` — 3 aşamalı pipeline orchestrator
  - Pre-Filter → Cache → LLM API
  - aiohttp, retry, semaphore, timeout
  - `force_analysis` bypass
  - `get_pipeline_stats()`

**Test**: Mock LLM ile analyze çağır, pre-filter ve cache bypass test et.
**Tahmini**: ORTA-BÜYÜK — bu adım en yoğun adımdır ama tek bir pipeline olduğu için bölmek mantıksız.

---

### Adım 9 — Decision: Whitelist & Action Executor
**Dosyalar**: `gozcu/decision/__init__.py`, `gozcu/decision/whitelist.py`, `gozcu/decision/action_executor.py`
**Kapsam**:
- `WhitelistManager` — JSON yükle, IP kontrol, subnet kontrol, servis kontrol
- `ActionExecutor` — simülasyon + gerçek mod, whitelist entegrasyonu
- Her aksiyon tipi için ayrı metot

**Test**: Whitelist IP'yi kontrol et (True), dışarıdaki IP'yi kontrol et (False). Simülasyon aksiyonu çalıştır.
**Tahmini**: Küçük-orta.

---

### Adım 10 — Decision: State Machine & Audit Trail
**Dosyalar**: `gozcu/decision/state_machine.py`, `gozcu/audit/__init__.py`, `gozcu/audit/audit_trail.py`
**Kapsam**:
- `DecisionStateMachine` — countdown, approve, reject, autonomous trigger
- `asyncio.Event` ile analist sinyali
- Confidence eşik kontrolü
- `AuditTrail` — JSONL yazma, hash zinciri, dosya kilitleme

**Test**: Decision oluştur, approve et → state kontrol. Timeout simüle et → autonomous kontrol. Audit kaydı oluştur, dosyadan oku.
**Tahmini**: Orta-büyük.

---

## BÖLÜM 3: ENTEGRASYON (Adım 11-12)

### Adım 11 — Ana Pipeline (main.py)
**Dosyalar**: `gozcu/main.py`
**Kapsam**:
- Tüm bileşenleri initialize et
- `asyncio.Queue` tabanlı event pipeline
- `process_event()` — Ingest → Analyze → Decision (yüksek riskse) → Audit
- Demo modu: Örnek logları pipeline'a gönder
- Graceful shutdown

**Test**: `python -m gozcu.main` çalıştır, demo loglarını işle, audit dosyasını kontrol et.
**Tahmini**: Orta.

---

### Adım 12 — Örnek Log Verileri & Demo Senaryoları
**Dosyalar**: `data/sample_logs/sample_syslog.log`, `data/sample_logs/sample_web.json`, `data/sample_logs/demo_scenarios.py`
**Kapsam**:
- 5-6 farklı senaryo logu:
  1. Brute force (yüksek risk)
  2. SQL injection (yüksek risk)
  3. Port tarama (orta risk)
  4. Health check (pre-filter yakalayacak)
  5. Normal trafik (düşük risk)
  6. Tekrarlı log (cache test)
- `demo_scenarios.py` — Pipeline'a logları sırayla gönderen demo scripti

**Test**: Demo çalıştır, her senaryonun beklenen sonucu ürettiğini doğrula.
**Tahmini**: Küçük.

---

## BÖLÜM 4: DASHBOARD ARAYÜZÜ (Adım 13-16)

### Adım 13 — Dashboard Backend (WebSocket Server)
**Dosyalar**: `gozcu/dashboard/__init__.py`, `gozcu/dashboard/web_server.py`
**Kapsam**:
- `aiohttp` web sunucu
- WebSocket endpoint (`/ws`)
- REST endpoint'leri: `/api/events`, `/api/decisions`, `/api/audit`, `/api/stats`
- `POST /api/decisions/{id}/approve`, `POST /api/decisions/{id}/reject`
- Statik dosya servisi (`static/`)
- Pipeline'dan WebSocket'e event yayını

**Test**: Sunucuyu başlat, `/api/stats` endpoint'ini curl ile çağır.
**Tahmini**: Orta.

---

### Adım 14 — Dashboard UI: HTML Yapısı
**Dosyalar**: `static/index.html`
**Kapsam**:
- Semantik HTML5 yapısı
- Bölümler: Header, Canlı Event Akışı, Bekleyen Kararlar, Audit Geçmişi, İstatistikler
- Google Fonts (Inter/JetBrains Mono)
- Responsive meta tag'ler

**Test**: HTML dosyasını tarayıcıda aç, yapının doğru render edildiğini gör.
**Tahmini**: Küçük-orta.

---

### Adım 15 — Dashboard UI: CSS Tasarım
**Dosyalar**: `static/style.css`
**Kapsam**:
- Koyu tema (SOC estetiği)
- CSS değişkenleri (renk paleti, spacing, font)
- Glassmorphism kartlar
- Countdown timer animasyonu (dairesel progress)
- Threat seviye renk kodlaması (kırmızı/turuncu/yeşil)
- Responsive grid layout
- Buton stilleri (approve=yeşil, reject=kırmızı)
- Pulse animasyonu (yeni event bildirimi)

**Test**: index.html'i tarayıcıda aç, tasarımı doğrula.
**Tahmini**: Orta.

---

### Adım 16 — Dashboard UI: JavaScript & WebSocket
**Dosyalar**: `static/app.js`
**Kapsam**:
- WebSocket bağlantısı ve reconnect mantığı
- Mesaj tiplerini işleme (new_event, new_decision, countdown_tick, stats_update)
- DOM güncelleme fonksiyonları
- Countdown timer (her saniye güncelleme, dairesel animasyon)
- Approve/Reject buton handler'ları (fetch POST)
- İstatistik kartlarını güncelleme
- Bağlantı durumu göstergesi

**Test**: main.py'yi başlat, dashboard'u aç, demo loglarını izle, bir kararı approve et.
**Tahmini**: Orta-büyük.

---

## Kullanım Rehberi

Her adımda bana şunu söylemen yeterli:

```
"Adım X'i yaz"
```

Ben o adımdaki dosyaları yazacağım, test edeceğim ve sonucu raporlayacağım.
Sorun yoksa "devam" de, sonraki adıma geçeyim.

### Önemli Kurallar

1. **Asla iki adımı birleştirme** — Her adım tek seferde bitmeli
2. **Her adım sonrası test** — Çalıştığından emin ol
3. **Sorun varsa orada dur** — Hatayı düzelt, sonra ilerle
4. **Sırayı değiştirme** — Bağımlılıklar sıralıdır

### Bağımlılık Zinciri

```
Adım 1 ──→ Adım 2 ──→ Adım 3 ──→ Adım 4
                                     │
              ┌──────────────────────┘
              ▼
Adım 5 ──→ Adım 6 ──→ Adım 7 ──→ Adım 8
                                     │
              ┌──────────────────────┘
              ▼
Adım 9 ──→ Adım 10 ──→ Adım 11 ──→ Adım 12
                                       │
              ┌────────────────────────┘
              ▼
Adım 13 ──→ Adım 14 ──→ Adım 15 ──→ Adım 16
```
