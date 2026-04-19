 # GÖZCÜ — Kodlama Kuralları & Standartları

> Projedeki tüm Python kodunun uyması gereken kurallar.

---

## 1. Dil & İsimlendirme

| Kapsam | Dil | Örnek |
|--------|-----|-------|
| Değişken, fonksiyon, sınıf | İngilizce | `threat_score`, `EventIngestor` |
| Kod içi yorumlar/docstring | İngilizce | `# Validate SHA-256 integrity` |
| README, dökümantasyon | Türkçe | `Kurulum Talimatları` |

```
Sınıflar          → PascalCase       → ReasoningEngine
Fonksiyonlar      → snake_case       → analyze_event
Sabitler          → UPPER_SNAKE      → CACHE_TTL_SECONDS
Enum üyeleri      → UPPER_SNAKE      → ThreatCategory.BRUTE_FORCE
Private metotlar  → _prefix          → _trigger_autonomous
```

---

## 2. Tip Sistemi

- Tüm veri modelleri `pydantic.BaseModel` kullanır. `dataclass` KULLANILMAZ.
- Immutable modeller `ConfigDict(frozen=True)` kullanır (Decision hariç).
- UUID → `str` olarak saklanır (JSON kolaylığı).
- Zaman → `datetime.utcnow().isoformat() + "Z"` (ISO-8601 UTC).
- Her fonksiyon tip anotasyonu taşır.

---

## 3. Asenkron Kurallar

| Yapı | Kullanım | Nerede |
|------|----------|--------|
| `asyncio.Queue` | Event pipeline | main → Ingestor → Engine |
| `asyncio.Lock` | Dosya yazımı | audit_trail, response_cache |
| `asyncio.Semaphore(5)` | LLM rate limiting | reasoning_engine |
| `asyncio.wait_for` | 30s countdown | state_machine |
| `asyncio.Event` | Analist kararı | state_machine |

**YASAKLAR** (async fonksiyon içinde):
- `time.sleep()` → `await asyncio.sleep()`
- `open().read()` → `aiofiles.open()`
- `requests.*` → `aiohttp`

---

## 4. Hata Yönetimi

```python
try:
    assessment = await self._call_llm(event)
except aiohttp.ClientError as e:
    logger.error(f"LLM API failed: {e}", extra={"event_id": event.event_id})
    return self._fallback_assessment(event)
except asyncio.TimeoutError:
    logger.warning("LLM timeout", extra={"event_id": event.event_id})
    return self._fallback_assessment(event)
```

- Fallback → `BENIGN, score=0, confidence=0.0` → Otonom aksiyon TETİKLENMEZ.
- Sessiz `except: pass` YASAKTIR.

---

## 5. Güvenlik

- Ham log → `InputSanitizer` üzerinden geçer (null byte, ANSI temizlik).
- Whitelist kontrolü `ActionExecutor.execute()` ilk satırında yapılır.
- API anahtarları `.env`'den yüklenir, hardcode YASAKTIR.
- SHA-256: Her TelemetryEvent ve AuditRecord hash taşır.

---

## 6. Modül Bağımlılık Hiyerarşisi

```
models/       → HİÇBİR ŞEYİ import etmez
ingestion/    → models/
ai/           → models/
decision/     → models/, ai/, audit/
audit/        → models/
dashboard/    → Hepsini import edebilir
main.py       → Hepsini import eder (composition root)
```

Dairesel import YASAKTIR. Gerekirse `TYPE_CHECKING` bloğu kullanılır.

---

## 7. Logging

```python
logger = logging.getLogger(__name__)
```

| Seviye | Ne Zaman |
|--------|----------|
| DEBUG | Cache hit/miss, pre-filter eşleşme |
| INFO | Event alındı, analiz tamamlandı |
| WARNING | LLM timeout, retry, malformed log |
| ERROR | LLM erişilemez, dosya yazma hatası |
| CRITICAL | Whitelist yüklenemedi |

Her log `extra={"event_id": ...}` taşımalı.

---

## 8. Performans

| Kural | Detay |
|-------|-------|
| Pre-Filter önce | LLM'e gitmeden kontrol |
| Cache ikinci | Pre-filter sonrası, LLM öncesi |
| High-risk cache yok | `threat_score >= 70` cache'lenmez |
| Semaphore | Max 5 eşzamanlı LLM çağrısı |
| Queue | `maxsize=1000` — backpressure |
| Audit async | Disk I/O event loop'u bloklamaz |

---

## 9. Test

- Framework: `pytest` + `pytest-asyncio`
- Dosya: `test_<modül>.py` → `tests/` dizininde
- LLM testleri `AsyncMock` kullanır
- Tüm public metotlar test edilmeli
