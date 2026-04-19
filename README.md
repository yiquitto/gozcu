# GÖZCÜ — Otonom Nöbetçi & Karar Destek Sistemi

<p align="center">
  <strong>🛡️ Yapay Zeka Destekli Mini-SOC Aracı</strong><br>
  <em>Alert Fatigue'i ortadan kaldır. MTTR'yi minimize et.</em>
</p>

---

## 🎯 Nedir?

GÖZCÜ, yeni nesil bir **Mini-SOC (Security Operations Center)** aracıdır. Geleneksel kural tabanlı sistemlerin aksine:

- **LLM ile Semantik Analiz** — Logları bağlamsal olarak yorumlar
- **Human-in-the-Loop** — Analist onay penceresi sunar
- **Otonom Mod** — Yanıt gelmezse 30 saniye sonra kendi karar alır
- **Tam Denetim** — Her karar şeffaf şekilde kayıt altına alınır

---

## 🏗️ Mimari

```
[Syslog/WinEvent/WebLog] → Ingestor → Pre-Filter → Cache → LLM → Decision → Action
                              │                                       │
                          TelemetryEvent                         AuditTrail
                          (UUID + SHA-256)                    (JSON Lines)
```

### Katmanlar

| Katman | Görev | Dosya |
|--------|-------|-------|
| **Ingestion** | Log toplama & normalizasyon | `gozcu/ingestion/` |
| **AI Reasoning** | Tehdit analizi (Pre-Filter → Cache → LLM) | `gozcu/ai/` |
| **Decision** | 30s countdown + otonom aksiyon | `gozcu/decision/` |
| **Audit** | Tamper-proof karar kaydı | `gozcu/audit/` |
| **Dashboard** | Gerçek zamanlı WebSocket UI | `gozcu/dashboard/` + `static/` |

---

## 🚀 Kurulum

### Gereksinimler
- Python 3.10+
- LM Studio veya Ollama (yerel LLM için)

### Adımlar

```bash
# 1. Repo'yu klonla
git clone https://github.com/yiquitto/gozcu.git
cd gozcu

# 2. Sanal ortam oluştur
python -m venv venv
venv\Scripts\activate  # Windows

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. Ortam değişkenlerini ayarla
copy .env.example .env
# .env dosyasını düzenle (LLM API ayarları)

# 5. Çalıştır
python -m gozcu.main
```

### LLM Ayarları

**LM Studio** (varsayılan):
```env
LLM_BASE_URL=http://localhost:1234/v1
LLM_MODEL=local-model
LLM_API_KEY=lm-studio
```

**Ollama**:
```env
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=mistral:7b
LLM_API_KEY=ollama
```

**OpenAI** (opsiyonel):
```env
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=sk-...
```

---

## 📊 Dashboard

Tarayıcıda `http://localhost:8080` adresini aç.

**Özellikler**:
- 🔴 Canlı olay akışı
- ⏱️ 30 saniyelik countdown timer
- ✅/❌ Approve/Reject butonları
- 📋 Audit geçmişi
- 📈 Pipeline istatistikleri (pre-filter, cache, LLM)

---

## ⚙️ Konfigürasyon

| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `DECISION_TIMEOUT` | `30` | Countdown süresi (saniye) |
| `HIGH_RISK_THRESHOLD` | `70` | Yüksek risk eşiği (0-100) |
| `AUTONOMOUS_CONFIDENCE_THRESHOLD` | `0.90` | Otonom aksiyon eşiği |
| `SIMULATION_MODE` | `True` | Gerçek aksiyon almasın |
| `CACHE_TTL_SECONDS` | `300` | Cache süresi (5 dk) |
| `PRE_FILTER_ENABLED` | `True` | Ön filtre aktif |

---

## 🔒 Güvenlik

- **SHA-256 Log Bütünlüğü** — Her event hash'lenir
- **Whitelist** — Kritik IP'ler asla banlanmaz
- **Simülasyon Modu** — Varsayılan olarak gerçek aksiyon almaz
- **Audit Trail** — Her karar tamper-proof kayıt altında

---

## 📁 Proje Yapısı

```
gozcu/
├── models/          # Veri yapıları (Pydantic)
├── ingestion/       # Log toplama & parse
├── ai/              # LLM entegrasyonu + Pre-Filter + Cache
├── decision/        # State machine + aksiyon
├── audit/           # Denetim kaydı
└── dashboard/       # Web sunucu
static/              # Dashboard UI (HTML/CSS/JS)
data/                # Whitelist, örnek loglar
logs/                # Audit trail çıktısı
tests/               # Unit testler
docs/                # Dokümantasyon
```

---

## 📝 Lisans

MIT License — Detaylar için `LICENSE` dosyasına bakın.
