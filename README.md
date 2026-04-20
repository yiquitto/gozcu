# GÖZCÜ — Autonomous SOC & Decision Support System

<p align="center">
  <strong>🛡️ AI-Powered Mini-SOC Aracı</strong><br>
  <em>Alert Fatigue'i ortadan kaldır, incident response sürecini otonomlaştır.</em>
</p>

---

## 🎯 Nedir?

GÖZCÜ, SOC (Security Operations Center) ekiplerindeki "Alert Fatigue" (Alarm Yorgunluğu) problemini çözmek için tasarlanmış yeni nesil bir otonom analiz aracıdır. Geleneksel kural tabanlı sistemlerin aksine; logları bağlamsal olarak analiz eder, false-positive oranını düşürür ve gerektiğinde kendi kendine aksiyon alabilir.

### Temel Özellikler
- **LLM Tabanlı Semantic Analysis** — Gelen logları yapay zeka ile yorumlayıp tehdidin asıl amacını anlar.
- **Real-Time Dashboard** — Chart.js destekli, Glassmorphism UI (cam efekti) ile modern ve dinamik tehdit akışı.
- **Autonomous Mitigation (KILL_PROCESS & BLOCK_IP)** — Tespit edilen tehdidi (taskkill/firewall ile) otomatik olarak izole eder.
- **Human-in-the-Loop (HITL)** — Yüksek riskli durumlarda analiste 30 saniyelik bir karar penceresi sunar. Süre dolarsa AI otonom kararı uygular.
- **Tam Şeffaflık (Audit Trail)** — Alınan her bir karar, değiştirilemez (tamper-proof) şekilde loglanır.

---

## 🏗️ Architecture

```
[Raw Logs] → Ingestor → Pre-Filter → Cache → LLM Engine → Decision Machine → Action Executor
                                       │                                           │
                                Threat Assessment                              Audit Trail
```

### Katmanlar (Modules)

| Katman | Görev | Path |
|--------|-------|-------|
| **Ingestion** | Logları collect edip normalize eder. | `gozcu/ingestion/` |
| **AI Reasoning** | 3 aşamalı zeka hattı (Pre-Filter → Cache → LLM). | `gozcu/ai/` |
| **Decision** | 30s asenkron non-blocking countdown ve otonom aksiyonlar. | `gozcu/decision/` |
| **Audit** | Alınan kararların SHA-256 bütünlük kontrolüyle kaydedilmesi. | `gozcu/audit/` |
| **Dashboard** | WebSockets üzerinden real-time haberleşen arayüz. | `gozcu/dashboard/` |

---

## 🚀 Kurulum (Setup)

### Gereksinimler (Requirements)
- Python 3.10+
- LM Studio veya Ollama (Local LLM için)
- Terminal/CMD **Administrator** olarak çalıştırılmalıdır (Firewall kuralları için zorunlu).

### Kurulum Adımları

```bash
# 1. Repository'i klonla
git clone https://github.com/yiquitto/gozcu.git
cd gozcu

# 2. Virtual Environment oluştur ve aktif et
python -m venv venv
venv\Scripts\activate

# 3. Dependencies'leri yükle
pip install -r requirements.txt

# 4. Environment config dosyasını oluştur
copy .env.example .env

# 5. Sistemi başlat (Stream flag'i ile sample logları akıtır)
python run_server.py --stream data/sample_logs/sample_web.jsonl
```

### LLM Config (`.env` dosyasında)

**LM Studio** (Tavsiye edilen):
```env
LLM_BASE_URL=http://localhost:1234/v1
LLM_MODEL=local-model
LLM_API_KEY=lm-studio
SIMULATION_MODE=false # Gerçek network aksiyonları almak için false yapın
```

---

## 📊 Dashboard UI

Uygulama ayağa kalktığında browser üzerinden `http://localhost:8080` adresine gidin.

**Arayüz Özellikleri**:
- 📈 **Canlı Grafikler:** Chart.js entegrasyonu ile Top Attacker IP'ler ve Threat Category dağılımı.
- 🔴 **Dynamic Event Feed:** WebSocket ile sayfa yenilemeden akan canlı loglar.
- ⏱️ **Decision Modal:** Yüksek risk anında ekrana düşen 30 saniyelik interaktif onay ekranı (Approve/Reject).
- 🎨 **Premium UI:** Dark mode, Glassmorphism detaylar ve tehdit seviyesine göre neon renk paleti.

---

## 🔒 Security & Failsafes

- **Whitelist Protection** — Sistemin kendini veya OS dosyalarını (`explorer.exe`, `python.exe`) kill etmesini engelleyen hardcoded güvenlik mekanizması.
- **Asenkron Event Loop** — `asyncio` altyapısı sayesinde decision countdown sırasında ana worker'lar blocklanmaz.
- **Tamper-Proof Logging** — Siber adli bilişim (Forensics) için her karar hashlenerek saklanır.

---

## 📝 License

Bu proje akademik sunum ve bitirme projesi amacıyla geliştirilmiştir. MIT License altındadır.
