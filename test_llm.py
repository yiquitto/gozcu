"""LM Studio baglanti testi."""
import urllib.request
import json

url = "http://localhost:1234/v1/models"
try:
    r = urllib.request.urlopen(url, timeout=5)
    data = json.loads(r.read())
    models = [m["id"] for m in data.get("data", [])]
    print(f"[OK] LM Studio baglantisi basarili!")
    print(f"     Yuklenen modeller: {models}")
    print(f"\n     .env dosyasindaki LLM_MODEL degerini su sekilde ayarla:")
    for m in models:
        print(f"     LLM_MODEL={m}")
except Exception as e:
    print(f"[HATA] LM Studio'ya baglanamadi: {e}")
    print(f"       LM Studio'yu ac ve 'Start Server' butonuna bas.")
