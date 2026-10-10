import json
import csv
import os

# Dosya yolları
zap_path = "inventory/raw/zap_baseline.json"
output_csv = "inventory/cwe_mapping.csv"
# Ayıklanan zaafiyetlerin koyulacağı liste
vulnerabilities = []

# Dosyayı okuma modunda utf-8 formatında açar ve pythonun anlayacağı sözlük yapısına dönüstürür
if os.path.exists(zap_path):
    with open(zap_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)

            # Okuma
            # ZAP JSON yapısına göre alert'leri bulma
            # ZAP çıktıları genelde 'site' anahtarı altında bir liste veya sözlük barındırır
            sites = data.get("site", [])
            if isinstance(sites, dict):
                sites = [sites]

            # Rapordaki her siteyi ve sitenin altındaki uyarıları tek tek inceler
            for site in sites:
                alerts = site.get("alert", [])  # Bazı ZAP versiyonlarında 'alerts' bazılarında 'alert' olur
                if not alerts and "alerts" in site:
                    alerts = site.get("alerts", [])

                # Zaafiyet adını çeker hem alert hem name yoksa Unknown Vulnerability yazar
                for alert in alerts:
                    name = alert.get("alert") or alert.get("name") or "Unknown Vulnerability"
                    cweid = alert.get("cweid", "0")  # Zaafiyetin resmi CWE numarasını yakalar
                    description = alert.get("desc", "").replace("\n", " ")

                    # Yakalanan numarayı resmi formata sokar
                    cwe_str = f"CWE-{cweid}" if str(cweid).isdigit() and str(cweid) != "0" else "CWE-Unknown"

                    # Aynı zafiyetin tekrar eklenmesini önlemek için kontrol eder
                    vuln_entry = {
                        "vulnerability_name": name,
                        "juice_shop_category": "Web Vulnerability",
                        "cwe_id": cwe_str,
                        "cwe_name": name
                    }
                    if vuln_entry not in vulnerabilities:
                        vulnerabilities.append(vuln_entry)

        except json.JSONDecodeError:
            print("Hata: zap_baseline.json dosyası geçerli bir JSON formatında değil.")

# CSV klasörünü oluşturur ve verileri yazdırırpython map_cwe.py
os.makedirs("inventory", exist_ok=True)
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["vulnerability_name", "juice_shop_category", "cwe_id", "cwe_name"])
    writer.writeheader()
    writer.writerows(vulnerabilities)

print(f"Başarılı! {len(vulnerabilities)} adet zafiyet {output_csv} dosyasına kaydedildi.")