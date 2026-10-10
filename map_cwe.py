import json
import csv
import os

# Dosya yolları
zap_path = "inventory/raw/zap_baseline.json"
output_csv = "inventory/cwe_mapping.csv"
# Ayıklanan zaafiyetlerin koyulacağı liste
vulnerabilities = []

# ZAP alert veya CWE ID'lerini Juice Shop kategorilerine eşleyen sözlük
CATEGORY_MAP = {
    "CWE-693": "Security Misconfiguration",
    "CWE-264": "Broken Access Control",
    "CWE-749": "Injection",
    "CWE-16": "Security Misconfiguration",
    "CWE-497": "Sensitive Data Exposure",
    "CWE-524": "Cryptographic Failures",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "Injection"
}


def get_juice_shop_category(cwe_id, alert_name):
    # Önce CWE ID'sine göre eşleme yap
    if cwe_id in CATEGORY_MAP:
        return CATEGORY_MAP[cwe_id]

    # CWE yoksa veya bulunamadıysa zafiyet ismine göre arat
    name_lower = alert_name.lower()
    if "header" in name_lower or "policy" in name_lower:
        return "Security Misconfiguration"
    elif "leak" in name_lower or "disclosure" in name_lower or "timestamp" in name_lower:
        return "Sensitive Data Exposure"
    elif "content" in name_lower or "cache" in name_lower:
        return "Cryptographic Failures"

    return "Miscellaneous"

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

                    category = get_juice_shop_category(cwe_str, name)

                    vuln_entry = {
                        "vulnerability_name": name,
                        "juice_shop_category": category,
                        "cwe_id": cwe_str,
                        "cwe_name": name
                    }
                    if vuln_entry not in vulnerabilities:
                        vulnerabilities.append(vuln_entry)

        except json.JSONDecodeError:
            print("Hata: zap_baseline.json dosyası geçerli bir JSON formatında değil.")

# CSV klasörünü oluşturur ve verileri yazdırır
os.makedirs("inventory", exist_ok=True)
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["vulnerability_name", "juice_shop_category", "cwe_id", "cwe_name"])
    writer.writeheader()
    writer.writerows(vulnerabilities)

print(f"Başarılı! {len(vulnerabilities)} adet zafiyet {output_csv} dosyasına kaydedildi.")