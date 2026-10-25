import csv
import json
import os


def generate_edges():
    # Çıkartılan düğümlerin okunması
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.abspath(os.path.join(current_dir, "../inventory/inventory_v1.0.csv"))

    if not os.path.exists(csv_path):
        print(f"CSV dosyası bulunamadı! Aranan yol: {csv_path}")
        return

    # inventory_v1.0.csv verilerinin okunması
    vulnerabilities = []
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            v_id = row.get("vuln_id", "").strip()
            if not v_id:
                continue
            vulnerabilities.append({
                "id": v_id,
                "name": row.get("name", "").strip(),
                "cwe_id": row.get("cwe_id", "").strip(),
                "component": row.get("component", "").strip().lower(),
                "cvss_score": row.get("cvss_score", "").strip()
            })

    # Grupları ayırmak için açılan liste
    edges = []

    # Listeye eklenmesi için türlerine ayırma
    # 1. Tüm zafiyetleri ele alıp giriş noktalarından zafiyetlere bağlantı kurulumu
    for v in vulnerabilities:
        comp = v["component"]
        cwe = v["cwe_id"].lower()
        name = v["name"].lower()
        v_id = v["id"]

        # Login ile ilişkili açıkları Login giriş noktasına bağla
        if "login" in comp or "auth" in comp or "session" in name or "login" in name or "user-registration" in comp:
            edges.append({
                "source": "node_entry_login",
                "target": v_id,
                "relation": "Triggers",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })
        # API / Injection açıklarını API giriş noktasına bağla
        elif "api" in comp or "endpoint" in comp or "rest" in comp or "basket" in comp:
            edges.append({
                "source": "node_entry_api",
                "target": v_id,
                "relation": "Exploits Endpoint",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })
        # Genel web açıklarını Arama uç noktasına bağla
        else:
            edges.append({
                "source": "node_entry_search",
                "target": v_id,
                "relation": "Accesses via Input",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })

    # Zincirleme (çok adımlı) yolların eklenmesi (Zafiyet 1 -> Zafiyet 2)
    primary_vulns = [v for v in vulnerabilities if "cwe-89" in v["cwe_id"].lower() or "cwe-79" in v["cwe_id"].lower() or "injection" in v["name"].lower()]
    secondary_vulns = [v for v in vulnerabilities if "cwe-639" in v["cwe_id"].lower() or "cwe-285" in v["cwe_id"].lower() or "access" in v["name"].lower() or "privilege" in v["name"].lower()]

    for p in primary_vulns:
        for s in secondary_vulns:
            if p["id"] != s["id"]:
                edges.append({
                    "source": p["id"],
                    "target": s["id"],
                    "relation": "Chains To / Enables",
                    "mitre_technique": "T1068",
                    "technique_name": "Exploitation for Privilege Escalation"
                })

    # 2. Zafiyetlerden hedeflere bağlantı kurulumu
    for v in vulnerabilities:
        cwe = v["cwe_id"].lower()
        name = v["name"].lower()
        v_id = v["id"]

        # Yetkilendirme / Admin temalı açıklar -> Admin Erişimi hedefi ile eşlenir
        if "admin" in name or "privilege" in name or "access control" in name or "cwe-639" in cwe or "cwe-285" in cwe:
            edges.append({
                "source": v_id,
                "target": "node_target_admin_access",
                "relation": "Leads to Privilege Escalation",
                "mitre_technique": "T1078",
                "technique_name": "Valid Accounts"
            })

        # Sızıntı / Hassas veri / Injection / XSS -> Veri Sızıntısı hedefi ile eşlenir
        if "data" in name or "exposure" in name or "injection" in name or "sensitive" in name or "cwe-548" in cwe or "cwe-89" in cwe:
            edges.append({
                "source": v_id,
                "target": "node_target_data_leak",
                "relation": "Leads to Exfiltration",
                "mitre_technique": "T1041",
                "technique_name": "Exfiltration Over C2 Channel"
            })

    # 3. JSON Olarak Kaydet
    edges_file = os.path.join(current_dir, "edges.json")

    with open(edges_file, "w", encoding="utf-8") as f:
        json.dump(edges, f, ensure_ascii=False, indent=4)

    print(f"BAŞARILI! Toplam {len(edges)} adet kenar şu konuma kaydedildi: {edges_file}")


if __name__ == "__main__":
    generate_edges()