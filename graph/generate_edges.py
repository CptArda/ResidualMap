import csv
import json
import os

# Proje dizin yapısına göre dosya yollarının dinamik olarak mutlak konumda tanımlanması
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "../inventory/inventory_v1.0.csv"))
OUTPUT_EDGES_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "edges.json"))


def generate_attack_edges():
    edges = []

    # Envanter dosyasının varlığının kontrol edilmesi
    if not os.path.exists(CSV_PATH):
        print(f"[HATA] Envanter dosyası bulunamadı: {CSV_PATH}")
        return

    vulnerabilities = []

    # CSV dosyasının güvenli bir şekilde UTF-8 encoding ile belleğe yüklenmesi
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            # Zafiyet ID'sinin doğrulanması
            v_id = row.get("vuln_id", "").strip()
            if not v_id:
                continue

            # Verilerin normalize edilmesi (küçük harfe çevirme ve boşluk temizleme)
            vulnerabilities.append({
                "id": v_id,
                "name": row.get("name", "").strip().lower(),
                "component": row.get("component", "").strip().lower(),
                "cwe_id": row.get("cwe_id", "").strip().upper()
            })

    # Zafiyetlerin tek tek işlenmesi ve kenarların üretilmesi
    for index, v in enumerate(vulnerabilities):
        v_id = v["id"]
        name = v["name"]
        component = v["component"]
        cwe_id = v["cwe_id"]


        # ADIM 1: Giriş Noktası (Entry Point) Vektörünün Belirlenmesi

        if any(keyword in component or keyword in cwe_id for keyword in ["login", "auth", "session", "cwe-287", "cwe-798"]):
            entry_node = "node_entry_login"
            technique_initial = "Initial Access via Authentication"
        elif any(keyword in component or keyword in cwe_id for keyword in ["api", "service", "endpoint", "cwe-200"]):
            entry_node = "node_entry_api"
            technique_initial = "API Exposure & Interface Abuse"
        else:
            entry_node = "node_entry_search"  # Varsayılan kullanıcı etkileşim vektörü
            technique_initial = "User Input Vector"

        # Giriş kenarının eklenmesi
        edges.append({
            "source": entry_node,
            "target": v_id,
            "relation": "Entry Point",
            "technique_name": technique_initial
        })


        # ADIM 2: Zafiyetler Arası Zincirleme (Multi-step Attack Chains)

        if index < len(vulnerabilities) - 1:
            next_v_id = vulnerabilities[index + 1]["id"]
            if next_v_id != v_id:
                edges.append({
                    "source": v_id,
                    "target": next_v_id,
                    "relation": "Chains To",
                    "technique_name": "Lateral Movement / Privilege Escalation Chain"
                })


        # ADIM 3: 5 Profesyonel Etki Hedefine (Impact Target) Dağıtım

        if any(keyword in name or keyword in component or keyword in cwe_id for keyword in ["admin", "privilege", "escalation", "cwe-269"]):
            target_node = "node_target_admin"
            relation_type = "Leads To"
            technique_impact = "Unauthorized Admin Access"
        elif any(keyword in name or keyword in component or keyword in cwe_id for keyword in ["leak", "disclosure", "information", "cwe-200", "sql", "cwe-89"]):
            target_node = "node_target_leak"
            relation_type = "Leads To"
            technique_impact = "Sensitive Data Exfiltration"
        elif any(keyword in name or keyword in component or keyword in cwe_id for keyword in ["account", "session", "csrf", "xss", "cwe-79", "auth"]):
            target_node = "node_target_account_takeover"
            relation_type = "Leads To"
            technique_impact = "Account Takeover & Unauthorized Action"
        elif any(keyword in name or keyword in component or keyword in cwe_id for keyword in ["rce", "execution", "command", "code", "cwe-78", "remote"]):
            target_node = "node_target_rce"
            relation_type = "Leads To"
            technique_impact = "Remote Code Execution & System Compromise"
        else:
            # Özel bir kategoriye uymayan sistem kararsızlıkları ve performans riskleri için
            target_node = "node_target_dos"
            relation_type = "Leads To"
            technique_impact = "Denial of Service (DoS)"

        # Hedef kenarının eklenmesi
        edges.append({
            "source": v_id,
            "target": target_node,
            "relation": relation_type,
            "technique_name": technique_impact
        })

    # Üretilen tüm kenar verilerinin edges.json dosyasına yazılması
    with open(OUTPUT_EDGES_PATH, "w", encoding="utf-8") as outfile:
        json.dump(edges, outfile, indent=4, ensure_ascii=False)

    print(f"[BAŞARILI] Toplam {len(edges)} mantıksal ve zincirleme kenar üretildi: {OUTPUT_EDGES_PATH}")


if __name__ == "__main__":
    generate_attack_edges()