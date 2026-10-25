import json
import os


def generate_edges():
    # Çıkartılan düğümlerin okunması
    current_dir = os.path.dirname(os.path.abspath(__file__))
    nodes_path = os.path.abspath(os.path.join(current_dir, "../inventory/attack_graph_nodes.json"))

    if not os.path.exists(nodes_path):
        print(f"Düğüm dosyası bulunamadı! Aranan yol: {nodes_path}")
        return

    with open(nodes_path, "r", encoding="utf-8") as f:
        nodes = json.load(f)

    # Grupları ayırmak için açılan liste
    edges = []

    # Listeye eklenmesi için türlerine ayırma
    entry_nodes = [n for n in nodes if n["type"] == "entry_point"]
    vuln_nodes = [n for n in nodes if n["type"] == "vulnerability"]
    target_nodes = [n for n in nodes if n["type"] == "target"]

    # 1. Tüm zafiyetleri ele alıp giriş noktalarından zafiyetlere bağlantı kurulumu
    for v in vuln_nodes:
        cat = v.get("category", "")
        name = v.get("name", "").lower()

        # Login ile ilişkili açıkları Login giriş noktasına bağla
        if "login" in name or "authentication" in name.lower() or "session" in name.lower():
            edges.append({
                "source": "node_entry_login",
                "target": v["id"],
                "relation": "Triggers",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })
        # API / Injection açıklarını API giriş noktasına bağla
        elif "api" in name or "injection" in cat.lower() or "xss" in cat.lower():
            edges.append({
                "source": "node_entry_api",
                "target": v["id"],
                "relation": "Exploits Endpoint",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })
        # Genel web açıklarını Arama uç noktasına bağla
        else:
            edges.append({
                "source": "node_entry_search",
                "target": v["id"],
                "relation": "Accesses via Input",
                "mitre_technique": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            })

    # 2. Zafiyetlerden hedeflere bağlantı kurulumu
    for v in vuln_nodes:
        cat = v.get("category", "")
        name = v.get("name", "").lower()

        # Yetkilendirme / Admin temalı açıklar -> Admin Erişimi hedefi ile eşlenir
        if "admin" in name or "broken access" in cat.lower() or "privilege" in name:
            edges.append({
                "source": v["id"],
                "target": "node_target_admin_access",
                "relation": "Leads to Privilege Escalation",
                "mitre_technique": "T1078",
                "technique_name": "Valid Accounts"
            })

        # Sızıntı / Hassas veri / Injection / XSS -> Veri Sızıntısı hedefi ile eşlenir
        if "data" in cat.lower() or "exposure" in cat.lower() or "injection" in cat.lower() or "sensitive" in name:
            edges.append({
                "source": v["id"],
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