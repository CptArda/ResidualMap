import csv
import json
import os

# Proje dizin yapısına göre dosya yollarının dinamik olarak mutlak konumda tanımlanması
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "../inventory/inventory_v1.0.csv"))
OUTPUT_EDGES_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "edges.json"))


def generate_attack_edges():

    edges = []

    # 1. Aşama: Envanter dosyasının fiziksel varlığının doğrulanması
    if not os.path.exists(CSV_PATH):
        print(f"[HATA] Envanter dosyası bulunamadı: {CSV_PATH}")
        return

    vulnerabilities = []

    # 2. Aşama: CSV verilerinin güvenli UTF-8 kodlamasıyla belleğe yüklenmesi ve normalize edilmesi
    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            v_id = row.get("vuln_id", "").strip()
            if not v_id:
                continue
            vulnerabilities.append({
                "id": v_id,
                "name": row.get("name", "").strip(),
                "component": row.get("component", "").strip().lower(),
                "cwe_id": row.get("cwe_id", "").strip().upper()
            })

    # Giriş ve Hedef havuzları (Yığılmayı önlemek ve dengeli dağılım sağlamak için)
    entry_nodes_pool = [
        ("node_entry_login", "Initial Access via Authentication & Session"),
        ("node_entry_api", "API Interface & Service Exposure"),
        ("node_entry_search", "User Input & Parameter Vector")
    ]

    target_nodes_pool = [
        ("node_target_admin", "Unauthorized Administrator Access"),
        ("node_target_leak", "Sensitive Data Exfiltration & Database Exposure"),
        ("node_target_account_takeover", "Account Takeover via Client-Side Attack"),
        ("node_target_rce", "Remote Code Execution & System Compromise"),
        ("node_target_dos", "Denial of Service & Resource Exhaustion")
    ]

    # Mantıksal zincirleme ve kategorizasyon için geçici havuzların oluşturulması
    auth_vulns = []
    input_vulns = []
    priv_vulns = []
    system_vulns = []

    # 3. Aşama: Zafiyetlerin taranması ve kenar (edge) ilişkilerinin kurulması
    for index, v in enumerate(vulnerabilities):
        v_id = v["id"]
        name = v["name"]
        component = v["component"]
        cwe_id = v["cwe_id"]
        name_lower = name.lower()

        # Giriş Noktası (Entry Point) Vektörünün Belirlenmesi
        if any(k in cwe_id or k in component or k in name_lower for k in ["287", "798", "auth", "login", "session", "credential"]):
            entry_node, technique_initial = entry_nodes_pool[0]  # Login
            auth_vulns.append(v)
        elif any(k in cwe_id or k in component or k in name_lower for k in ["200", "api", "service", "endpoint", "exposure", "proxy", "ws"]):
            entry_node, technique_initial = entry_nodes_pool[1]  # API
            input_vulns.append(v)
        else:
            # Tek bir giriş noktasına (Search) yığılmayı önlemek için homojen dağılım (Round-Robin)
            chosen_entry = entry_nodes_pool[index % len(entry_nodes_pool)]
            entry_node, technique_initial = chosen_entry[0], f"Vector via {chosen_entry[0].replace('node_entry_', '').upper()}"
            input_vulns.append(v)

        # Giriş kenarının (Entry Point) listeye eklenmesi
        edges.append({
            "source": entry_node,
            "target": v_id,
            "relation": "Entry Point",
            "technique_name": technique_initial
        })

        # Etki Hedeflerine (Impact Target) Dengeli Dağılım
        if any(k in cwe_id or k in name_lower for k in ["269", "250", "admin", "privilege", "escalation"]):
            target_node, technique_impact = target_nodes_pool[0]  # Admin
            priv_vulns.append(v)
        elif any(k in cwe_id or k in name_lower for k in ["200", "538", "leak", "disclosure", "sql", "89", "information", "idor"]):
            target_node, technique_impact = target_nodes_pool[1]  # Data Leak
        elif any(k in cwe_id or k in name_lower for k in ["79", "601", "csrf", "xss", "session", "account", "basket", "cookie"]):
            target_node, technique_impact = target_nodes_pool[2]  # Account Takeover
        elif any(k in cwe_id or k in name_lower for k in ["78", "94", "rce", "execution", "command", "code", "decompress"]):
            target_node, technique_impact = target_nodes_pool[3]  # RCE
            system_vulns.append(v)
        else:
            # DoS hedefine aşırı yığılmayı önlemek için 5 hedef arasında dengeli dağılım
            chosen_target = target_nodes_pool[index % len(target_nodes_pool)]
            target_node, technique_impact = chosen_target[0], f"Impact leading to {chosen_target[0].replace('node_target_', '').upper()}"
            system_vulns.append(v)

        # Hedef kenarının (Leads To) listeye eklenmesi
        edges.append({
            "source": v_id,
            "target": target_node,
            "relation": "Leads To",
            "technique_name": technique_impact
        })

    # Anlamlı ve Mantıksal Zafiyetler Arası Zincirleme (Chains To)
    for i, auth_v in enumerate(auth_vulns):
        if priv_vulns:
            target_chain = priv_vulns[i % len(priv_vulns)]
            if auth_v["id"] != target_chain["id"]:
                edges.append({
                    "source": auth_v["id"],
                    "target": target_chain["id"],
                    "relation": "Chains To",
                    "technique_name": "Authentication Flaw Leading to Privilege Escalation"
                })

    for i, inp_v in enumerate(input_vulns):
        if system_vulns:
            target_chain = system_vulns[i % len(system_vulns)]
            if inp_v["id"] != target_chain["id"]:
                edges.append({
                    "source": inp_v["id"],
                    "target": target_chain["id"],
                    "relation": "Chains To",
                    "technique_name": "Input Vector Chaining to System Compromise"
                })

    # 4. Aşama: Üretilen tüm kenar ve zincir verilerinin edges.json dosyasına yazılması
    with open(OUTPUT_EDGES_PATH, "w", encoding="utf-8") as outfile:
        json.dump(edges, outfile, indent=4, ensure_ascii=False)

    print(f"[BAŞARILI] Profesyonel ve dengeli mimariyle toplam {len(edges)} mantıksal kenar üretildi: {OUTPUT_EDGES_PATH}")


if __name__ == "__main__":
    generate_attack_edges()