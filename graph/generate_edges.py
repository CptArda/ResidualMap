"""
    Bu modül, 'inventory/inventory_v1.0.csv' envanter dosyasını okuyarak siber
    güvenlik standartlarına (CWE eşleştirmeleri) dayalı bir saldırı grafiği
    oluşturur. Rastgele veya zorlama atamalar yerine;
    1. Giriş vektörlerini (Login, API, Search) belirler,
    2. CWE tabanlı küme analiziyle zafiyetleri 5 profesyonel etki hedefine bağlar,
    3. Yetenek (capability) bağımlılıklarına göre gerçekçi 'Chains To' zincirleri kurar,
    4. Nihai grafiği 'edges.json' olarak dışa aktarır.
"""

import csv
import json
import os

# Proje dizin yapısına göre dosya yollarının dinamik olarak mutlak konumda tanımlanması
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "../inventory/inventory_v1.0.csv"))
OUTPUT_EDGES_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "edges.json"))


# CWE (Common Weakness Enumeration) Kümeleri Tanımları
# Zafiyetlerin etki hedeflerine doğru bir şekilde bağlanması için standart CWE kodları kategorize edilmiştir.

ADMIN_CWES = {"cwe-798", "cwe-521", "cwe-20", "cwe-290", "cwe-285", "cwe-915"}
LEAK_CWES = {"cwe-200", "cwe-548", "cwe-611", "cwe-209", "cwe-264", "cwe-497", "cwe-328"}
ACCOUNT_CWES = {"cwe-79", "cwe-639", "cwe-640", "cwe-352", "cwe-601", "cwe-693", "cwe-749", "cwe-331"}
RCE_CWES = {"cwe-1321", "cwe-94", "cwe-22", "cwe-176", "cwe-122", "cwe-119"}
DOS_CWES = {"cwe-400", "cwe-476", "cwe-248"}


def map_to_target(v_id, name, cwe_id):

    cwe = cwe_id.lower().strip()
    name_lower = name.lower()

    # İstisnai Durum: CWE-89 bağlama göre ayrıştırılır
    if cwe == "cwe-89":
        if "login" in name_lower or "admin" in name_lower:
            return "node_target_admin"
        return "node_target_leak"

    # Standart CWE Küme Kontrolleri
    if cwe in ADMIN_CWES:
        return "node_target_admin"
    if cwe in LEAK_CWES:
        return "node_target_leak"
    if cwe in ACCOUNT_CWES:
        return "node_target_account_takeover"
    if cwe in RCE_CWES:
        return "node_target_rce"
    if cwe in DOS_CWES:
        return "node_target_dos"

    # Kümede yer almasa bile isim bazlı kesin admin göstergeleri
    if "admin" in name_lower:
        return "node_target_admin"

    return None


# Hedef düğüm kimliklerinin profesyonel teknik metin karşılıkları
TARGET_TECHNIQUE_NAMES = {
    "node_target_admin": "Unauthorized Administrator Access",
    "node_target_leak": "Sensitive Data Exfiltration & Database Exposure",
    "node_target_account_takeover": "Account Takeover via Client-Side Attack",
    "node_target_rce": "Remote Code Execution & System Compromise",
    "node_target_dos": "Denial of Service & Resource Exhaustion",
}


def generate_attack_edges():
    """
    Envanter dosyasını okur, giriş noktalarını, CWE tabanlı etki hedeflerini
    ve yetenek tabanlı (capability-based) zafiyet zincirlerini hesaplayarak
    edges.json dosyasına kaydeder.
    """
    edges = []

    # Envanter dosyasının varlığının doğrulanması
    if not os.path.exists(CSV_PATH):
        print(f"[HATA] Envanter dosyası bulunamadı: {CSV_PATH}")
        return

    vulnerabilities = []

    # CSV verilerinin güvenli bir şekilde okunması ve normalize edilmesi
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
                "cwe_id": row.get("cwe_id", "").strip().upper(),
                # Yetenek tabanlı zincirleme için gerekli capability sütunları (varsayılan: "none")
                "requires_capability": row.get("requires_capability", "none").strip().lower() or "none",
                "grants_capability": row.get("grants_capability", "none").strip().lower() or "none",
            })

    # Giriş noktaları havuzu ve teknik tanımları
    entry_nodes_pool = [
        ("node_entry_login", "Initial Access via Authentication & Session"),
        ("node_entry_api", "API Interface & Service Exposure"),
        ("node_entry_search", "User Input & Parameter Vector")
    ]

    unmapped_targets = []

    # Her bir zafiyet için giriş ve hedef kenarlarının üretilmesi
    for index, v in enumerate(vulnerabilities):
        v_id = v["id"]
        name = v["name"]
        component = v["component"]
        cwe_id = v["cwe_id"]
        name_lower = name.lower()

        # 1. Aşama: Giriş Noktası (Entry Point) Vektörünün Belirlenmesi
        if any(k in cwe_id.lower() or k in component or k in name_lower for k in
               ["287", "798", "auth", "login", "session", "credential"]):
            entry_node, technique_initial = entry_nodes_pool[0]
        elif any(k in cwe_id.lower() or k in component or k in name_lower for k in
                 ["200", "api", "service", "endpoint", "exposure", "proxy", "ws"]):
            entry_node, technique_initial = entry_nodes_pool[1]
        else:
            chosen_entry = entry_nodes_pool[index % len(entry_nodes_pool)]
            entry_node, technique_initial = chosen_entry[
                0], f"Vector via {chosen_entry[0].replace('node_entry_', '').upper()}"

        edges.append({
            "source": entry_node,
            "target": v_id,
            "relation": "Entry Point",
            "technique_name": technique_initial
        })

        # 2. Aşama: CWE Bazlı Hedef Eşlemesi ve 'Leads To' Kenarının Oluşturulması
        target_node = map_to_target(v_id, name, cwe_id)
        if target_node is not None:
            edges.append({
                "source": v_id,
                "target": target_node,
                "relation": "Leads To",
                "technique_name": TARGET_TECHNIQUE_NAMES[target_node]
            })
        else:
            unmapped_targets.append(v_id)

    # 3. Aşama: Capability (Yetenek) Tabanlı Mantıksal Zincirleme ('Chains To')
    # Bir zafiyetin sağladığı yetenek, başka bir zafiyetin çalışması için gerekliyse  anlamlı bir saldırı yolu oluşturulur.
    capability_sources = {}
    for v in vulnerabilities:
        grants = v["grants_capability"]
        if grants != "none":
            capability_sources.setdefault(grants, []).append(v["id"])

    for v in vulnerabilities:
        requires = v["requires_capability"]
        if requires != "none" and requires in capability_sources:
            for source_id in capability_sources[requires]:
                if source_id != v["id"]:
                    edges.append({
                        "source": source_id,
                        "target": v["id"],
                        "relation": "Chains To",
                        "technique_name": f"{requires} elde edilince mümkün olur"
                    })

    # 4. Aşama: Üretilen tüm verilerin JSON formatında diske yazılması
    with open(OUTPUT_EDGES_PATH, "w", encoding="utf-8") as outfile:
        json.dump(edges, outfile, indent=4, ensure_ascii=False)

    # Konsol Bilgilendirme Çıktıları
    print(f"[BAŞARILI] Toplam {len(edges)} kenar üretildi: {OUTPUT_EDGES_PATH}")
    if unmapped_targets:
        print(
            f"[UYARI] {len(unmapped_targets)} zafiyet hiçbir hedefe eşlenemedi (düşük etkili/destekleyici bulgular): {', '.join(unmapped_targets)}")
    else:
        print("Tüm zafiyetler bir hedefe eşlendi.")


if __name__ == "__main__":
    generate_attack_edges()