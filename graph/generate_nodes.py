import csv
import json
import os


def generate_nodes():
    nodes = []

    # 1. Giriş Noktaları
    entry_points = [
        {"id": "node_entry_login", "type": "entry_point", "name": "Login Ucu",
         "description": "Kullanici giris noktasi"},
        {"id": "node_entry_search", "type": "entry_point", "name": "Arama Ucu",
         "description": "Urun ve icerik arama noktasi"},
        {"id": "node_entry_api", "type": "entry_point", "name": "REST API Endpoint",
         "description": "Disa acik API arayuzu"}
    ]
    nodes.extend(entry_points)

    # 2. cwe_mapping.csv Dosyasından Zafiyet Düğümlerini Üretme
    csv_path = "../inventory/cwe_mapping.csv"
    if os.path.exists(csv_path):
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for index, row in enumerate(reader):
                vuln_name = row.get("vulnerability_name")
                category = row.get("juice_shop_category")
                cwe_id = row.get("cwe_id")

                node_id = f"node_vuln_{index + 1}"
                node_entry = {
                    "id": node_id,
                    "type": "vulnerability",
                    "name": vuln_name,
                    "category": category,
                    "cwe_id": cwe_id,
                    "description": f"{cwe_id} - {vuln_name} ({category})"
                }
                nodes.append(node_entry)

    # 3. Hedef Düğümlerini Ekleme
    targets = [
        {"id": "node_target_data_leak", "type": "target", "name": "Veri Sızıntısı",
         "description": "Kritik hassas verilerin ele geçirilmesi"},
        {"id": "node_target_admin_access", "type": "target", "name": "Admin Erişimi",
         "description": "Yönetici yetkilerinin ele geçirilmesi"}
    ]
    nodes.extend(targets)

    # 4. Çıktı Dizini ve JSON Kaydı
    output_dir = "../inventory"
    os.makedirs(output_dir, exist_ok=True)
    output_json = os.path.join(output_dir, "attack_graph_nodes.json")

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=4)

    print(
        f"Başarılı! Toplam {len(nodes)} adet düğüm (Giriş Noktaları + Zafiyetler + Hedefler) {output_json} dosyasına kaydedildi.")


if __name__ == "__main__":
    generate_nodes()