import csv
import json
import os

# Dosya yollarının dinamik olarak mutlak konumda belirlenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.abspath(os.path.join(current_dir, "../inventory/inventory_v1.0.csv"))
output_edges_path = os.path.abspath(os.path.join(current_dir, "edges.json"))

edges = []
nodes_dict = {}

# Sistem giriş noktaları (Entry Points) tanımı
entry_nodes = {
    "node_entry_login": {"name": "Giriş Portalı (Login Form)", "type": "entry"},
    "node_entry_api": {"name": "API Endpoint", "type": "entry"},
    "node_entry_search": {"name": "Arama Uç Noktası", "type": "entry"}
}

# Nihai hedef düğümleri (Target Nodes) tanımı
target_nodes = {
    "node_target_admin": {"name": "Yetkisiz Admin Erişimi", "type": "target"},
    "node_target_leak": {"name": "Hassas Veri Sızıntısı", "type": "target"}
}

# CSV veri kaynağının satır satır okunması ve işlenmesi
if os.path.exists(csv_path):
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            v_id = row.get("vuln_id", "").strip()
            if not v_id:
                continue

            name = row.get("name", v_id)
            component = row.get("component", "").lower()
            cwe_id = row.get("cwe_id", "")

            # Düğüm detay sözlüğünün oluşturulması
            nodes_dict[v_id] = {
                "id": v_id,
                "name": f"{v_id}: {name}",
                "description": f"Bileşen: {component} | CWE: {cwe_id}"
            }

            # Giriş Noktası Eşleme Mantığı
            # Zafiyetin bileşen (component) ve CWE değerine göre uygun giriş noktasıyla ilişkilendirilmesi
            if "login" in component or "auth" in component or "cwe-287" in cwe_id.lower() or "cwe-798" in cwe_id.lower():
                edges.append({"source": "node_entry_login", "target": v_id, "relation": "Entry Point",
                              "technique_name": "Initial Access"})
            elif "api" in component or "service" in component or "cwe-200" in cwe_id.lower():
                edges.append({"source": "node_entry_api", "target": v_id, "relation": "Entry Point",
                              "technique_name": "API Exposure"})
            else:
                # Yüksek riskli veya eşleşmeyen zafiyetlerin boşta (izole) kalmaması için genel arama/giriş noktasına yönlendirme
                edges.append({"source": "node_entry_search", "target": v_id, "relation": "Entry Point",
                              "technique_name": "User Input Exposure"})

            # Multi-step (Çok Adımlı) Zincirleme ve Hedef Bağlantı Mantığı
            if "sql" in name.lower() or "cwe-89" in cwe_id.lower() or "admin" in component:
                edges.append({"source": v_id, "target": "node_target_admin", "relation": "Leads To",
                              "technique_name": "Privilege Escalation"})
            elif "xss" in name.lower() or "disclosure" in name.lower() or "cwe-200" in cwe_id.lower():
                edges.append({"source": v_id, "target": "node_target_leak", "relation": "Leads To",
                              "technique_name": "Exfiltration"})

# Üretilen kenar listesinin edges.json dosyasına kaydedilmesi
with open(output_edges_path, "w", encoding="utf-8") as f:
    json.dump(edges, f, indent=4, ensure_ascii=False)

print(f"BAŞARILI! Toplam {len(edges)} kenar mantıksal olarak oluşturuldu: {output_edges_path}")