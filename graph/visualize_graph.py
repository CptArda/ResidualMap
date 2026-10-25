import csv
import json
import os
from pyvis.network import Network


def create_visual_graph():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    edges_path = os.path.abspath(os.path.join(current_dir, "edges.json"))
    csv_path = os.path.abspath(os.path.join(current_dir, "../inventory/inventory_v1.0.csv"))
    output_path = os.path.abspath(os.path.join(current_dir, "attack_graph_v1.html"))

    if not os.path.exists(edges_path):
        print(f"[HATA] Edges dosyası bulunamadı: {edges_path}")
        return

    vulnerability_names = {}
    if os.path.exists(csv_path):
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                v_id = row.get("vuln_id", "").strip()
                v_name = row.get("name", "").strip()
                if v_id and v_name:
                    vulnerability_names[v_id] = v_name

    net = Network(height="900px", width="100%", bgcolor="#1a1a1a", font_color="white", directed=True)

    with open(edges_path, "r", encoding="utf-8") as f:
        edges = json.load(f)

    active_nodes = set()
    for edge in edges:
        if edge.get("source"):
            active_nodes.add(edge.get("source"))
        if edge.get("target"):
            active_nodes.add(edge.get("target"))

    for node_id in active_nodes:
        if "node_entry" in node_id:
            # Giriş Noktaları (Level 0)
            label = node_id.replace("node_entry_", "Giriş: ").upper()
            net.add_node(node_id, label=label, title=f"Giriş Vektörü: {node_id}", color="#ff9900", size=30, level=0)

        elif "node_target" in node_id:
            # KRİTİK HEDEFLER: Etiket (label) kısmına doğrudan isimler atanıyor
            target_labels = {
                "node_target_admin": "Yetkisiz Admin Erişimi",
                "node_target_leak": "Hassas Veri Sızıntısı",
                "node_target_account_takeover": "Hesap Ele Geçirme",
                "node_target_rce": "RCE ve Sistem Ele Geçirme",
                "node_target_dos": "Hizmet Engelleme (DoS)"
            }
            # Etiket doğrudan sözlükten alınır, yoksa düzenlenmiş ID basılır
            label = target_labels.get(node_id, node_id.replace("node_target_", "").replace("_", " ").title())
            title_text = f"Kritik Hedef Düğümü\nKimlik: {node_id}\nAçıklama: {label}"

            # label=label parametresi sayesinde grafikte kutunun üstünde doğrudan bu isim yazar
            net.add_node(node_id, label=label, title=title_text, color="#ff4d4d", size=35, level=2)

        else:
            # Zafiyet Düğümleri (Level 1) -> Doğrudan CSV'deki ist (name)
            label = vulnerability_names.get(node_id, node_id)
            title_text = f"Zafiyet ID: {node_id}\nİsim: {label}"
            net.add_node(node_id, label=label, title=title_text, color="#3388ff", size=20, level=1)

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        relation = edge.get("relation", "")
        technique = edge.get("technique_name", "")

        hover_title = f"İlişki: {relation}\nTeknik: {technique}"
        if source and target:
            net.add_edge(source, target, title=hover_title, arrowStrikethrough=False)

    net.set_options("""
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "nodeSpacing": 200,
          "treeSpacing": 250,
          "levelSeparation": 340
        }
      },
      "physics": {
        "hierarchicalRepulsion": {
          "centralGravity": 0.0,
          "springLength": 150,
          "springConstant": 0.01,
          "nodeDistance": 150
        }
      }
    }
    """)

    net.save_graph(output_path)
    print(f"[BAŞARILI] Hedef etiketleri güncellenerek grafik kaydedildi: {output_path}")


if __name__ == "__main__":
    create_visual_graph()