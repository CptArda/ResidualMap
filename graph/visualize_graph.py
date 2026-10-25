import json
import os
from pyvis.network import Network


def create_visual_graph():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    nodes_path = os.path.abspath(os.path.join(current_dir, "../inventory/attack_graph_nodes.json"))
    edges_path = os.path.abspath(os.path.join(current_dir, "edges.json"))

    if not os.path.exists(nodes_path) or not os.path.exists(edges_path):
        print(f"Hata! Dosya bulunamadı.\nDüğüm: {nodes_path}\nKenar: {edges_path}")
        return

    with open(nodes_path, "r", encoding="utf-8") as f:
        nodes = json.load(f)

    with open(edges_path, "r", encoding="utf-8") as f:
        edges = json.load(f)

    # Ağ grafiği oluşturuluyor (Standart ve sade yapı)
    net = Network(height="900px", width="100%", directed=True, bgcolor="#222222", font_color="white")

    color_map = {
        "entry_point": "#4CAF50",  # Yeşil
        "vulnerability": "#FF9800",  # Turuncu
        "target": "#F44336"  # Kırmızı
    }

    for n in nodes:
        node_type = n.get("type", "vulnerability")
        color = color_map.get(node_type, "#9E9E9E")
        title_text = f"<b>{n['name']}</b><br>ID: {n['id']}<br>{n.get('description', '')}"

        net.add_node(
            n["id"],
            label=n["name"],
            title=title_text,
            color=color,
            shape="ellipse" if node_type == "vulnerability" else "box"
        )

    for e in edges:
        edge_label = f"{e['mitre_technique']}"
        edge_title = f"Teknik: {e['mitre_technique']} ({e['technique_name']})<br>İlişki: {e['relation']}"
        net.add_edge(e["source"], e["target"], title=edge_title, label=edge_label)

    output_html = os.path.join(current_dir, "attack_graph_v1.html")
    net.write_html(output_html)
    print(f"Görselleştirme tamamlandı! İnteraktif harita '{output_html}' dosyasına kaydedildi.")


if __name__ == "__main__":
    create_visual_graph()

