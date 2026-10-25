import json
import os
from pyvis.network import Network


def create_visual_graph():
    # Çıkartılan düğüm ve kenar dosyalarının yolları
    current_dir = os.path.dirname(os.path.abspath(__file__))
    nodes_path = os.path.abspath(os.path.join(current_dir, "../inventory/attack_graph_nodes.json"))
    edges_path = os.path.abspath(os.path.join(current_dir, "edges.json"))
    output_path = os.path.abspath(os.path.join(current_dir, "attack_graph_v1.html"))

    if not os.path.exists(edges_path):
        print(f"Edges dosyası bulunamadı: {edges_path}")
        return

    # PyVis ağı oluştur
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)

    # Kenarları yükle
    with open(edges_path, "r", encoding="utf-8") as f:
        edges = json.load(f)

    # Sadece kenarlarda geçen (aktif) düğüm ID'lerini topla
    active_node_ids = set()
    for e in edges:
        if e.get("source"):
            active_node_ids.add(e.get("source"))
        if e.get("target"):
            active_node_ids.add(e.get("target"))

    # Düğüm detaylarını yükle (Sadece aktif olanları ekle)
    node_details = {}
    if os.path.exists(nodes_path):
        with open(nodes_path, "r", encoding="utf-8") as f:
            nodes = json.load(f)
            for node in nodes:
                n_id = node.get("id")
                if n_id in active_node_ids:
                    node_details[n_id] = {
                        "label": node.get("name", n_id),
                        "title": node.get("description", "")
                    }

    # Aktif düğümleri ağa ekle (Giriş, hedef ve zafiyetlere göre renklendirme)
    for n_id in active_node_ids:
        details = node_details.get(n_id, {})
        label = details.get("label", n_id)
        title = details.get("title", "")

        if "node_entry" in n_id:
            net.add_node(n_id, label=label, title=title, color="#ff9900", size=25)
        elif "node_target" in n_id:
            net.add_node(n_id, label=label, title=title, color="#00cc66", size=25)
        else:
            net.add_node(n_id, label=label, title=title, color="#3388ff", size=15)

    # Kenarları ekle
    for e in edges:
        source = e.get("source")
        target = e.get("target")
        edge_title = f"{e.get('relation', '')} - {e.get('technique_name', '')}"
        edge_label = e.get("relation", "")

        if source and target:
            net.add_edge(source, target, title=edge_title, label=edge_label)

    # v1 olarak kaydet
    net.save_graph(output_path)
    print(f"BAŞARILI! Aktif saldırı yolları ile Attack Graph v1 oluşturuldu: {output_path}")


if __name__ == "__main__":
    create_visual_graph()