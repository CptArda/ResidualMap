import json
import os
from pyvis.network import Network


def create_visual_graph():
    # Dosya yollarının güvenli bir şekilde mutlak konumda ayarlanması
    current_dir = os.path.dirname(os.path.abspath(__file__))
    edges_path = os.path.abspath(os.path.join(current_dir, "edges.json"))
    output_path = os.path.abspath(os.path.join(current_dir, "attack_graph_v1.html"))

    if not os.path.exists(edges_path):
        print(f"Edges dosyası bulunamadı: {edges_path}")
        return

    # PyVis ağ nesnesinin koyu tema ve yönlü (directed) yapı ile başlatılması
    net = Network(height="800px", width="100%", bgcolor="#1a1a1a", font_color="white", directed=True)

    # Kenar verilerinin JSON dosyasından okunması
    with open(edges_path, "r", encoding="utf-8") as f:
        edges = json.load(f)

    # Grafik karmaşasını önlemek adına yalnızca aktif (kenarı bulunan) düğüm kimliklerinin toplanması
    active_nodes = set()
    for e in edges:
        if e.get("source"):
            active_nodes.add(e.get("source"))
        if e.get("target"):
            active_nodes.add(e.get("target"))

    # Aktif düğümlerin ağ yapılandırmasına eklenmesi (Türlerine göre hiyerarşi seviyesi ve renk ataması)
    for n_id in active_nodes:
        if "node_entry" in n_id:
            label = n_id.replace("node_entry_", "Giriş: ").upper()
            net.add_node(n_id, label=label, title=f"Giriş Noktası: {n_id}", color="#ff9900", size=30, level=0)
        elif "node_target" in n_id:
            label = n_id.replace("node_target_", "Hedef: ").upper()
            net.add_node(n_id, label=label, title=f"Kritik Hedef: {n_id}", color="#ff4d4d", size=35, level=2)
        else:
            # Zafiyet düğümleri (V001 vb.) için etiket ve ipucu ayarları
            label = n_id
            title_text = f"Zafiyet ID: {n_id}"
            net.add_node(n_id, label=label, title=title_text, color="#3388ff", size=20, level=1)

    # Kenarların eklenmesi (Ekran kalabalığını önlemek için sabit label kullanılmaz, hover için title kullanılır)
    for e in edges:
        source = e.get("source")
        target = e.get("target")
        relation = e.get("relation", "")
        technique = e.get("technique_name", "")

        # Kullanıcı fare ile kenarın üzerine geldiğinde (hover) görünecek detaylı açıklama metni
        hover_title = f"İlişki: {relation}\nTeknik: {technique}"

        if source and target:
            net.add_edge(source, target, title=hover_title, arrowStrikethrough=False)

    # Okunabilirliği maksimize eden Hiyerarşik Düzen (Hierarchical Layout) ve fizik motoru konfigürasyonu
    net.set_options("""
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "nodeSpacing": 150,
          "treeSpacing": 200
        }
      },
      "physics": {
        "hierarchicalRepulsion": {
          "centralGravity": 0.0,
          "springLength": 100,
          "springConstant": 0.01,
          "nodeDistance": 120
        }
      }
    }
    """)

    # İnteraktif HTML çıktısının attack_graph_v1.html olarak kaydedilmesi
    net.save_graph(output_path)
    print(f"BAŞARILI! Hiyerarşik Attack Graph v1 başarıyla oluşturuldu: {output_path}")


if __name__ == "__main__":
    create_visual_graph()