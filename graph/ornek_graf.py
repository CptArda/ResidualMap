"""
ResidualMap - Örnek Saldırı Grafiği Modülü
Amaç: networkx ve pyvis ile 4 düğümlü saldırı zinciri prototipi oluşturmak
      ve graf verisini standart JSON formatında dışa aktarmak.
"""
import json
from pathlib import Path
import networkx as nx
from pyvis.network import Network


def ornek_graf_olustur():
    # 1. Yönlü grafiği başlat
    G = nx.DiGraph()

    # 2. 4 Durum Düğümü (States)
    G.add_node("N0", label="Dış Ağ (Saldırgan)", color="#3498db", shape="box", title="Başlangıç Noktası")
    G.add_node("N1", label="Kullanıcı Oturumu (BOLA/IDOR)", color="#f39c12", shape="box", title="Oturum Ele Geçirildi")
    G.add_node("N2", label="Admin Paneli Erişimi (JWT Bypass)", color="#e67e22", shape="box", title="Yetki Yükseltildi")
    G.add_node("N3", label="Hedef: Veritabanı Sızıntısı (SQLi)", color="#e74c3c", shape="box", title="Kritik Veri İhlali")

    # 3. Zafiyet/Geçiş Kenarları (Transitions)
    G.add_edge(
        "N0", "N1",
        label="IDOR",
        vulnerability="BOLA / IDOR",
        capec="CAPEC-1",
        mitre="T1190",
        cvss=7.5,
        weight=7.5,
        title="Zafiyet: BOLA / IDOR<br>CAPEC: CAPEC-1<br>CVSS: 7.5"
    )
    G.add_edge(
        "N1", "N2",
        label="JWT None Alg",
        vulnerability="JWT Key Confusion",
        capec="CAPEC-59",
        mitre="T1078",
        cvss=8.8,
        weight=8.8,
        title="Zafiyet: JWT Key Confusion<br>CAPEC: CAPEC-59<br>CVSS: 8.8"
    )
    G.add_edge(
        "N2", "N3",
        label="Data Dumping",
        vulnerability="SQL Injection",
        capec="CAPEC-66",
        mitre="T1190",
        cvss=9.8,
        weight=9.8,
        title="Zafiyet: SQL Injection<br>CAPEC: CAPEC-66<br>CVSS: 9.8"
    )
    G.add_edge(
        "N0", "N2",
        label="Login SQLi",
        vulnerability="Login SQL Injection",
        capec="CAPEC-66",
        mitre="T1190",
        cvss=9.8,
        weight=9.8,
        title="Zafiyet: Login SQL Injection<br>CAPEC: CAPEC-66<br>CVSS: 9.8"
    )

    mevcut_dizin = Path(__file__).resolve().parent

    # 4. JSON Formatında Dışa Aktar (Data Exchange Format)
    cikis_json_yolu = mevcut_dizin / "ornek_graf.json"
    graf_verisi = {
        "nodes": [
            {"id": dugum, "label": veri.get("label"), "title": veri.get("title")}
            for dugum, veri in G.nodes(data=True)
        ],
        "edges": [
            {
                "source": u,
                "target": v,
                "label": veri.get("label"),
                "vulnerability_name": veri.get("vulnerability"),
                "capec_id": veri.get("capec"),
                "mitre_technique": veri.get("mitre"),
                "cvss": veri.get("cvss"),
                "weight": veri.get("weight")
            }
            for u, v, veri in G.edges(data=True)
        ]
    }

    with open(cikis_json_yolu, "w", encoding="utf-8") as f:
        json.dump(graf_verisi, f, indent=2, ensure_ascii=False)

    # 5. PyVis HTML Görselleştirmesi
    cikis_html_yolu = mevcut_dizin / "ornek_graf.html"
    net = Network(height="600px", width="100%", directed=True)
    net.from_nx(G)
    net.write_html(str(cikis_html_yolu))

    print(f"[+] Başarılı: JSON verisi oluşturuldu -> {cikis_json_yolu}")
    print(f"[+] Başarılı: HTML görseli oluşturuldu -> {cikis_html_yolu}")
    print(f"[+] Toplam Düğüm: {G.number_of_nodes()}, Toplam Kenar: {G.number_of_edges()}")


if __name__ == "__main__":
    ornek_graf_olustur()