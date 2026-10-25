
#!/usr/bin/env python3
"""
[H5][K4] Baseline sıralama

Sadece CVSS skoruna göre sıralar.
Girdi : ai/features.csv
Çıktı : ai/baseline_ranking.csv

Kullanım:
python ai/baseline_ranking.py
"""

import argparse
import os
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="ai/features.csv")
    ap.add_argument("--out", default="ai/baseline_ranking.csv")
    args = ap.parse_args()

    # Veriyi oku
    df = pd.read_csv(args.features)

 
    required_cols = ["vuln_id", "cve_id", "name", "cwe_id", "cvss_score"]
    missing = [col for col in required_cols if col not in df.columns]

    if missing:
        raise ValueError(f"Eksik sütunlar: {missing}")

    # CVSS skorlarını sayısal formata dönüştür
    df["cvss_score"] = pd.to_numeric(
        df["cvss_score"], errors="coerce"
    )

    # CVSS skoru bulunmayan kayıtları sıralamaya alma
    df = df.dropna(subset=["cvss_score"]).copy()

    # Boş CVE kimliklerini boş metin olarak düzenle
    df["cve_id"] = df["cve_id"].fillna("").astype(str)

    # CVSS yüksekten düşüğe; eşitlikte vuln_id (artık birincil anahtar olarak
    # tutarlı ve tekrarlanabilir bir sıralama veriyor, isim/cve_id yerine)
    df = df.sort_values(
        ["cvss_score", "vuln_id"],
        ascending=[False, True]
    ).reset_index(drop=True)

    # Aynı CVSS skorları aynı sırayı alır
    df["baseline_rank"] = (
        df["cvss_score"]
        .rank(method="min", ascending=False)
        .astype(int)
    )

    df["baseline_score"] = df["cvss_score"]

    # Mevcut CSV yapısına uygun çıktı sütunları (vuln_id en başta)
    cols = [
        "baseline_rank",
        "vuln_id",
        "cve_id",
        "name",
        "cwe_id",
        "baseline_score"
    ]

    # Çıktı klasörünü oluştur ve kaydet
    output_dir = os.path.dirname(args.out)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    df[cols].to_csv(
        args.out,
        index=False,
        encoding="utf-8"
    )

    print(f"{len(df)} zafiyet sıralandı -> {args.out}")
    print(df[cols].head(10).to_string(index=False))


if __name__ == "__main__":
    main()
