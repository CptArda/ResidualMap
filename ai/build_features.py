import csv

INPUT_CSV = "inventory/inventory_v1.0.csv"
OUTPUT_CSV = "ai/features.csv"


def parse_cvss_vector(vector):
    """CVSS vektör string'inden alt bileşenleri çıkarır."""
    if not vector or vector in ("None", ""):
        return {}
    parts = vector.split("/")
    result = {}
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            result[key] = value
    return result


def to_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def main():
    with open(INPUT_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    features = []
    for r in rows:
        vector_parts = parse_cvss_vector(r.get("cvss_vector", ""))

        cvss_score = to_float(r.get("cvss_score"))
        epss_score = to_float(r.get("epss_score"))

        attack_vector = vector_parts.get("AV", "Unknown")        # N/A/L/P
        attack_complexity = vector_parts.get("AC", "Unknown")    # L/H
        auth_required = "Hayır" if vector_parts.get("PR") == "N" else "Evet"
        user_interaction = "Hayır" if vector_parts.get("UI") == "N" else "Evet"

        features.append({
   
            "vuln_id": r.get("vuln_id", ""),
            "cve_id": r.get("cve_id", ""),
            "name": r.get("name", ""),
            "cwe_id": r.get("cwe_id", ""),
            "cvss_score": cvss_score if cvss_score is not None else "",
            "epss_score": epss_score if epss_score is not None else "",
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "auth_required": auth_required,
            "user_interaction": user_interaction,
            "asset_criticality": r.get("asset_criticality", ""),
            "exposure": r.get("exposure", ""),
            "has_data": "Evet" if cvss_score is not None else "Hayır",
        })

    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=features[0].keys())
        writer.writeheader()
        writer.writerows(features)

    total = len(features)
    missing = sum(1 for f_ in features if f_["has_data"] == "Hayır")
    print(f"Toplam {total} satır işlendi, {missing} tanesinde CVSS/vektör verisi eksik.")
    print(f"Çıktı: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
