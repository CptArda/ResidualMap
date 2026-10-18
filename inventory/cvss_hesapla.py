"""CVSS Base Score hesaplayici.

Kullanim:
  python cvss_hesapla.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  python cvss_hesapla.py inventory/inventory.csv --vektor-sutunu cvss_vector --skor-sutunu cvss_score
"""
import argparse
import csv
import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x):
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def skor(vektor):
    parcalar = dict(p.split(":") for p in vektor.strip().split("/")[1:])
    degisti = parcalar["S"] == "C"
    pr = (PR_C if degisti else PR_U)[parcalar["PR"]]
    iss = 1 - (1 - CIA[parcalar["C"]]) * (1 - CIA[parcalar["I"]]) * (1 - CIA[parcalar["A"]])
    if degisti:
        etki = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        etki = 6.42 * iss
    saldirilabilirlik = 8.22 * AV[parcalar["AV"]] * AC[parcalar["AC"]] * pr * UI[parcalar["UI"]]
    if etki <= 0:
        return 0.0
    toplam = etki + saldirilabilirlik
    return roundup(min((1.08 if degisti else 1.0) * toplam, 10))


def siddet(s):
    if s == 0:
        return "None"
    if s < 4:
        return "Low"
    if s < 7:
        return "Medium"
    if s < 9:
        return "High"
    return "Critical"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("girdi", help="CVSS vektoru ya da CSV dosyasi yolu")
    ap.add_argument("--vektor-sutunu", default="cvss_vector")
    ap.add_argument("--skor-sutunu", default="cvss_score")
    a = ap.parse_args()

    if not a.girdi.lower().endswith(".csv"):
        s = skor(a.girdi)
        print(s, siddet(s))
    else:
        with open(a.girdi, newline="", encoding="utf-8") as f:
            for i, satir in enumerate(csv.DictReader(f), start=2):
                v = (satir.get(a.vektor_sutunu) or "").strip()
                if not v:
                    print(f"satir {i}: vektor yok")
                    continue
                hesap = skor(v)
                yazili = (satir.get(a.skor_sutunu) or "").strip()
                durum = "OK" if yazili and abs(float(yazili) - hesap) < 0.05 else "FARKLI/BOS"
                print(f"satir {i}: hesaplanan={hesap} ({siddet(hesap)}) yazili={yazili or '-'} -> {durum}")
