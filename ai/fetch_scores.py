import json
import time
import requests
import os
from dotenv import load_dotenv
load_dotenv()

INPUT_TRIVY = "../inventory/raw/trivy.json"
OUTPUT_CSV = "cvss_epss_scores.csv"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_API_KEY = os.getenv("API_KEY")

def get_cve_ids():
    with open(INPUT_TRIVY, encoding="utf-8") as f:
        data = json.load(f)
    cve_ids = set()
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            cve_ids.add(v["VulnerabilityID"])
    return sorted(cve_ids)


def get_cvss_from_nvd(cve_id):
    try:
        headers = {"apiKey": NVD_API_KEY}
        resp = requests.get(NVD_API,params={"cveId": cve_id},headers=headers,timeout=15)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, None
        metrics = vulns[0]["cve"].get("metrics", {})
        # Önce v3.1, yoksa v3.0, yoksa v2 dene
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                return m.get("baseScore"), m.get("vectorString")
        return None, None
    except Exception as e:
        print(f"  NVD hata ({cve_id}): {e}")
        return None, None


def get_epss(cve_id):
    try:
        resp = requests.get(EPSS_API, params={"cve": cve_id}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("data", [])
        if results:
            return float(results[0]["epss"])
        return None
    except Exception as e:
        print(f"  EPSS hata ({cve_id}): {e}")
        return None


def main():
    cve_ids = get_cve_ids()
    print(f"{len(cve_ids)} CVE sorgulanacak...\n")

    rows = []
    for i, cve_id in enumerate(cve_ids, 1):
        print(f"[{i}/{len(cve_ids)}] {cve_id}")
        cvss_score, cvss_vector = get_cvss_from_nvd(cve_id)
        epss_score = get_epss(cve_id)
        rows.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
        })
        time.sleep(0.6)  # NVD API rate limit'e takılmamak için bekleme

    with open(OUTPUT_CSV, "w", encoding="utf-8") as f:
        f.write("cve_id,cvss_score,cvss_vector,epss_score\n")
        for r in rows:
            f.write(f'{r["cve_id"]},{r["cvss_score"]},"{r["cvss_vector"]}",{r["epss_score"]}\n')

    print(f"\nTamamlandı. Sonuç: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()