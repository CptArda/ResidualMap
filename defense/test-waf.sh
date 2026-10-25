#!/usr/bin/env bash
# Kendi lab ortamımıza (localhost:8080) basit WAF doğrulama istekleri gönderir.
# DetectionOnly'de hepsi 200 döner; ama audit.log'a kayıt düşmelidir.
# Engelleme moduna (On) geçince saldırı örnekleri 403 dönmelidir.
BASE="${1:-http://localhost:8080}"

req() {  # etiket, curl argümanları...
  local label="$1"; shift
  code=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  printf '%-22s -> HTTP %s\n' "$label" "$code"
}

echo "== Normal trafik =="
req "ana sayfa"          "$BASE/"
req "ürün listesi"       "$BASE/rest/products/search?q=apple"

echo "== Test payload'ları (kendi lab'ımız) =="
req "SQLi"               -G "$BASE/rest/products/search" --data-urlencode "q=' OR 1=1--"
req "XSS"                -G "$BASE/rest/products/search" --data-urlencode "q=<script>alert(1)</script>"
req "Path traversal"     "$BASE/?file=../../../../etc/passwd"
req "Scanner UA"         -A "sqlmap/1.7" "$BASE/"
