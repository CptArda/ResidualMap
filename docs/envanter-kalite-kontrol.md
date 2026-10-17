# Envanter Kalite Kontrol Notu — Hafta 4

## Kontrol edilen dosyalar
- inventory/raw/zap_baseline.json
- inventory/raw/trivy.json
- ai/cvss_epss_scores.csv
- inventory/cwe_mapping.csv

## Bulgular
- Toplam CVE: 159 (Trivy, CRITICAL+HIGH öncelikli)
- Tekrar eden CVE: yok
- CVSS skoru eksik olan: 15 kayıt (NVD'de bulunamadı)
- EPSS skoru eksik olan: 6 kayıt
- ZAP bulguları: 12 tür, 41 örnek, 9'unda CWE hazır geldi

## Alınan aksiyon
- Eksik CVSS/EPSS'li kayıtlar envanterde "bilinmiyor" olarak işaretlenecek,
  silinmeyecek.
- İsimlendirme K2/K3 ile [tarih]'te konuşuldu, [sonuç].