# SIEM için Log Kaynakları

## Şu an mevcut
- **nginx access log** (`defense/logs/access.log`) — her HTTP isteğinin
kaynak IP, zaman, yöntem, yol, durum kodu bilgisi

## İleride eklenecek (Hafta 4-8 arası kurulumla birlikte)
- **nginx error log** — nginx'in kendi hata kayıtları
- **ModSecurity (WAF) log** — Hafta 4-5'te kurulduğunda, engellenen/
şüpheli isteklerin kaydı
- **Suricata (IDS/IPS) log** — Hafta 6'da kurulduğunda, ağ seviyesinde
tespit edilen saldırı paternleri
- **Juice Shop uygulama logu** (varsa) — başarısız giriş denemeleri gibi
uygulama seviyesi olaylar

## SIEM'e bağlanma planı (Hafta 8)
Yukarıdaki log dosyaları Wazuh/Elastic agent'ı ile okunup merkezi panoya
aktarılacak. Öncelik: nginx access log + ModSecurity log (saldırı
denemelerini doğrudan gösterirler).