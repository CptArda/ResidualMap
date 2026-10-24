# En Kritik 10 Zafiyet (Envanter v1.0)

Kaynak: `inventory/inventory_v1.0.csv` (36 kayıt). Sıralama ölçütü: CVSS v3.1 skoru, eşitlikte varlık kritikliği (`asset_criticality`), sonra EPSS.

| # | ID | Zafiyet | CVE | CVSS | EPSS | Kritiklik |
|---|---|---|---|---|---|---|
| 1 | V022 | jsonwebtoken 0.1.0 / 0.4.0 - CVE-2015-9235 | CVE-2015-9235 | 9.8 | 0.08524 | 5 |
| 2 | V001 | SQL Injection - login formu (Login Admin) | - | 9.8 | bilinmiyor | 5 |
| 3 | V008 | Mass Assignment - admin kaydi (Admin Registration) | - | 9.8 | bilinmiyor | 5 |
| 4 | V025 | crypto-js 3.3.0 - CVE-2023-46233 | CVE-2023-46233 | 9.1 | 0.00635 | 4 |
| 5 | V023 | lodash 2.4.2 - CVE-2019-10744 | CVE-2019-10744 | 9.1 | 0.05006 | 3 |
| 6 | V027 | decompress 4.2.1 - CVE-2026-101894 | CVE-2026-101894 | 9.1 | 0.00814 | 3 |
| 7 | V028 | proxy-addr 2.0.7 - CVE-2026-90711 | CVE-2026-90711 | 9.1 | 0.00332 | 3 |
| 8 | V026 | crypto-js 3.3.0 - CVE-2026-71851 | CVE-2026-71851 | 9.0 | 0.0055 | 4 |
| 9 | V029 | tar 6.2.1 - CVE-2026-23950 | CVE-2026-23950 | 8.8 | 0.00257 | 3 |
| 10 | V015 | Zayif admin parolasi - brute force (Password Strength) | - | 8.1 | bilinmiyor | 5 |

## Neden bu sıralama?

1. **jsonwebtoken 0.1.0 / 0.4.0 - CVE-2015-9235** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H): JWT algoritma karışıklığı ile token sahteciliği; kimlik doğrulama tamamen atlatılabilir. Düzeltme: jsonwebtoken 4.2.2+.
2. **SQL Injection - login formu (Login Admin)** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H): Kimlik doğrulamasız SQL injection ile admin girişi; veritabanı üzerinde tam kontrol.
3. **Mass Assignment - admin kaydi (Admin Registration)** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H): Kayıt sırasında rol alanı manipüle edilerek admin hesabı açılabiliyor (mass assignment).
4. **crypto-js 3.3.0 - CVE-2023-46233** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N): crypto-js 3.3.0'daki zayıf PBKDF2 varsayılanları, parola türevlerinin kırılmasını kolaylaştırır. Düzeltme: 4.2.0.
5. **lodash 2.4.2 - CVE-2019-10744** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H): lodash prototype pollution; uygulama mantığını bozabilir. Düzeltme: 4.17.12+.
6. **decompress 4.2.1 - CVE-2026-101894** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N): decompress path traversal; dosya sisteminde istenmeyen yere yazma/okuma. Resmi düzeltme yok.
7. **proxy-addr 2.0.7 - CVE-2026-90711** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N): proxy-addr güven zinciri hatası; istemci IP'si taklit edilebilir (log ve erişim kontrolü etkilenir). Düzeltme: 2.0.8.
8. **crypto-js 3.3.0 - CVE-2026-71851** (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H): crypto-js'te zayıf rastgelelik; üretilen anahtar ve tokenlar tahmin edilebilir. Düzeltme: 4.0.0.
9. **tar 6.2.1 - CVE-2026-23950** (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L): tar paketinde Unicode normalizasyon hatası; kullanıcı etkileşimiyle dosya üzerine yazma. Düzeltme: 7.5.4.
10. **Zayif admin parolasi - brute force (Password Strength)** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H): Admin parolası zayıf; brute force ile ele geçirilebilir. (Vektör ekip tahmini, kesin değil.)

## Not

- İki libc6 kaydı (CVE-2026-5450, CVE-2019-1010022) CVSS 9.8 olmasına rağmen listeye alınmadı: Trivy bunları MEDIUM/LOW işaretliyor ve skor tutarsız/tartışmalı. Envanterde `[EMIN DEGIL]` olarak duruyor.
- Juice Shop zafiyetlerinin (V001, V008, V015) CVSS vektörleri resmi değil, ekip tahminidir; EPSS değerleri yoktur ("bilinmiyor").
