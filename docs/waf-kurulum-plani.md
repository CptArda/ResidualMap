# WAF Kurulum Planı (Hafta 5 için)

## Amaç

Bu belge, Hafta 5'te Juice Shop'un önüne kuracağımız WAF (Web Application Firewall)
katmanının nasıl kurulacağını önceden planlamak için hazırlanmıştır. Bu hafta
(Hafta 4) kod veya config değişikliği yapılmamaktadır — sadece araştırma ve plan.

## Seçilen Yaklaşım

**ModSecurity + OWASP Core Rule Set (CRS)**, nginx üzerinde çalışan bir WAF modülü
olarak kullanılacaktır.

- **ModSecurity**: HTTP isteklerini inceleyen WAF motoru (kuralları kendisi
  içermez, bir kural setine ihtiyaç duyar).
- **OWASP CRS**: SQL injection, XSS, path traversal gibi saldırı paternlerini
  yakalayan hazır, açık kaynak kural paketi.

Kendi nginx image'ımıza ModSecurity modülünü elle derleyip eklemek yerine,
hazır **`owasp/modsecurity-crs:nginx`** Docker image'ı kullanılacaktır. Bu image
nginx + ModSecurity + CRS'i önceden paketlenmiş halde sunar, kurulumu basitleştirir.

## docker-compose.yml Değişikliği (Taslak)

Mevcut `nginx` servisi şu image ile değiştirilecek:

```yaml
nginx:
  image: owaspcrs/modsecurity-crs:nginx-alpine
  container_name: defense-proxy
  ports:
    - "8080:80"
  environment:
    - PARANOIA=1
    - MODE=DetectionOnly
    - BACKEND=http://juice-shop:3000
  depends_on:
    - juice-shop
```

### Önemli Ortam Değişkenleri

| Değişken | Değer (başlangıç) | Açıklama |
|---|---|---|
| `PARANOIA` | `1` | Kural sıkılığı (PL1–PL4). PL1 en gevşek, az yanlış pozitif üretir. |
| `MODE` | `DetectionOnly` | Hafta 5'te sadece tespit/log, engelleme yapmaz. |
| `BACKEND` | `http://juice-shop:3000` | WAF'ın arkasındaki hedef uygulama. |

## Juice Shop'a Yönlendirme

Mevcut `proxy_pass http://juice-shop:3000;` mantığı korunacak, sadece nginx
image'ı WAF'lı sürüme geçecek. Trafiğin akışı değişmeyecek, sadece araya bir
inceleme katmanı eklenecek:

```
Tarayıcı → WAF (ModSecurity + CRS, nginx tabanlı) → Juice Shop
```

## Aşamalı Kurulum Planı

| Hafta | Adım |
|---|---|
| **Hafta 5** | WAF, `DetectionOnly` modunda kurulacak. Hiçbir istek engellenmeyecek, sadece loglanacak. Amaç: normal kullanım sırasında yanlış pozitif üretip üretmediğini görmek. |
| **Hafta 7** | Loglar incelendikten sonra `MODE=Blocking` yapılacak, gerekirse `PARANOIA` seviyesi ayarlanacak (yanlış pozitif çoksa düşürülecek, yetersiz engelleme varsa artırılacak). |

## Ön Deneme (İsteğe Bağlı)

Zaman kalırsa, Hafta 5'i kolaylaştırmak için WAF'ın tek başına (Juice Shop'a
bağlamadan) ayağa kalkıp kalkmadığı test edilebilir:

```bash
docker run --rm -p 8081:8080 -e PARANOIA=1 owaspcrs/modsecurity-crs:nginx-alpine
```

Bu, kalıcı bir değişiklik yapmadan image'ın doğru çalıştığını doğrulamak içindir.

## Riskler ve Dikkat Edilecekler

- **Yanlış pozitif riski**: CRS, bazen normal kullanıcı isteklerini de saldırı
  gibi algılayabilir. Bu yüzden Hafta 5'te önce `DetectionOnly` ile başlanacak.
- **Performans**: WAF, her isteği incelediği için küçük bir gecikme ekler;
  projenin ölçeğinde (tek kullanıcı, test ortamı) önemli bir sorun beklenmiyor.

## Referanslar

- OWASP ModSecurity Core Rule Set: https://owasp.org/www-project-modsecurity-core-rule-set/
- CRS Docker Image (GitHub): https://github.com/coreruleset/modsecurity-crs-docker
- ModSecurity Resmi Belgeleri: https://github.com/owasp-modsecurity/ModSecurity
