# ResidualMap — Kurulum Rehberi (HAFTA2)

## Gereksinimler
- Docker Desktop (20+)
- Git
- Python 3.14

## Kurulum
1. Repoyu klonlayın:
   git clone https://github.com/<kullanici>/residualmap.git
   cd residualmap

2. Juice Shop'u çalıştırın:
   docker run -d -p 3000:3000 bkimminich/juice-shop

3. Tarayıcıda açın: http://localhost:3000

## Doğrulama
- Ana sayfa açılıyor mu?
- "Account" menüsünden kayıt olabiliyor musunuz?

## Sorun Giderme
- Port 3000 doluysa: docker run -d -p 3001:3000 bkimminich/juice-shop