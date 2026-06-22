# JumpBox Güvenlik Sertleştirme Kontrol Listesi

Bu doküman, JumpBox'ı üretimde güvenli biçimde konumlandırmak için adımları içerir.

## 1. İşletim sistemi SSH'ı (OpenSSH) ile çakışmayı önle

JumpBox kendi SSH sunucusunu **22**'de çalıştırır. Sistemin OpenSSH'ını yönetici
erişimi için başka bir porta taşıyın:

```sh
# /etc/ssh/sshd_config
Port 2022
PermitRootLogin no
PasswordAuthentication no          # yönetici erişimi anahtar tabanlı olsun
AllowUsers yonetici break-glass    # yalnızca belirli hesaplar
AllowAgentForwarding no
```

```sh
systemctl restart ssh   # veya sshd
```

> Not: Önce 2022 portuyla erişebildiğinizi doğrulayın, sonra JumpBox'ı 22'ye alın.

## 2. Kullanıcı, dizinler ve ana anahtar

```sh
useradd --system --home /var/lib/jumpbox --shell /usr/sbin/nologin jumpbox
mkdir -p /etc/jumpbox /var/lib/jumpbox /var/log/jumpbox
chown -R jumpbox:jumpbox /var/lib/jumpbox /var/log/jumpbox
chown -R root:jumpbox /etc/jumpbox && chmod 750 /etc/jumpbox

# AES-256 ana anahtarı (32 bayt, 0600).
sudo -u jumpbox /usr/local/bin/jumpbox -config /etc/jumpbox/config.yaml genkey
chmod 600 /etc/jumpbox/master.key
```

## 3. Kontrol listesi

- [x] **Parolalar bcrypt** ile saklanır (maliyet >= 12).
- [x] **SSH özel anahtarları AES-256-GCM** ile şifreli (rest); ana anahtar 0600.
- [x] **TOTP zorunlu**; devre dışı bırakılamaz, ilk girişte QR ile kurulum.
- [x] **IP whitelist** kullanıcı başına (IP + CIDR). Liste boşsa kısıtlama yok —
      hassas hesaplar için mutlaka `jumpbox allow-ip <kullanıcı> <cidr>` ekleyin.
- [x] **Rate limit / geçici ban**: 5 başarısız denemeden sonra 15 dk (DB kalıcı).
- [x] **Root login yasak** (JumpBox'a `root` kullanıcı adıyla giriş reddedilir).
- [x] **Agent forwarding kapalı** ve **port yönlendirme kapalı** (yalnızca interaktif
      session kanalı; `exec`/`subsystem`/`direct-tcpip` reddedilir).
- [x] **Tam JSON denetim logu** (login, IP, sunucu bağlantısı, oturum başlangıç/bitiş).
- [x] **Uzak host anahtarı TOFU** doğrulaması (fingerprint değişimi = bağlantı reddi).
- [x] Servis **root olmayan** `jumpbox` kullanıcısıyla, sıkı systemd sandbox'ı ile çalışır.
- [ ] (Sonraki faz) **Fail2Ban** entegrasyonu — `audit.log` içindeki `LOGIN_FAIL`/
      `LOGIN_BANNED` satırlarını izleyen bir filtre.
- [ ] (Sonraki faz) **Oturum kaydı** (asciinema), RBAC, LDAP, uyarılar.

## 4. Fail2Ban (opsiyonel) için örnek filtre fikri

`audit.log` NDJSON satırlarında `"action":"LOGIN_FAIL"` ve `"ip":"..."` alanlarını
yakalayan bir `failregex` yazılabilir. Bu, dahili rate-limit'e ek bir ağ-seviyesi
katmandır.

## 5. Yedekleme

- `/etc/jumpbox/master.key` **kritik** — bu anahtar olmadan saklı SSH anahtarları
  çözülemez. Güvenli (offline) bir yerde yedekleyin.
- `/var/lib/jumpbox/jumpbox.db` düzenli yedeklenmeli (kullanıcılar, sunucular, anahtarlar).
