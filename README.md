# JumpBox — Hafif SSH Bastion 

Tüm sunucu erişiminiz için **tek giriş noktası** olan; Go ile yazılmış, tek binary,
terminal-öncelikli bir SSH JumpBox (bastion). Teleport'un hafif, kendi-barındırılan
ve **web yerine terminal** odaklı bir alternatifi gibi davranır.

Kullanıcılar tek bir sunucuya `ssh kullanıcı@jumpbox` ile bağlanır; **parola + IP +
TOTP** ile doğrulanır; ardından klavyeyle yönetilen bir menüden, JumpBox'ın sakladığı
(kullanıcıya asla gösterilmeyen) şifreli SSH anahtarlarıyla hedef sunuculara bağlanır.

> **Dil:** Arayüz çok dillidir. Varsayılan ve öncelikli dil **Türkçe**'dir; kullanıcı
> oturum içinde **Türkçe ↔ English** geçiş yapabilir ve tercihi kalıcı saklanır.

> **Lisans:** MIT — bkz. [LICENSE.md](LICENSE.md). © 2026 Alptekin Sünnetci.

---

## Özellikler

- 🔐 **Kimlik doğrulama zinciri:** bcrypt parola + kullanıcı bazlı IP/CIDR whitelist + zorunlu TOTP (elle girilen kurulum anahtarı; QR gerektirmez).
- 🧭 **Terminal UI** (Bubble Tea): klavyeyle yönetilen, tamamen SSH üzerinden çalışan panel.
- 🔁 **Şeffaf SSH proxy:** JumpBox → hedef; PTY + interaktif shell, gerçek-zamanlı G/Ç, pencere boyutu iletimi.
- 🗝️ **Anahtar yönetimi:** Özel anahtarlar **AES-256-GCM** ile rest'te şifreli; kullanıcıya hiç gösterilmez.
- 🔑 **Grup tabanlı erişim denetimi (RBAC-lite):** Sunucular **birden çok gruba** atanabilir; kullanıcılara **birden çok grup** erişimi verilebilir. **Admin tüm sunucuları**, admin olmayan **yalnızca izinli gruplarındaki** sunucuları görür/bağlanır.
- 👤 **Giriş sonrası yönetim (admin):** Kullanıcı ekle/sil, IP whitelist, SSH anahtarı üret/sil/görüntüle, grup oluştur/sil, kullanıcı↔grup atama — hepsi menüden.
- 🛡️ **Sertleştirme:** root login yasak, agent/port forwarding kapalı, login rate-limit/geçici ban, uzak host TOFU doğrulaması.
- 📝 **Denetim:** Her olay **JSON (NDJSON)** dosyaya + veritabanına yazılır.
- 📦 **Tek binary:** Saf Go SQLite (`modernc.org/sqlite`), CGO yok, harici servis yok.

> Yol haritası (sonraki fazlar): asciinema oturum kaydı, LDAP/AD, Telegram/Discord uyarıları, komut kısıtlama politikaları, web paneli.

---

## Mimari

```
ssh kullanıcı@jumpbox:22
        │
        ▼
[sshserver]  golang.org/x/crypto/ssh  (host key: ed25519)
        │   KeyboardInteractiveCallback  → MFA zinciri:
        │     1) root reddi  2) IP whitelist  3) bcrypt parola  4) TOTP
        │     (rate-limit/ban; ilk girişte elle TOTP kurulumu)
        ▼  permissions.Extensions ile user_id / dil / admin taşınır
[session]    pty-req + shell  → kanal io.ReadWriteCloser; window-change izlenir
        ▼
[tui]        Bubble Tea menü (TR/EN) — yetkiye göre öğeler
        ▼  "Bağlan" seçilince menü kapanır (erişim sunucu tarafında da doğrulanır)
[proxy]      ssh.Dial(hedef) decrypt edilmiş anahtarla → RequestPty → Shell
        ▼  uzak shell kapanınca menüye dönülür; SESSION_END audit'lenir
```

Yalnızca **interaktif session** kanalı kabul edilir; `exec`, `subsystem`,
`direct-tcpip` ve `auth-agent-req@openssh.com` reddedilir (komut bypass'ı, port ve
agent yönlendirme engellenir).

## Proje yapısı

```
cmd/jumpbox/            # CLI: serve, migrate, genkey, useradd, passwd, keygen, keyimport, allow-ip, list-keys, list-users
internal/config/        # YAML + env yapılandırma (süreler "15m" biçiminde)
internal/model/         # Domain yapıları (User, Server, SSHKey, Group, ...)
internal/db/            # SQLite Store + gömülü migration'lar + repolar
internal/crypto/        # AES-256-GCM vault + ana anahtar yükleme/üretme
internal/keysvc/        # SSH anahtarı üretme/içe aktarma (CLI + TUI ortak)
internal/auth/          # parola, TOTP, IP whitelist, rate-limit, MFA zinciri
internal/sshserver/     # SSH sunucusu, host key, oturum + pencere yönetimi + erişim denetimi
internal/proxy/         # uzak SSH istemci + PTY + akış proxy'si (TOFU host key)
internal/tui/           # Bubble Tea menü, sunucu/anahtar/kullanıcı/grup yönetimi, loglar, dil
internal/audit/         # NDJSON dosya + DB denetim kaydı
internal/i18n/          # mesaj katalogları (locales/tr.json, en.json)
deploy/                 # systemd unit, örnek config, sertleştirme rehberi
```

## Veritabanı şeması (SQLite)

`users` (+`language`, `totp_enrolled`), `allowed_ips`, `ssh_keys`
(`private_key_encrypted` = nonce‖ciphertext), `servers`, `groups`, `user_groups`,
`server_groups` (her ikisi de çoktan-çoğa), `audit_logs`, `login_attempts`,
`known_hosts` (TOFU). DDL: [internal/db/migrations/](internal/db/migrations/).

---

## Derleme

Go **1.25+** gerekir. Tek statik binary:

```sh
CGO_ENABLED=0 go build -o jumpbox ./cmd/jumpbox
```

## Hızlı başlangıç (yerel deneme)

```sh
export JUMPBOX_DB=./data/jb.db JUMPBOX_MASTER_KEY=./data/master.key \
       JUMPBOX_HOST_KEY=./data/host_ed25519 JUMPBOX_AUDIT_LOG=./data/audit.log \
       JUMPBOX_ADDR=127.0.0.1:2200

./jumpbox genkey                      # AES-256 ana anahtarı üret
./jumpbox migrate                     # şema
./jumpbox useradd -admin alptekin     # parola sorar + TOTP kurulum anahtarını yazdırır
./jumpbox serve

# Başka bir terminalde:
ssh -p 2200 alptekin@127.0.0.1        # parola + TOTP → menü
```

İlk girişte ekranda gösterilen **kurulum anahtarını** Google Authenticator / Authy'de
"Kurulum anahtarı gir" ile ekleyin (QR yoktur).

## CLI komutları

| Komut | Açıklama |
|---|---|
| `serve` | SSH sunucusunu başlat (varsayılan) |
| `migrate` | Veritabanı şemasını uygula |
| `genkey` | AES-256 ana anahtarını üret |
| `useradd [-admin] <kullanıcı>` | Kullanıcı oluştur (parola + TOTP) |
| `passwd <kullanıcı>` | Parola değiştir |
| `keygen <ad>` | Yeni SSH anahtar çifti üret (şifreli sakla) |
| `keyimport <ad> <dosya>` | Mevcut özel anahtarı içe aktar |
| `allow-ip <kullanıcı> <ip\|cidr>` | İzinli IP/CIDR ekle |
| `list-keys` / `list-users` | Listele |

> Çoğu yönetim işi giriş sonrası **TUI menüsünden** de yapılabilir (admin).

## Menü (giriş sonrası)

- **Herkes:** Sunucuları Listele · Sunucuya Bağlan · Loglar · Dil · Çıkış
- **Yalnızca admin:** Sunucu Ekle/Düzenle/Sil · SSH Anahtarları · Kullanıcılar · Gruplar

Yönetim ekranları:
- **SSH Anahtarları:** `n` üret · `v` açık anahtarı göster · `d` sil
- **Kullanıcılar:** `n` ekle · `d` sil · `i` izinli IP'leri yönet · `g` grup erişimi (Boşluk ile aç/kapa)
- **Gruplar:** `n` oluştur · `d` sil

## Grup tabanlı erişim — örnek akış (admin)

1. **Gruplar → `n`** → grup oluştur (örn. `prod`).
2. **Sunucu Ekle/Düzenle** → "Gruplar" alanına virgülle yaz (örn. `prod, dev`).
3. **Kullanıcılar → kullanıcıyı seç → `g`** → ilgili grupları **Boşluk** ile işaretle.
4. O kullanıcı SSH ile girince menüde yalnızca izinli gruplarındaki sunucuları görür/bağlanır.

> Bir sunucu birden çok gruba, bir kullanıcı birden çok gruba atanabilir; erişim için
> **en az bir ortak grup** yeterlidir. Hiçbir gruba ait olmayan sunucular yalnızca
> admin'e görünür. Değişiklikler, kullanıcı **Listele/Bağlan** menüsüne tekrar girdiğinde
> (veya yeniden bağlandığında) yansır.

## Hedef sunucuya bağlanma (anahtar kurulumu)

JumpBox hedefe yalnızca anahtarla bağlanır ve hedefe anahtarı kendiliğinden ekleyemez:

1. **SSH Anahtarları → `n`** (veya CLI `keygen`) ile anahtar üret; özel kısım şifreli saklanır.
2. **`v`** (veya CLI `list-keys`) ile **açık anahtarı** kopyala.
3. Bu açık anahtarı hedef sunucuda ilgili kullanıcının `~/.ssh/authorized_keys` dosyasına ekle.
4. **Sunucu Ekle/Düzenle**'de "SSH Anahtarı" alanına anahtarın adını yaz.

İlk bağlantıda hedefin host anahtarı TOFU ile kaydedilir; sonradan değişirse (olası MITM) bağlantı reddedilir.

---

## Üretim dağıtımı

Adımların tamamı için [deploy/HARDENING.md](deploy/HARDENING.md):

1. Binary'yi `/usr/local/bin/jumpbox` olarak kurun.
2. `jumpbox` sistem kullanıcısı + `/etc/jumpbox`, `/var/lib/jumpbox`, `/var/log/jumpbox` dizinleri.
3. `jumpbox genkey` → `/etc/jumpbox/master.key` (0600).
4. `jumpbox useradd -admin <kullanıcı>` → TOTP kurulum anahtarını uygulamaya ekleyin.
5. OS sshd'yi **2022**'ye taşıyın (`PermitRootLogin no`).
6. [deploy/jumpbox.service](deploy/jumpbox.service) → `systemctl enable --now jumpbox`.

## Güvenlik notları

- **Ana anahtar (`master.key`) olmadan** saklı SSH anahtarları çözülemez — güvenli yedekleyin.
- IP whitelist boşsa o kullanıcı için **kısıtlama yoktur**; hassas hesaplara mutlaka `allow-ip` ekleyin.
- Tüm başarısız/başarılı girişler, sunucu bağlantıları ve yönetim işlemleri `audit.log`'a NDJSON olarak yazılır:

```json
{"user":"alptekin","action":"CONNECT_SERVER","server":"web-01","ip":"1.2.3.4","detail":"10.0.0.1:22","time":"2026-06-22T20:10:00Z"}
```

## Testler

```sh
go test ./...
```

Kapsam: kripto round-trip, bcrypt/TOTP, IP/CIDR, rate-limit/ban, i18n anahtar paritesi,
DB repoları, **grup tabanlı erişim**, TUI kullanıcı↔grup atama akışı ve **uçtan uca SSH
entegrasyonu** (parola+TOTP girişi → menü → yetki gating → yanlış kimlik/root reddi).

---

## English (summary)

A lightweight, single-binary SSH bastion in Go. Users SSH into one host, authenticate
with **password + IP allowlist + mandatory TOTP**, then use a keyboard-driven Bubble Tea
menu to connect to target servers through JumpBox-managed, AES-256-GCM–encrypted keys.

It includes **group-based access control (RBAC-lite)**: servers and users can each belong
to multiple groups, and a non-admin user only sees/connects to servers that share at least
one group with them; admins see everything. Admins manage users, SSH keys, per-user IP
allowlists, and groups directly from the terminal UI.

The UI is **multilingual with Turkish as the default**; switch to English in-session via
the **Language / Dil** menu. Storage is embedded SQLite (pure Go, no CGO). See
[deploy/HARDENING.md](deploy/HARDENING.md) for production hardening.

## License

MIT © 2026 Alptekin Sünnetci — see [LICENSE.md](LICENSE.md).
