// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package config, JumpBox'ın çalışma zamanı yapılandırmasını yükler.
// Varsayılanlar Linux üretim ortamına göredir; YAML dosyası ve ortam
// değişkenleri (env) ile üzerine yazılabilir.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration, YAML'de "15m", "30s" gibi insan-okur süreleri çözebilen bir
// time.Duration sarmalayıcısıdır. Sayı verilirse saniye kabul edilir.
type Duration time.Duration

// Std, standart time.Duration değerini döndürür.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalYAML, "15m" gibi bir dizgeyi ya da saniye cinsinden bir sayıyı çözer.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("geçersiz süre %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var secs int64
	if err := value.Decode(&secs); err == nil {
		*d = Duration(time.Duration(secs) * time.Second)
		return nil
	}
	return fmt.Errorf("geçersiz süre değeri")
}

// Config, tüm bileşenlerin paylaştığı ayar kümesidir.
type Config struct {
	// Addr, SSH sunucusunun dinleyeceği adrestir (örn. ":22").
	Addr string `yaml:"addr"`
	// DBPath, SQLite veritabanı dosyasının yoludur.
	DBPath string `yaml:"db_path"`
	// MasterKeyPath, AES-256 ana anahtarının (32 ham bayt) yoludur.
	MasterKeyPath string `yaml:"master_key_path"`
	// HostKeyPath, JumpBox SSH host anahtarının (ed25519) yoludur.
	HostKeyPath string `yaml:"host_key_path"`
	// AuditLogPath, JSON denetim loglarının yazılacağı dosyadır.
	AuditLogPath string `yaml:"audit_log_path"`
	// DefaultLang, kimlik doğrulanmadan önce kullanılacak dildir (tr|en).
	DefaultLang string `yaml:"default_lang"`
	// BcryptCost, parola hash maliyetidir.
	BcryptCost int `yaml:"bcrypt_cost"`
	// TOTPIssuer, Google Authenticator'da görünecek hesap sağlayıcı adıdır.
	TOTPIssuer string `yaml:"totp_issuer"`
	// Ban, login deneme sınırlaması ayarlarıdır.
	Ban BanConfig `yaml:"ban"`
}

// BanConfig, kaba kuvvet (brute-force) korumasını tanımlar.
type BanConfig struct {
	// Threshold, geçici bana yol açan başarısız deneme sayısıdır.
	Threshold int `yaml:"threshold"`
	// Window, başarısız denemelerin sayıldığı (ve banın sürdüğü) süredir
	// (örn. "15m").
	Window Duration `yaml:"window"`
}

// Default, güvenli üretim varsayılanlarını döndürür.
func Default() Config {
	return Config{
		Addr:          ":22",
		DBPath:        "/var/lib/jumpbox/jumpbox.db",
		MasterKeyPath: "/etc/jumpbox/master.key",
		HostKeyPath:   "/etc/jumpbox/host_ed25519",
		AuditLogPath:  "/var/log/jumpbox/audit.log",
		DefaultLang:   "tr",
		BcryptCost:    12,
		TOTPIssuer:    "JumpBox",
		Ban: BanConfig{
			Threshold: 5,
			Window:    Duration(15 * time.Minute),
		},
	}
}

// Load, verilen YAML dosyasını varsayılanların üzerine uygular. Dosya yoksa
// yalnızca varsayılanlar (ve env override'ları) döner; bu bir hata değildir.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return cfg, err
			}
		} else if !os.IsNotExist(err) {
			return cfg, err
		}
	}
	cfg.applyEnv()
	return cfg, nil
}

// applyEnv, JUMPBOX_* ortam değişkenleriyle ayarları geçersiz kılar.
func (c *Config) applyEnv() {
	if v := os.Getenv("JUMPBOX_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("JUMPBOX_DB"); v != "" {
		c.DBPath = v
	}
	if v := os.Getenv("JUMPBOX_MASTER_KEY"); v != "" {
		c.MasterKeyPath = v
	}
	if v := os.Getenv("JUMPBOX_HOST_KEY"); v != "" {
		c.HostKeyPath = v
	}
	if v := os.Getenv("JUMPBOX_AUDIT_LOG"); v != "" {
		c.AuditLogPath = v
	}
	if v := os.Getenv("JUMPBOX_LANG"); v != "" {
		c.DefaultLang = v
	}
}
