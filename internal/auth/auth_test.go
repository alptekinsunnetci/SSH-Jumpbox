// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-parola", 4) // hızlı test için düşük maliyet
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "s3cret-parola") {
		t.Fatal("doğru parola doğrulanmadı")
	}
	if VerifyPassword(hash, "yanlis") {
		t.Fatal("yanlış parola kabul edildi")
	}
}

func TestTOTPGenerateValidate(t *testing.T) {
	key, err := GenerateTOTPSecret("JumpBox", "alice")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(code, key.Secret()) {
		t.Fatal("geçerli TOTP kodu doğrulanmadı")
	}
	if ValidateTOTP("123456", key.Secret()) && ValidateTOTP("000000", key.Secret()) {
		t.Fatal("rastgele kodlar geçerli görünmemeli")
	}
}

func TestCheckIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		allowed []string
		want    bool
	}{
		{"boş liste = kısıtlama yok", "10.0.0.5", nil, true},
		{"tam eşleşme", "1.2.3.4", []string{"1.2.3.4"}, true},
		{"eşleşmeme", "1.2.3.5", []string{"1.2.3.4"}, false},
		{"CIDR içinde", "192.168.1.50", []string{"192.168.1.0/24"}, true},
		{"CIDR dışında", "192.168.2.50", []string{"192.168.1.0/24"}, false},
		{"birden çok kural", "10.0.0.1", []string{"1.2.3.4", "10.0.0.0/8"}, true},
		{"geçersiz IP", "abc", []string{"1.2.3.4"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckIP(c.ip, c.allowed); got != c.want {
				t.Fatalf("CheckIP(%q,%v)=%v, beklenen %v", c.ip, c.allowed, got, c.want)
			}
		})
	}
}

func TestHostFromAddr(t *testing.T) {
	if got := HostFromAddr("1.2.3.4:5678"); got != "1.2.3.4" {
		t.Fatalf("HostFromAddr=%q", got)
	}
	if got := HostFromAddr("notanaddr"); got != "notanaddr" {
		t.Fatalf("HostFromAddr fallback=%q", got)
	}
}
