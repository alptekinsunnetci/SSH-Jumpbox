// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret, bir kullanıcı için yeni bir TOTP gizli anahtarı üretir.
func GenerateTOTPSecret(issuer, account string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
}

// ValidateTOTP, 6 haneli kodu gizli anahtara göre doğrular.
func ValidateTOTP(code, secret string) bool {
	return totp.Validate(code, secret)
}
