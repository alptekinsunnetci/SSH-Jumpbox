// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword, parolayı verilen maliyetle bcrypt ile hashler.
func HashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(b), err
}

// VerifyPassword, parolayı saklı hash ile karşılaştırır.
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
