// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import "time"

// limiterStore, rate limiter'ın ihtiyaç duyduğu veritabanı işlemleridir.
type limiterStore interface {
	CountRecentFailures(username, ip string, since time.Time) (int, error)
	RecordAttempt(username, ip string, success bool) error
	ClearFailures(username, ip string) error
}

// Limiter, (kullanıcı, IP) başına başarısız giriş denemelerini sınırlar.
// Belirli bir pencere içinde eşik aşılırsa, pencere boyunca giriş reddedilir
// (geçici ban).
type Limiter struct {
	store     limiterStore
	threshold int
	window    time.Duration
}

// NewLimiter, yeni bir rate limiter oluşturur.
func NewLimiter(store limiterStore, threshold int, window time.Duration) *Limiter {
	if threshold <= 0 {
		threshold = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &Limiter{store: store, threshold: threshold, window: window}
}

// Allowed, (kullanıcı, IP) için yeni bir giriş denemesine izin verilip
// verilmediğini döndürür. Eşik aşıldıysa false döner (banlı).
func (l *Limiter) Allowed(username, ip string) (bool, error) {
	since := time.Now().Add(-l.window)
	n, err := l.store.CountRecentFailures(username, ip, since)
	if err != nil {
		return false, err
	}
	return n < l.threshold, nil
}

// RecordFailure, başarısız bir denemeyi kaydeder.
func (l *Limiter) RecordFailure(username, ip string) {
	_ = l.store.RecordAttempt(username, ip, false)
}

// RecordSuccess, başarılı bir denemeyi kaydeder ve başarısızlık geçmişini temizler.
func (l *Limiter) RecordSuccess(username, ip string) {
	_ = l.store.RecordAttempt(username, ip, true)
	if username != "" {
		_ = l.store.ClearFailures(username, ip)
	}
}
