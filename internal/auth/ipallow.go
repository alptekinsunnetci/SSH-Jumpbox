// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package auth

import (
	"net"
	"strings"
)

// CheckIP, kaynak IP'nin izinli liste tarafından kabul edilip edilmediğini döndürür.
// Liste boşsa kısıtlama yok kabul edilir (true). Girdiler tek IP veya CIDR olabilir.
func CheckIP(remoteIP string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // kısıtlama tanımlanmamış
	}
	ip := net.ParseIP(strings.TrimSpace(remoteIP))
	if ip == nil {
		return false
	}
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
			return true
		}
	}
	return false
}

// HostFromAddr, "ip:port" biçimindeki bir adresten yalnızca IP kısmını çıkarır.
func HostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
