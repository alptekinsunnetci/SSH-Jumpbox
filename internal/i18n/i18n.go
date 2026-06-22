// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

// Package i18n, çok dilli mesaj kataloglarını yönetir. Varsayılan ve kaynak dil
// Türkçe'dir (tr); eksik çeviriler Türkçe'ye, o da yoksa anahtarın kendisine düşer.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed locales/*.json
var localeFS embed.FS

// Default, varsayılan ve kaynak dildir.
const Default = "tr"

var catalogs = map[string]map[string]string{}

func init() {
	entries, err := localeFS.ReadDir("locales")
	if err != nil {
		panic("i18n: locales klasörü okunamadı: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := localeFS.ReadFile("locales/" + e.Name())
		if err != nil {
			panic("i18n: " + e.Name() + " okunamadı: " + err.Error())
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			panic("i18n: " + e.Name() + " ayrıştırılamadı: " + err.Error())
		}
		catalogs[strings.TrimSuffix(e.Name(), ".json")] = m
	}
}

// Normalize, desteklenmeyen/boş bir dil kodunu varsayılana indirger.
func Normalize(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if _, ok := catalogs[lang]; ok {
		return lang
	}
	return Default
}

// Available, kullanıcıya sunulacak dilleri öngörülebilir sırada döndürür
// (Türkçe önce gelir).
func Available() []string {
	return []string{"tr", "en"}
}

// T, verilen dilde anahtarın çevirisini döndürür. args verilirse fmt.Sprintf uygulanır.
func T(lang, key string, args ...any) string {
	s, ok := lookup(lang, key)
	if !ok {
		s, ok = lookup(Default, key)
	}
	if !ok {
		s = key
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

func lookup(lang, key string) (string, bool) {
	m, ok := catalogs[lang]
	if !ok {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}

// Keys, bir dilin tanımladığı tüm anahtarları döndürür (testler için).
func Keys(lang string) []string {
	m := catalogs[lang]
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
