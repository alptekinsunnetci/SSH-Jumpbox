// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package i18n

import (
	"sort"
	"strings"
	"testing"
)

// TestLocaleParity, tüm dillerin aynı anahtar kümesine sahip olmasını ve format
// belirteçlerinin (%) sayısının eşleşmesini doğrular. Böylece eksik/uyumsuz
// çeviriler derleme/test aşamasında yakalanır.
func TestLocaleParity(t *testing.T) {
	ref := Default
	refKeys := keySet(ref)
	if len(refKeys) == 0 {
		t.Fatalf("%q kataloğu boş", ref)
	}

	for _, lang := range Available() {
		keys := keySet(lang)
		for k := range refKeys {
			if _, ok := keys[k]; !ok {
				t.Errorf("[%s] eksik anahtar: %s", lang, k)
			}
		}
		for k := range keys {
			if _, ok := refKeys[k]; !ok {
				t.Errorf("[%s] fazladan anahtar (referansta yok): %s", lang, k)
			}
		}
		// Format belirteçlerinin sayısı eşleşmeli.
		for k := range refKeys {
			refN := strings.Count(T(ref, k), "%")
			gotN := strings.Count(T(lang, k), "%")
			if refN != gotN {
				t.Errorf("[%s] %q için %% sayısı uyuşmuyor: ref=%d got=%d", lang, k, refN, gotN)
			}
		}
	}
}

func TestTFallback(t *testing.T) {
	// Var olmayan anahtar kendisini döndürür.
	if got := T("tr", "yok.boyle.anahtar"); got != "yok.boyle.anahtar" {
		t.Fatalf("fallback başarısız: %q", got)
	}
	// Argümanlı format.
	got := T("tr", "app.welcome_user", "ali")
	if !strings.Contains(got, "ali") {
		t.Fatalf("argüman uygulanmadı: %q", got)
	}
}

func TestNormalize(t *testing.T) {
	if Normalize("EN") != "en" {
		t.Fatal("EN -> en olmalı")
	}
	if Normalize("xx") != Default {
		t.Fatal("bilinmeyen dil varsayılana düşmeli")
	}
	if Normalize("") != Default {
		t.Fatal("boş dil varsayılana düşmeli")
	}
}

func keySet(lang string) map[string]struct{} {
	keys := Keys(lang)
	sort.Strings(keys)
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out
}
