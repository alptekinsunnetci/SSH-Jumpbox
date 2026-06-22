// Copyright (c) 2026 Alptekin Sünnetci
// SPDX-License-Identifier: MIT

package sshserver

import "sync"

// winState, bir oturumun terminal boyutunu (ve term tipini) izler ve boyut
// değişikliklerini aboneye (menü ya da proxy) iletir.
// Konvansiyon: w = sütun (cols), h = satır (rows).
type winState struct {
	mu   sync.Mutex
	w, h int
	term string
	sub  func(w, h int)
}

func (s *winState) set(w, h int) {
	s.mu.Lock()
	if w > 0 {
		s.w = w
	}
	if h > 0 {
		s.h = h
	}
	sub := s.sub
	cw, ch := s.w, s.h
	s.mu.Unlock()
	if sub != nil {
		sub(cw, ch)
	}
}

func (s *winState) setTerm(t string) {
	if t == "" {
		return
	}
	s.mu.Lock()
	s.term = t
	s.mu.Unlock()
}

func (s *winState) get() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w, s.h
}

func (s *winState) getTerm() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.term
}

// Subscribe, tui.Winsizer ve proxy.WinSource arayüzlerini karşılar. Abonelik
// kurulduğunda mevcut boyut hemen bir kez iletilir.
func (s *winState) Subscribe(f func(w, h int)) {
	s.mu.Lock()
	s.sub = f
	cw, ch := s.w, s.h
	s.mu.Unlock()
	if f != nil {
		f(cw, ch)
	}
}
