package sniper

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type TargetSession struct {
	SessionID    string `json:"session_id"`
	ResumeURL    string `json:"resume_url"`
	Sequence     int    `json:"sequence"`
	MFAToken     string `json:"mfa_token"`
	MFAExpiresAt int64  `json:"mfa_expires_at"`
	LastVanity   string `json:"last_vanity"`
	LastFree     bool   `json:"last_free"`
}

type SessionStore struct {
	mu      sync.RWMutex
	path    string
	Targets map[string]*TargetSession `json:"targets"`
	dirty   bool
	stopCh  chan struct{}
}

func NewSessionStore(path string) *SessionStore {
	return &SessionStore{
		path:    path,
		Targets: make(map[string]*TargetSession),
		stopCh:  make(chan struct{}),
	}
}

func (s *SessionStore) Load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[session] load error: %v", err)
		}
		return
	}

	var store struct {
		Targets map[string]*TargetSession `json:"targets"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		log.Printf("[session] parse error: %v", err)
		return
	}

	s.mu.Lock()
	for k, v := range store.Targets {
		s.Targets[k] = v
	}
	s.mu.Unlock()

	log.Printf("[session] loaded %d sessions from %s", len(store.Targets), s.path)
}

func (s *SessionStore) Save() {
	s.mu.RLock()
	data, err := json.MarshalIndent(map[string]interface{}{
		"targets": s.Targets,
	}, "", "  ")
	s.mu.RUnlock()

	if err != nil {
		log.Printf("[session] marshal error: %v", err)
		return
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[session] write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("[session] rename error: %v", err)
		return
	}
}

func (s *SessionStore) AutoSave() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.Save()
			return
		case <-ticker.C:
			s.mu.RLock()
			dirty := s.dirty
			s.mu.RUnlock()

			if dirty {
				s.Save()
				s.mu.Lock()
				s.dirty = false
				s.mu.Unlock()
			}
		}
	}
}

func (s *SessionStore) Stop() {
	close(s.stopCh)
}

func (s *SessionStore) markDirty() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

func (s *SessionStore) Get(key string) *TargetSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Targets[key]
}

func (s *SessionStore) Set(key string, ts *TargetSession) {
	s.mu.Lock()
	s.Targets[key] = ts
	s.dirty = true
	s.mu.Unlock()
}

func (s *SessionStore) UpdateSequence(key string, seq int) {
	s.mu.Lock()
	if ts, ok := s.Targets[key]; ok {
		ts.Sequence = seq
		s.dirty = true
	}
	s.mu.Unlock()
}

func (s *SessionStore) UpdateMFAToken(key string, token string, expiresAt int64) {
	s.mu.Lock()
	ts, ok := s.Targets[key]
	if !ok {
		ts = &TargetSession{}
		s.Targets[key] = ts
	}
	ts.MFAToken = token
	ts.MFAExpiresAt = expiresAt
	s.dirty = true
	s.mu.Unlock()
}

func (s *SessionStore) Clear(key string) {
	s.mu.Lock()
	delete(s.Targets, key)
	s.dirty = true
	s.mu.Unlock()
}
