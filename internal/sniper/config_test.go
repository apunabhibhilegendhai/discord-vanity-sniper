package sniper

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigAcceptsLegacyGraceEnd proves removing the unused field did not
// break existing configs: encoding/json ignores an object key with no matching
// Go field, so both a valid and a malformed grace_end must still load.
func TestLoadConfigAcceptsLegacyGraceEnd(t *testing.T) {
	for _, grace := range []string{"2026-07-18T14:30:00Z", "not-a-timestamp"} {
		t.Run(grace, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			data := `{
			  "targets": [{
			    "guild_id": "123456789",
			    "vanity": "legacy",
			    "token": "test-token",
			    "grace_end": "` + grace + `"
			  }]
			}`
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig rejected legacy grace_end: %v", err)
			}
			if len(cfg.Targets) != 1 || cfg.Targets[0].Vanity != "legacy" {
				t.Fatalf("unexpected targets: %+v", cfg.Targets)
			}
		})
	}
}
