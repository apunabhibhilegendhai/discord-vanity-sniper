package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// processStartTime is set at init and used by startup timing logs across
// packages to report "READY in Xs" relative to process launch.
var processStartTime = time.Now()

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	noCLI := flag.Bool("no-cli", false, "disable interactive CLI (daemon mode)")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Log the resolved browser profile so fingerprint drift is visible at
	// startup. activeProfile is set by ResolveFingerprint inside LoadConfig; if
	// it's nil something is wrong with config resolution and downstream TLS
	// handshakes would fall back to the chrome preset silently.
	if activeProfile != nil {
		// Decode the super-props so the operator can eyeball browser/build
		// without pasting the base64 into a decoder.
		sp := decodeSuperPropsSummary(activeProfile.SuperPropsB64)
		log.Printf("[fingerprint] browser=%s ua=%q super_props={%s} tls=%s",
			activeProfile.Name, activeProfile.UserAgent, sp, activeProfile.UTLSSpecID.Str())
	} else {
		log.Printf("[fingerprint] WARNING: activeProfile is nil — TLS will fall back to chrome preset")
	}

	// Ensure every target has a working token. If a target's token is missing or
	// dead (401), mint a fresh one via email/password + TOTP auto-login and
	// persist it back to config.json so subsequent runs reuse it. This avoids a
	// manual token-grab from DevTools every time Discord invalidates the token.
	if err := ensureTokens(cfg, *configPath); err != nil {
		log.Fatalf("token: %v", err)
	}

	orch := NewOrchestrator(cfg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go orch.Run()

	if !*noCLI {
		orch.cliMode = true
		cli := NewCLI(orch)
		go cli.Run()
		select {
		case <-sig:
		case <-cli.Done():
		}
	} else {
		<-sig
	}
	orch.Shutdown()
}

// ensureTokens checks each target's token and mints a fresh one if needed.
// A token is "needed" if it's empty or fails ValidateToken (GET /users/@me).
// Minting requires global email + password + totp_secret in config.
func ensureTokens(cfg *Conf, configPath string) error {
	sp := cfg.Fingerprint.SuperPropsB64
	ua := cfg.Fingerprint.UserAgent

	anyChanged := false
	for i := range cfg.Targets {
		t := &cfg.Targets[i]

		// If a usable token is already present and valid, skip.
		if t.Token != "" && ValidateToken(t.Token, sp, ua, "") {
			log.Printf("[token] target %s: existing token valid ✅", t.Vanity)
			continue
		}

		if t.Token != "" {
			log.Printf("[token] target %s: existing token dead (401), minting fresh...", t.Vanity)
		} else {
			log.Printf("[token] target %s: no token, minting fresh...", t.Vanity)
		}

		if cfg.Email == "" {
			return fmt.Errorf("auto-login requires 'email' in config (target %s)", t.Vanity)
		}
		pwd := cfg.Password
		if pwd == "" {
			pwd = t.Password
		}
		if pwd == "" {
			return fmt.Errorf("auto-login requires 'password' in config (target %s)", t.Vanity)
		}

		tok, err := MintToken(cfg.Email, pwd, cfg.TOTPSecret, sp, ua)
		if err != nil {
			return fmt.Errorf("auto-login failed for %s: %w", t.Vanity, err)
		}
		t.Token = tok
		log.Printf("[token] target %s: minted fresh token ✅", t.Vanity)
		anyChanged = true
	}

	if anyChanged {
		if err := saveConfig(cfg, configPath); err != nil {
			return fmt.Errorf("persist minted token: %w", err)
		}
		log.Printf("[token] config persisted to %s", configPath)
	}
	return nil
}

// saveConfig re-serializes the config back to disk, preserving structure. We
// round-trip through the json tags on Conf (rather than a raw map) so the
// written file stays canonical. New tokens are written into each target.
func saveConfig(cfg *Conf, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
