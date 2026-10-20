package sniper

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// processStartTime is set at init and used by startup timing logs across
// packages to report "READY in Xs" relative to process launch.
var processStartTime = time.Now()

func Main() {
	configPath := flag.String("config", "config.json", "path to config file (all targets in it are launched)")
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
	if len(orch.runners) == 0 {
		log.Fatalf("startup: no targets could be armed")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// One command starts every target in the config. Orchestrator.StartAll is
	// the only owner of run state; there is no menu and no per-target prompt.
	go orch.Run()

	<-sig
	orch.Shutdown()
}

type validateTokenFunc func(token, superProps, userAgent, cookie string) bool
type mintTokenFunc func(email, password, totpSecret, superProps, userAgent string) (string, error)

// ensureTokens checks each target's token and mints a fresh one if needed.
// A token is "needed" if it's empty or fails ValidateToken (GET /users/@me).
// Minting requires global email + password + totp_secret in config.
//
// Validation is concurrent across targets. Mints for the same account are
// coalesced into one login (Discord invalidates/rate-limits duplicate login
// attempts), while different accounts mint in parallel. A failure on one target
// is reported and leaves that target's token empty; it does not abort the other
// lanes. NewOrchestrator then skips token-less lanes and exposes them through
// ArmFailures.
func ensureTokens(cfg *Conf, configPath string) error {
	return ensureTokensWith(cfg, configPath, ValidateToken, MintToken)
}

func ensureTokensWith(cfg *Conf, configPath string, validate validateTokenFunc, mint mintTokenFunc) error {
	sp := cfg.Fingerprint.SuperPropsB64
	ua := cfg.Fingerprint.UserAgent

	type outcome struct {
		idx    int
		token  string
		minted bool
		err    error
	}
	outcomes := make([]outcome, len(cfg.Targets))

	// One mint per credential set. Targets that share an account wait for the
	// first mint instead of racing a second login (which can rotate the token
	// the first one just received).
	type mintCall struct {
		done  chan struct{}
		token string
		err   error
	}
	var mintMu sync.Mutex
	mintCalls := make(map[string]*mintCall)

	var wg sync.WaitGroup
	for i := range cfg.Targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t := &cfg.Targets[i]

			if t.Token != "" && validate(t.Token, sp, ua, "") {
				log.Printf("[token] target %s: existing token valid ✅", t.Vanity)
				outcomes[i] = outcome{idx: i, token: t.Token}
				return
			}

			if t.Token != "" {
				log.Printf("[token] target %s: existing token dead (401), minting fresh...", t.Vanity)
			} else {
				log.Printf("[token] target %s: no token, minting fresh...", t.Vanity)
			}

			if cfg.Email == "" {
				outcomes[i] = outcome{idx: i, err: fmt.Errorf("auto-login requires 'email' in config")}
				return
			}
			pwd := cfg.Password
			if pwd == "" {
				pwd = t.Password
			}
			if pwd == "" {
				outcomes[i] = outcome{idx: i, err: fmt.Errorf("auto-login requires 'password' in config")}
				return
			}

			key := cfg.Email + "\x00" + pwd + "\x00" + cfg.TOTPSecret
			mintMu.Lock()
			call, ok := mintCalls[key]
			if !ok {
				call = &mintCall{done: make(chan struct{})}
				mintCalls[key] = call
			}
			mintMu.Unlock()

			if ok {
				<-call.done
			} else {
				call.token, call.err = mint(cfg.Email, pwd, cfg.TOTPSecret, sp, ua)
				close(call.done)
			}

			if call.err != nil {
				outcomes[i] = outcome{idx: i, err: fmt.Errorf("auto-login failed: %w", call.err)}
				return
			}
			outcomes[i] = outcome{idx: i, token: call.token, minted: true}
		}(i)
	}
	wg.Wait()

	anyChanged := false
	failed := 0
	for _, out := range outcomes {
		if out.err != nil {
			failed++
			log.Printf("[token] target %s: %v", cfg.Targets[out.idx].Vanity, out.err)
			continue
		}
		if out.minted {
			if cfg.Targets[out.idx].Token != out.token {
				cfg.Targets[out.idx].Token = out.token
				anyChanged = true
			}
			log.Printf("[token] target %s: minted fresh token ✅", cfg.Targets[out.idx].Vanity)
		}
	}

	if failed > 0 {
		log.Printf("[token] %d/%d target(s) lack a usable token; those lanes will be skipped", failed, len(cfg.Targets))
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
