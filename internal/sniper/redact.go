package sniper

import (
	"io"
	"log"
	"os"
	"strings"
)

// redact.go keeps credential values out of log output.
//
// GitHub-hosted Actions logs are public on a public repository, but the
// sniper's own log lines routinely carry guild ids, vanity codes, account
// tokens, proxies and webhook URLs. When an Actions-hosted session runs
// (SNIPER_REDACT_LOGS=1), log.SetOutput hands every line through redactWriter,
// which masks every configured secret before it reaches the log stream. Local
// runs default to full detail — redaction is chosen by the operator's
// environment, not compiled in.

type redactWriter struct {
	w io.Writer
	// repl holds (secret, placeholder) pairs sorted longest-secret-first.
	repl [][2]string
}

func newRedactWriter(w io.Writer, secrets []string) *redactWriter {
	// Longest first so a shorter value that is a substring of a longer one
	// (guild id inside a webhook URL, token prefix inside a cache key) never
	// wins the replacement and leaves half the secret visible.
	uniq := make(map[string]bool, len(secrets))
	ordered := make([]string, 0, len(secrets))
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if s == "" || uniq[s] {
			continue
		}
		uniq[s] = true
		ordered = append(ordered, s)
	}
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && len(ordered[j]) > len(ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	rw := redactWriter{w: w, repl: make([][2]string, len(ordered))}
	for i, s := range ordered {
		rw.repl[i] = [2]string{s, "<redacted>"}
	}
	return &rw
}

// Write masks every configured secret in one log line. Go's log package
// performs exactly one Write per log call, so a secret is never split across
// two Write calls. The original length is reported so the log package never
// retries or short-writes.
func (r *redactWriter) Write(p []byte) (int, error) {
	s := string(p)
	for _, pair := range r.repl {
		if strings.Contains(s, pair[0]) {
			s = strings.ReplaceAll(s, pair[0], pair[1])
		}
	}
	_, err := io.WriteString(r.w, s)
	return len(p), err
}

// installLogRedaction swaps the standard logger's output for a redacting
// writer when SNIPER_REDACT_LOGS is enabled ("1" or "true"). Every value that
// appears in the config and could identify credentials is masked: account
// email/password, TOTP secret, backup codes, webhook URL, and per-target
// token/password/guild id/vanity/proxy entries, plus the device cookie
// properties from the fingerprint block. Returns whether redaction is active.
func installLogRedaction(cfg *Conf) bool {
	switch v := strings.TrimSpace(os.Getenv("SNIPER_REDACT_LOGS")); v {
	case "1", "true", "TRUE", "True":
	default:
		return false
	}

	var secrets []string
	add := func(values ...string) {
		secrets = append(secrets, values...)
	}
	add(cfg.Email, cfg.Password, cfg.TOTPSecret, cfg.WebhookURL, cfg.SessionPath)
	add(cfg.Fingerprint.DcfDuid, cfg.Fingerprint.SdcfDuid)
	for i := range cfg.BackupCodes {
		add(cfg.BackupCodes[i])
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		add(t.Token, t.Password, t.GuildID, t.Vanity)
		add(t.Proxies...)
	}
	if len(secrets) == 0 {
		return false
	}

	log.SetOutput(newRedactWriter(os.Stderr, secrets))
	return true
}
