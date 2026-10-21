package sniper

import (
	"io"
	"log"
	"strings"
	"testing"
)

func TestRedactWriterMasksSecrets(t *testing.T) {
	rw := newRedactWriter(io.Discard, []string{
		"guildid-longer-substring", "vanity", "tok-prefix", "email@example.com",
	})
	if len(rw.repl) != 4 {
		t.Fatalf("expected 4 unique non-empty secrets, got %d", len(rw.repl))
	}
	// Longest-secret-first ordering, so the longer id consumes the match
	// before its shorter prefix can.
	if got := rw.repl[0][0]; got != "guildid-longer-substring" {
		t.Errorf("expected longest secret first, got %q", got)
	}

	line := "[claim vanity] target guildid-longer-substring token=tok-prefix email=email@example.com"
	out, err := rw.Write([]byte(line))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if out != len(line) {
		t.Errorf("must report the original length (log pkg depends on it): %d != %d", out, len(line))
	}
}

func TestRedactWriterReplacement(t *testing.T) {
	rw := newRedactWriter(io.Discard, []string{"delta", "1562362699894227007"})
	var buf strings.Builder
	rw.w = &nopWriter{&buf}
	_, _ = rw.Write([]byte("[claim delta] guild=1562362699894227007 ok"))
	got := buf.String()
	if strings.Contains(got, "delta") || strings.Contains(got, "1562362699894227007") {
		t.Errorf("secrets leaked: %q", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Errorf("missing redaction marker: %q", got)
	}
}

type nopWriter struct{ b *strings.Builder }

func (w *nopWriter) Write(p []byte) (int, error) {
	return w.b.Write(p)
}

func TestRedactWriterIgnoresEmptyAndDuplicates(t *testing.T) {
	rw := newRedactWriter(io.Discard, []string{"", "  ", "tok", "tok"})
	if len(rw.repl) != 1 {
		t.Fatalf("empty values and duplicates must be dropped, got %d", len(rw.repl))
	}
}

func TestInstallLogRedactionGatedByEnv(t *testing.T) {
	// Off by default.
	if installLogRedaction(&Conf{Targets: []Target{{Vanity: "x"}}}) {
		t.Error("must stay off without SNIPER_REDACT_LOGS")
	}

	t.Setenv("SNIPER_REDACT_LOGS", "1")
	cfg := &Conf{
		Email:      "me@example.com",
		TOTPSecret: "SECRETVALUE",
		Targets: []Target{{
			GuildID: "123456789012345678",
			Vanity:  "delta",
			Token:   "tok.TokenPart.signature",
		}},
	}
	if !installLogRedaction(cfg) {
		t.Fatal("must activate with SNIPER_REDACT_LOGS=1")
	}

	// The env-emabled install must have swapped the logger's writer.
	visibility := logOutput()
	_, isRedactor := visibility.(*redactWriter)
	if !isRedactor {
		t.Fatalf("expected log output swapped to a redactWriter, got %T", visibility)
	}
}

func logOutput() io.Writer { return log.Writer() }
