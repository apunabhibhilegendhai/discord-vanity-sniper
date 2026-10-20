package sniper

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestResolveFingerprintChromeConsistency is the regression test for the
// 403/10008 bug: the fix is that TLS JA3, User-Agent, and X-Super-Properties
// must all agree on the same browser. Before this change, TLS was forced to
// Chrome while headers/super-props came from a Firefox UA in config —
// Discord's fingerprint check saw "Chrome TLS + Firefox headers" and rejected
// requests with 403 / code 10008.
//
// This test asserts that resolving a Chrome profile produces a UA containing
// "Chrome", super-props whose decoded "browser" field is "Chrome", and a TLS
// spec that is HelloChrome_Auto. Any drift between these three re-introduces
// the bug, so the test fails the build on regression.
func TestResolveFingerprintChromeConsistency(t *testing.T) {
	cfg := &Conf{Browser: "chrome"}
	prof := ResolveFingerprint(cfg)

	if prof.Name != "chrome" {
		t.Fatalf("profile name = %q, want chrome", prof.Name)
	}

	// 1. User-Agent must identify Chrome.
	if !strings.Contains(prof.UserAgent, "Chrome") {
		t.Errorf("Chrome profile UA %q does not contain 'Chrome'", prof.UserAgent)
	}
	if strings.Contains(prof.UserAgent, "Firefox") {
		t.Errorf("Chrome profile UA %q unexpectedly contains 'Firefox'", prof.UserAgent)
	}

	// 2. Decoded super-props must report browser=Chrome and a matching
	//    browser_user_agent. This is what Discord's client-integrity check
	//    compares against the TLS fingerprint.
	browser, ua := decodeSuperProps(t, prof.SuperPropsB64)
	if browser != "Chrome" {
		t.Errorf("super-props browser = %q, want Chrome", browser)
	}
	if ua != prof.UserAgent {
		t.Errorf("super-props browser_user_agent %q != profile UA %q (drift!)", ua, prof.UserAgent)
	}

	// 3. TLS spec must be Chrome. This is the JA3 Discord sees in the
	//    handshake; it must match the UA the headers claim.
	if prof.UTLSSpecID != utls.HelloChrome_Auto {
		t.Errorf("TLS spec = %v, want HelloChrome_Auto", prof.UTLSSpecID)
	}

	// 4. The resolved profile must have been written back into cfg so every
	//    downstream consumer reads consistent values without re-resolving.
	if cfg.Fingerprint.UserAgent != prof.UserAgent {
		t.Errorf("cfg.Fingerprint.UserAgent not updated to match profile (drift!)")
	}
	if cfg.Fingerprint.SuperPropsB64 != prof.SuperPropsB64 {
		t.Errorf("cfg.Fingerprint.SuperPropsB64 not updated to match profile (drift!)")
	}
}

// TestResolveFingerprintFirefoxConsistency mirrors the Chrome test for the
// Firefox profile, asserting all three fingerprint components agree on Firefox.
func TestResolveFingerprintFirefoxConsistency(t *testing.T) {
	cfg := &Conf{Browser: "firefox"}
	prof := ResolveFingerprint(cfg)

	if prof.Name != "firefox" {
		t.Fatalf("profile name = %q, want firefox", prof.Name)
	}
	if !strings.Contains(prof.UserAgent, "Firefox") {
		t.Errorf("Firefox profile UA %q does not contain 'Firefox'", prof.UserAgent)
	}
	browser, ua := decodeSuperProps(t, prof.SuperPropsB64)
	if browser != "Firefox" {
		t.Errorf("super-props browser = %q, want Firefox", browser)
	}
	if ua != prof.UserAgent {
		t.Errorf("super-props browser_user_agent %q != profile UA %q (drift!)", ua, prof.UserAgent)
	}
	if prof.UTLSSpecID != utls.HelloFirefox_Auto {
		t.Errorf("TLS spec = %v, want HelloFirefox_Auto", prof.UTLSSpecID)
	}
}

// TestResolveFingerprintDefaultsToChrome verifies that an empty browser field
// resolves to the proven-working Chrome profile, not some undefined state.
func TestResolveFingerprintDefaultsToChrome(t *testing.T) {
	cfg := &Conf{}
	prof := ResolveFingerprint(cfg)
	if prof.Name != "chrome" {
		t.Errorf("empty browser resolved to %q, want chrome default", prof.Name)
	}
	if prof.UTLSSpecID != utls.HelloChrome_Auto {
		t.Errorf("empty browser TLS spec = %v, want HelloChrome_Auto", prof.UTLSSpecID)
	}
}

// TestResolveFingerprintInfersFromUA verifies that when no browser field is
// set but a user_agent is, the browser is inferred correctly. This lets old
// configs (which only set user_agent) keep working without edits.
func TestResolveFingerprintInfersFromUA(t *testing.T) {
	cfg := &Conf{Fingerprint: Fingerprint{UserAgent: "Mozilla/5.0 ... Firefox/128.0"}}
	prof := ResolveFingerprint(cfg)
	if prof.Name != "firefox" {
		t.Errorf("Firefox UA inferred as %q, want firefox", prof.Name)
	}
}

// TestResolveFingerprintOverridesExplicitUA is the core anti-drift guarantee:
// even if the operator pastes a Firefox user_agent into config while browser
// is "chrome", the chrome profile wins. The whole point of the single source
// of truth is that the three components can NEVER disagree.
func TestResolveFingerprintOverridesExplicitUA(t *testing.T) {
	cfg := &Conf{
		Browser: "chrome",
		Fingerprint: Fingerprint{
			UserAgent: "Mozilla/5.0 ... Firefox/128.0", // conflicting!
		},
	}
	prof := ResolveFingerprint(cfg)

	// Profile must be chrome despite the conflicting UA in config.
	if prof.Name != "chrome" {
		t.Fatalf("expected chrome to win over conflicting Firefox UA, got %q", prof.Name)
	}
	// The resolved UA must be Chrome, and cfg must reflect it (not the stale
	// Firefox value the operator pasted).
	if !strings.Contains(prof.UserAgent, "Chrome") {
		t.Errorf("profile UA %q is not Chrome (drift not prevented!)", prof.UserAgent)
	}
	if !strings.Contains(cfg.Fingerprint.UserAgent, "Chrome") {
		t.Errorf("cfg.Fingerprint.UserAgent %q was not overridden to Chrome (drift not prevented!)",
			cfg.Fingerprint.UserAgent)
	}
	// And TLS must be Chrome to match.
	if prof.UTLSSpecID != utls.HelloChrome_Auto {
		t.Errorf("TLS spec = %v, want HelloChrome_Auto (must match UA)", prof.UTLSSpecID)
	}
}

// TestResolveFingerprintPreservesDeviceCookies verifies that device cookies
// (dcfduid/sdcfduid) — which identify the device to Discord and must persist
// across runs for session continuity — are preserved from config and not
// clobbered by the browser profile resolution.
func TestResolveFingerprintPreservesDeviceCookies(t *testing.T) {
	cfg := &Conf{
		Browser: "chrome",
		Fingerprint: Fingerprint{
			DcfDuid:  "preserved-dcf",
			SdcfDuid: "preserved-sdcf",
		},
	}
	ResolveFingerprint(cfg)
	if cfg.Fingerprint.DcfDuid != "preserved-dcf" {
		t.Errorf("dcfduid not preserved: got %q", cfg.Fingerprint.DcfDuid)
	}
	if cfg.Fingerprint.SdcfDuid != "preserved-sdcf" {
		t.Errorf("sdcfduid not preserved: got %q", cfg.Fingerprint.SdcfDuid)
	}
}

// TestResolveFingerprintGeneratesDeviceCookiesIfMissing verifies fresh device
// cookies are generated when absent, so a cold config still has valid device
// identifiers.
func TestResolveFingerprintGeneratesDeviceCookiesIfMissing(t *testing.T) {
	cfg := &Conf{Browser: "chrome"}
	ResolveFingerprint(cfg)
	if cfg.Fingerprint.DcfDuid == "" {
		t.Errorf("dcfduid not generated when missing")
	}
	if cfg.Fingerprint.SdcfDuid == "" {
		t.Errorf("sdcfduid not generated when missing")
	}
}

// decodeSuperProps is a test helper that decodes the base64 X-Super-Properties
// blob and returns the browser and browser_user_agent fields, failing the test
// on any decode error.
func decodeSuperProps(t *testing.T, b64 string) (browser, ua string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode super-props: %v", err)
	}
	var props map[string]interface{}
	if err := json.Unmarshal(raw, &props); err != nil {
		t.Fatalf("unmarshal super-props: %v", err)
	}
	browser, _ = props["browser"].(string)
	ua, _ = props["browser_user_agent"].(string)
	return browser, ua
}
