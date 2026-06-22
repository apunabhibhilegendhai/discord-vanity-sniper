package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// BrowserProfile bundles the three parts of a consistent browser fingerprint:
// User-Agent, X-Super-Properties (base64 JSON), and the utls ClientHelloID that
// controls the TLS JA3/JA4 handshake. All three are derived from a single
// browser choice so they can never disagree (TLS says Chrome → headers say Chrome),
// which is the structural fix for the 403/10008 "Unknown Message" failures caused
// by a TLS↔UA fingerprint mismatch.
//
// The operator sets `browser: "chrome"` (or "firefox") in config.json; the profile
// derives everything else. Explicit user_agent / super_properties_b64 fields in
// the fingerprint block are ignored when a browser is set, because letting them
// override the derived values would re-introduce the drift that caused the bug.
type BrowserProfile struct {
	Name          string              // "chrome" or "firefox"
	UserAgent     string              // full User-Agent header
	SuperPropsB64 string              // base64-encoded X-Super-Properties JSON
	UTLSSpecID    utls.ClientHelloID  // utls preset for the matching TLS fingerprint
}

// activeProfile is the package-level profile set once at startup (in
// config.go's LoadConfig) and read by tlsdial.go for every TLS handshake.
// All paths — pool, MFA solve, login, gateway REST — share this same profile,
// so the fingerprint is identical across every Discord connection the sniper opens.
var activeProfile *BrowserProfile

// browserPresets returns the known presets keyed by lowercase browser name.
func browserPresets() map[string]BrowserProfile {
	return map[string]BrowserProfile{
		"chrome": {
			Name:      "chrome",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
			// Super-props derived from the proven working sniper (main.js):
			//   browser_version and client_build_number match what a real Chrome
			//   Discord client reports. client_launch_id is randomised per startup
			//   (like the working JS) to avoid session correlation across runs.
			SuperPropsB64: buildChromeSuperProps(),
			UTLSSpecID:    utls.HelloChrome_Auto, // Chrome JA3
		},
		"firefox": {
			Name:      "firefox",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			SuperPropsB64: buildFirefoxSuperProps(),
			UTLSSpecID:    utls.HelloFirefox_Auto, // Firefox 120 JA3 (closest available)
		},
	}
}

// ResolveFingerprint takes the raw config values and returns a consistent
// BrowserProfile. Priority:
//  1. If cfg.Browser is set ("chrome" or "firefox"), use that preset. Any
//     explicit user_agent / super_properties_b64 in the fingerprint block are
//     ignored (logged as a warning) to prevent drift.
//  2. If cfg.Browser is empty but user_agent is set, infer the browser from the
//     UA string ("Firefox" → firefox, anything else → chrome) and use that preset.
//  3. If neither is set, default to chrome (the proven working configuration).
//
// Device cookies (dcfduid, sdcfduid) are always preserved from config or
// generated fresh — they're not part of the browser fingerprint.
func ResolveFingerprint(cfg *Conf) *BrowserProfile {
	presets := browserPresets()

	browser := strings.ToLower(strings.TrimSpace(cfg.Browser))

	// Case 2: infer from explicit user_agent if no browser field set
	if browser == "" && cfg.Fingerprint.UserAgent != "" {
		if strings.Contains(cfg.Fingerprint.UserAgent, "Firefox") {
			browser = "firefox"
		} else {
			browser = "chrome"
		}
		log.Printf("[config] no browser field set — inferred %q from user_agent", browser)
	}

	// Case 3: default
	if browser == "" {
		browser = "chrome"
	}

	profile, ok := presets[browser]
	if !ok {
		log.Printf("[config] unknown browser %q — defaulting to chrome (supported: chrome, firefox)", browser)
		profile = presets["chrome"]
	}

	// Warn if explicit fingerprint fields will be overridden by the profile.
	// The operator may have copy-pasted these from DevTools and expects them to be
	// used; logging makes the override visible rather than silently ignoring it.
	ua := cfg.Fingerprint.UserAgent
	sp := cfg.Fingerprint.SuperPropsB64
	if ua != "" && ua != profile.UserAgent {
		log.Printf("[config] WARNING: ignoring user_agent %q (does not match browser %q profile %q); using %q",
			truncate(ua, 60), browser, browser, truncate(profile.UserAgent, 60))
	}
	if sp != "" && sp != profile.SuperPropsB64 {
		log.Printf("[config] WARNING: ignoring super_properties_b64 (does not match browser %q profile); auto-generated", browser)
	}

	// Preserve or generate device cookies — these are orthogonal to the browser
	// fingerprint and must persist across runs for session continuity.
	if cfg.Fingerprint.DcfDuid == "" {
		cfg.Fingerprint.DcfDuid = newUUID()
	}
	if cfg.Fingerprint.SdcfDuid == "" {
		cfg.Fingerprint.SdcfDuid = newUUID()
	}

	// Write the resolved fingerprint back into cfg so every downstream consumer
	// (claimer, MFA, login, pool) reads consistent values without further
	// coordination.
	cfg.Fingerprint.UserAgent = profile.UserAgent
	cfg.Fingerprint.SuperPropsB64 = profile.SuperPropsB64

	activeProfile = &profile
	return activeProfile
}

// buildChromeSuperProps generates a base64-encoded X-Super-Properties JSON
// matching a real Chrome Discord client: Windows, Chrome 143.0.0.0,
// client_build_number 565311, has_client_mods: false, with referrer fields
// (referrer, referring_domain, search_engine) set to plausible values.
func buildChromeSuperProps() string {
	props := map[string]interface{}{
		"os":                       "Windows",
		"browser":                  "Chrome",
		"device":                   "",
		"system_locale":            "en-US",
		"browser_user_agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		"browser_version":          "143.0.0.0",
		"os_version":               "10",
		"referrer":                 "https://www.google.com/",
		"referring_domain":         "www.google.com",
		"search_engine":            "google",
		"referrer_current":         "",
		"referring_domain_current": "",
		"release_channel":          "stable",
		"client_build_number":      565311,
		"client_event_source":      nil,
		"has_client_mods":          false,
	}
	return base64Props(props)
}

// buildFirefoxSuperProps generates a base64-encoded X-Super-Properties JSON
// matching a Firefox Discord client on Windows, including the referrer fields
// that the proven working JS sniper sends. Matches the working sniper's field
// set to avoid anti-abuse flags.
func buildFirefoxSuperProps() string {
	props := map[string]interface{}{
		"os":                       "Windows",
		"browser":                  "Firefox",
		"device":                   "",
		"system_locale":            "en-US",
		"browser_user_agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"browser_version":          "133.0",
		"os_version":               "10",
		"referrer":                 "https://www.google.com/",
		"referring_domain":         "www.google.com",
		"search_engine":            "google",
		"referrer_current":         "",
		"referring_domain_current": "",
		"release_channel":          "stable",
		"client_build_number":      565311,
		"client_event_source":      nil,
		"has_client_mods":          false,
	}
	return base64Props(props)
}

// base64Props marshals a map to JSON then base64-encodes it (matching Discord's
// X-Super-Properties wire format).
func base64Props(props map[string]interface{}) string {
	raw, _ := json.Marshal(props)
	return base64.StdEncoding.EncodeToString(raw)
}

// decodeSuperPropsSummary decodes an X-Super-Properties base64 blob and returns
// a short "browser=X, build=Y" string for startup logging. Returns "<opaque>"
// if the blob can't be decoded (e.g. a custom value the operator pasted) so the
// log line stays readable without leaking the full base64.
func decodeSuperPropsSummary(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "<opaque>"
	}
	var props map[string]interface{}
	if err := json.Unmarshal(raw, &props); err != nil {
		return "<opaque>"
	}
	browser, _ := props["browser"].(string)
	build := ""
	switch v := props["client_build_number"].(type) {
	case float64:
		build = fmt.Sprintf("%v", int(v))
	default:
		build = fmt.Sprintf("%v", props["client_build_number"])
	}
	ver, _ := props["browser_version"].(string)
	return fmt.Sprintf("browser=%s version=%s build=%s", browser, ver, build)
}


