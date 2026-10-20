package sniper

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebhookSender posts Discord embed payloads to a webhook URL. It keeps a warm
// TLS connection to discord.com so that Send() does not pay a fresh dial+handshake
// on every call. The warm conn is lazily established on the first Send and
// re-established on errors.
//
// Send is now SYNCHRONOUS (the caller blocks until delivery or all retries
// exhaust). Every failure is logged with the HTTP status + body so dropped
// embeds are diagnosable. A WaitGroup tracks in-flight Sends for clean shutdown.
type WebhookSender struct {
	url   string
	wg    sync.WaitGroup // tracks in-flight Sends for Flush

	mu       sync.Mutex
	warmConn net.Conn // persistent TCP+TLS conn (nil = not yet dialed)
	tlsConn  *tls.Conn
}

func NewWebhookSender(url string) *WebhookSender {
	if url == "" {
		return nil
	}
	return &WebhookSender{url: url}
}

// Send posts a Discord embed to the webhook. It blocks until delivery succeeds
// (204 from Discord) or all 3 retries exhaust. Every failure is logged. The
// caller blocks briefly (~1 RTT on success, up to 3× on transient failures) —
// but this runs AFTER the claim 200 is already confirmed, so it does NOT add
// latency to the snipe itself.
//
// Nil receiver is a no-op (webhook URL not configured).
func (w *WebhookSender) Send(title string, color int, fields map[string]string) {
	if w == nil {
		return
	}
	w.wg.Add(1)
	w.send(title, color, fields)
	w.wg.Done()
}

// Flush waits for all in-flight Sends to complete. Call during shutdown so
// success embeds are never orphaned by a process exit.
func (w *WebhookSender) Flush() {
	if w == nil {
		return
	}
	w.wg.Wait()
}

func (w *WebhookSender) send(title string, color int, fields map[string]string) {
	host, path, useTLS, err := parseWebhookURL(w.url)
	if err != nil {
		log.Printf("[webhook] parse URL error: %v", err)
		return
	}

	embedFields := make([]map[string]interface{}, 0, len(fields))
	for k, v := range fields {
		embedFields = append(embedFields, map[string]interface{}{
			"name":   k,
			"value":  v,
			"inline": true,
		})
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":     title,
				"color":     color,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"fields":    embedFields,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[webhook] json marshal error: %v", err)
		return
	}

	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		path, host, len(body), body,
	)

	// Retry up to 3 times with short backoff. Transient failures (stale warm
	// conn, Cloudflare blip, webhook 429) are common; retrying gives us
	// reliability without a persistent queue.
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}

		conn, tlsC, dialErr := w.acquireConn(host, useTLS)
		if dialErr != nil {
			log.Printf("[webhook] dial error (attempt %d/%d): %v", attempt+1, maxRetries, dialErr)
			continue
		}

		var writeConn net.Conn
		if tlsC != nil {
			writeConn = tlsC
		} else {
			writeConn = conn
		}

		if _, werr := writeConn.Write([]byte(req)); werr != nil {
			log.Printf("[webhook] write error (attempt %d/%d): %v", attempt+1, maxRetries, werr)
			w.closeConn()
			continue
		}

		// Read the response to confirm delivery. Discord returns 204 No Content
		// on success; anything else (429, 404, 500, Cloudflare block) means the
		// embed was NOT delivered.
		writeConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		respBuf := make([]byte, 1024)
		n, rerr := writeConn.Read(respBuf)

		// On read error, the warm conn is likely stale — close it so the next
		// attempt dials fresh.
		if rerr != nil && n == 0 {
			log.Printf("[webhook] read error (attempt %d/%d): %v", attempt+1, maxRetries, rerr)
			w.closeConn()
			continue
		}

		resp := respBuf[:n]
		statusLine := extractStatusLine(resp)
		statusCode := parseStatusCode(resp)

		if statusCode == 204 || (statusCode >= 200 && statusCode < 300) {
			// Success — keep the warm conn alive for the next Send.
			return
		}

		// Non-success: log and retry. Extract body for diagnosis.
		respBody := ""
		if idx := bytes.Index(resp, []byte("\r\n\r\n")); idx >= 0 {
			b := bytes.TrimSpace(resp[idx+4:])
			if len(b) > 300 {
				b = b[:300]
			}
			respBody = string(b)
		}
		log.Printf("[webhook] delivery failed (attempt %d/%d) — %s body: %s",
			attempt+1, maxRetries, statusLine, respBody)

		// Close the warm conn so the next retry dials fresh. A stale conn that
		// returned an error won't recover on a subsequent POST.
		w.closeConn()
	}

	log.Printf("[webhook] all %d attempts exhausted — embed dropped: %s", maxRetries, title)
}

// acquireConn returns the warm persistent connection to the webhook host, or
// dials a fresh one. The returned net.Conn is the underlying raw TCP; the
// *tls.Conn (if TLS) is returned separately so callers can Write to the TLS
// layer (which encrypts) instead of the raw TCP (which would send plaintext).
func (w *WebhookSender) acquireConn(host string, useTLS bool) (raw net.Conn, tlsC *tls.Conn, err error) {
	w.mu.Lock()
	if w.warmConn != nil && w.tlsConn != nil {
		// Check if the warm conn is still alive before returning it. A server-side
		// close or idle timeout can kill it between Sends. Past-deadline probe is
		// non-blocking (same trick as isConnAlive in pool.go).
		w.tlsConn.SetReadDeadline(time.Now().Add(-time.Millisecond))
		buf := make([]byte, 1)
		_, probeErr := w.tlsConn.Read(buf)
		w.tlsConn.SetReadDeadline(time.Time{})

		if probeErr != nil {
			if ne, ok := probeErr.(net.Error); ok && ne.Timeout() {
				// Timeout = conn still open and waiting for data — healthy.
				raw, tlsC = w.warmConn, w.tlsConn
				w.mu.Unlock()
				return
			}
			// EOF / connection reset / other error — conn is dead.
			w.warmConn.Close()
			w.warmConn = nil
			w.tlsConn = nil
		} else {
			raw, tlsC = w.warmConn, w.tlsConn
			w.mu.Unlock()
			return
		}
	}
	w.mu.Unlock()

	// Dial a fresh conn (no warm conn available or the old one was dead).
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	rawConn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
	if dialErr != nil {
		return nil, nil, dialErr
	}

	if useTLS {
		tlsC = tls.Client(rawConn, &tls.Config{
			ServerName:  host,
			MinVersion:  tls.VersionTLS12,
			NextProtos:  []string{"http/1.1"},
		})
		if herr := tlsC.Handshake(); herr != nil {
			rawConn.Close()
			return nil, nil, herr
		}
		// Store as the new warm conn for reuse.
		w.mu.Lock()
		if w.warmConn != nil {
			w.warmConn.Close() // shouldn't happen, but be safe
		}
		w.warmConn = rawConn
		w.tlsConn = tlsC
		w.mu.Unlock()
		return rawConn, tlsC, nil
	}

	w.mu.Lock()
	w.warmConn = rawConn
	w.mu.Unlock()
	return rawConn, nil, nil
}

// closeConn closes and nils the warm connection. The next Send will dial fresh.
func (w *WebhookSender) closeConn() {
	w.mu.Lock()
	if w.warmConn != nil {
		w.warmConn.Close()
		w.warmConn = nil
		w.tlsConn = nil
	}
	w.mu.Unlock()
}

// parseWebhookURL splits a Discord webhook URL into host, request path, and
// whether to use TLS. Handles both https:// (the only scheme Discord uses) and
// http:// gracefully. Returns an error if the URL has no host.
func parseWebhookURL(raw string) (host, reqPath string, useTLS bool, err error) {
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" {
		return "", "", false, fmt.Errorf("invalid webhook url")
	}
	reqPath = u.Path
	if reqPath == "" {
		reqPath = "/"
	}
	if u.RawQuery != "" {
		reqPath += "?" + u.RawQuery
	}
	useTLS = strings.EqualFold(u.Scheme, "https") || u.Scheme == ""
	if u.Scheme == "" {
		useTLS = true
	}
	return u.Host, reqPath, useTLS, nil
}
