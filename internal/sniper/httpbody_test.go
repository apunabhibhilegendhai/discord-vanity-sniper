package sniper

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The chunked fixtures mirror what Discord actually sends on the auth and
// mfa endpoints: two chunks whose boundary falls in different places,
// plus the size markers that used to leak into extracted values.

func chunkedResp(header, body string) string {
	var b bytes.Buffer
	b.WriteString(header)
	// Split the JSON into two chunks: sizes f2 (242) style hex markers.
	mid := len(body) / 2
	ch := func(data string) string {
		return strings.ToLower(strings.TrimSpace(strings.Replace(
			"", "", "", 0))) + hexSize(len(data)) + "\r\n" + data + "\r\n"
	}
	b.WriteString(ch(body[:mid]))
	b.WriteString(ch(body[mid:]))
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func hexSize(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{digits[n%16]}, out...)
		n /= 16
	}
	return string(out)
}

func TestDecodeChunkedBody(t *testing.T) {
	body := `{"ticket":"MTU2MjM2MjY5OTg5NDIyNzAwNw.HnJI_g.Gvv1FU_4Uy6JUtAQ0iOCgsyK3k.abc123xyZ","mfa":true,"totp":true}`

	// A single-chunk stream round-trips.
	single := hexSize(len(body)) + "\r\n" + body + "\r\n0\r\n"
	if got := string(decodeChunkedBody([]byte(single))); got != body {
		t.Errorf("single chunk: got %q want %q", got, body)
	}

	// The multi-chunk fixture from the real wire: the chunk boundary splices
	// a size marker INTO the middle of the ticket string, which is exactly
	// what used to corrupt the extraction.
	resp := chunkedResp("HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n", body)
	if !isChunkedHeaders([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")) {
		t.Fatal("isChunkedHeaders missed a standard chunked header")
	}
	if isChunkedHeaders([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")) {
		t.Fatal("isChunkedHeaders flagged a content-length response as chunked")
	}
	decoded := respBody([]byte(resp))
	ticket, err := extractTicket([]byte(resp))
	if err != nil {
		t.Fatalf("extractTicket on chunked 60003 body: %v", err)
	}
	if want := `MTU2MjM2MjY5OTg5NDIyNzAwNw.HnJI_g.Gvv1FU_4Uy6JUtAQ0iOCgsyK3k.abc123xyZ`; ticket != want {
		t.Errorf("ticket corrupted by chunk boundary: got %q want %q", ticket, want)
	}
	if !strings.Contains(string(decoded), `"totp":true`) {
		t.Errorf("decoded body missing tail fields: %q", decoded)
	}
}

func TestDecodeChunkedBodyPassthrough(t *testing.T) {
	// Body with no framing headers at all is handed back untouched.
	raw := []byte(`{"a":1}`)
	out := decodeChunkedBody(raw)
	if !bytes.Equal(out, raw) {
		t.Errorf("empty-size passthrough mismatch: %q", out)
	}

	// A malformed size line means "not chunked": original must be returned.
	bogus := []byte("nonsense\r\nmore nonsense\r\n")
	out = decodeChunkedBody(bogus)
	if !bytes.Equal(out, bogus) {
		t.Errorf("bogus size line should pass through unchanged, got %q", out)
	}

	// Empty body decodes to nil.
	if decodeChunkedBody(nil) != nil {
		t.Error("nil body should decode to nil")
	}
}

func TestParseFinishResponseChunked(t *testing.T) {
	finish := `{"token":"MjYzNjM1Nzg5NzQzMTkzNDI0Nw.GxP7X8.abc123def456ghi789jkl","expires_in":300,"expires_at":1739999999}`
	// Two chunks with the boundary mid-token.
	mid := 40
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		hexSize(mid) + "\r\n" + finish[:mid] + "\r\n" +
		hexSize(len(finish)-mid) + "\r\n" + finish[mid:] + "\r\n0\r\n"

	token, expiresIn, err := parseFinishResponse([]byte(raw))
	if err != nil {
		t.Fatalf("parseFinishResponse on chunked body: %v", err)
	}
	if token != "MjYzNjM1Nzg5NzQzMTkzNDI0Nw.GxP7X8.abc123def456ghi789jkl" {
		t.Errorf("token corrupted at the chunk boundary: %q", token)
	}
	if expiresIn <= 0 {
		t.Errorf("expiresIn not recovered: %d", expiresIn)
	}
}

func TestExtractRawBodyChunked(t *testing.T) {
	payload := `{"ticket":"t1","login_instance_id":"80509542-454f-48fd-acc7-5c5ce0076834"}`
	resp := chunkedResp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", payload)

	body := extractRawBody([]byte(resp))
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("chunked body is not clean JSON after extractRawBody: %v (body=%q)", err, body)
	}
	if m["login_instance_id"] != "80509542-454f-48fd-acc7-5c5ce0076834" {
		t.Errorf("login_instance_id corrupted: %v", m["login_instance_id"])
	}

	// Non-chunked responses pass through verbatim.
	plain := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nplainbody"
	if got := extractRawBody([]byte(plain)); got != "plainbody" {
		t.Errorf("plain body mangled: %q", got)
	}
}
