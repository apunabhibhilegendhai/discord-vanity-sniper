package sniper

import (
	"bytes"
	"strconv"
)

// httpbody.go: HTTP response body decoding shared by the login, MFA-solve and
// claim paths. Discord's auth and mfa endpoints respond with
// Transfer-Encoding: chunked bodies; returning the raw wire form (with hex
// chunk-size markers embedded) corrupted every structured JSON parse and could
// inject chunk markers INSIDE a value extracted by the fallback substring scan
// — a corrupted ticket or, worse, a corrupted freshly-minted token, on every
// Actions-hosted cold start where token minting runs.

// isChunkedHeaders reports whether an HTTP header block declares
// Transfer-Encoding: chunked. Header names/values are compared
// case-insensitively because Cloudflare and Discord both emit this header and
// gateway formats have historically varied in capitalization.
func isChunkedHeaders(headerBlock []byte) bool {
	lower := make([]byte, len(headerBlock))
	copy(lower, headerBlock)
	lower = bytes.ToLower(lower)
	for _, seg := range bytes.Split(lower, []byte("\r\n")) {
		i := bytes.Index(seg, []byte("transfer-encoding:"))
		if i < 0 {
			continue
		}
		return bytes.Contains(seg[i+len("transfer-encoding:"):], []byte("chunked"))
	}
	return false
}

// respBody returns the decoded HTTP response body: everything after the header
// terminator, with transfer-coding applied. A non-chunked response is returned
// verbatim; a chunked response is reassembled so JSON parses see clean bytes.
// A response with no header terminator has no body and returns nil.
func respBody(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	body := resp[idx+4:]
	if isChunkedHeaders(resp[:idx]) {
		return decodeChunkedBody(body)
	}
	return body
}

// decodeChunkedBody reassembles a chunked body from its raw wire form:
//
//	<hex-size>[;ext]\r\n<data>\r\n ... \r\n0\r\n[trailers]
//
// Returns the reassembled payload. A malformed size line anywhere in the
// stream means this was not actually a chunked body (or it is badly corrupt);
// the ORIGINAL input is returned untouched so callers keep their old behavior.
// A truncated final chunk (deadline hit mid-body) yields every full chunk —
// callers already treat short bodies as incomplete.
func decodeChunkedBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	out := make([]byte, 0, len(body))
	pos := 0
	for {
		eol := bytes.Index(body[pos:], []byte("\r\n"))
		if eol < 0 {
			// No size line left to parse: keep any unparsed remainder verbatim.
			return append(out, body[pos:]...)
		}
		sizeLine := splitAtByte(body[pos:pos+eol], ';')
		size, err := strconv.ParseUint(string(sizeLine), 16, 32)
		if err != nil {
			// Not chunked after all — hand back exactly what arrived.
			return append([]byte(nil), body...)
		}
		pos += eol + 2
		if size == 0 {
			// Terminal chunk; trailers (if any) are intentionally dropped.
			return out
		}
		if pos+int(size) > len(body) {
			// Truncated mid-chunk (deadline/EOF): what we have is what we keep.
			return append(out, body[pos:]...)
		}
		out = append(out, body[pos:pos+int(size)]...)
		pos += int(size)
		if len(body)-pos >= 2 && bytes.Equal(body[pos:pos+2], []byte("\r\n")) {
			pos += 2
		}
	}
}

// splitAtByte returns the prefix of p before b's first occurrence, or p itself.
func splitAtByte(p []byte, sep byte) []byte {
	if i := bytes.IndexByte(p, sep); i >= 0 {
		return p[:i]
	}
	return p
}
