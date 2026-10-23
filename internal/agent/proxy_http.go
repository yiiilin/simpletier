package agent

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement: R-MESH-006 (HTTP proxy ingress).
//
// One inbound serves both request forms with mandatory
// Proxy-Authorization: Basic (RFC 7617):
//
//   - CONNECT establishes an opaque byte tunnel. Nothing above TCP is parsed
//     after the 200 response, so WebSocket-over-CONNECT works and there is no
//     HTTPS man-in-the-middle.
//   - A normal forward request (an http absolute-form URI, or an origin-form
//     request with a valid Host) is streamed to the origin server: request and
//     response bodies are copied incrementally, chunked framing is re-encoded
//     rather than buffered, an Expect: 100-continue is answered by this proxy in
//     one bounded write, and hop-by-hop headers including Proxy-Authorization
//     are stripped before anything reaches the target.
//
// A normal request is answered with Connection: close and the connection is
// closed after one exchange, which keeps the adapter bounded without pretending
// to implement a connection pool. Plain-HTTP Upgrade (ws:// without CONNECT) is
// not part of this slice; the Upgrade/Connection hop headers are stripped and
// the WebSocket path of record is CONNECT.
const (
	maxHTTPRequestBytes        = 32 << 10
	maxProxyAuthorizationBytes = 4096
	basicRealm                 = "simpletier"
	httpErrorWriteTimeout      = 2 * time.Second

	// maxHTTPInterimResponses bounds how many 1xx responses are relayed before
	// the upstream is treated as unusable. Expect: 100-continue is stripped
	// before the request is forwarded, so interim responses are not expected.
	maxHTTPInterimResponses = 16

	// unlimitedHTTPBodyBytes replaces the header byte limit once a request has
	// been parsed, so a large streamed body is never truncated by the limit that
	// exists only to bound the header block.
	unlimitedHTTPBodyBytes = int64(1) << 62
)

var (
	errInvalidTarget   = errors.New("agent: invalid CONNECT target")
	errForbiddenTarget = errors.New("agent: forbidden CONNECT target")
)

// hopByHopHeaders are consumed by one HTTP hop and must never be forwarded to
// the origin server. Proxy-Authorization is included because it authenticates
// the client to this proxy and is a private credential of the proxy entry.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// serveHTTPProxy runs one HTTP proxy ingress connection: bounded failure budget,
// mandatory Basic authentication, then CONNECT or a streamed forward request.
func serveHTTPProxy(ctx context.Context, server *proxyServer, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(server.config.handshakeTimeout()))

	if !server.authBudget.allow(time.Now()) {
		// The entry's failure budget is exhausted for this window; the connection
		// is closed without doing request or credential work.
		server.stats.throttled.Add(1)
		return
	}

	socketReader := bufio.NewReader(conn)
	headerLimit := &io.LimitedReader{R: socketReader, N: maxHTTPRequestBytes}
	headerReader := bufio.NewReader(headerLimit)
	request, err := http.ReadRequest(headerReader)
	if err != nil {
		status := http.StatusBadRequest
		if headerLimit.N <= 0 {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		writeHTTPStatus(conn, status)
		return
	}

	if err := checkProxyAuthorization(request.Header.Get("Proxy-Authorization"), server.credentials); err != nil {
		server.noteAuthFailure()
		writeHTTPStatus(conn, http.StatusProxyAuthRequired, `Proxy-Authenticate: Basic realm="`+basicRealm+`"`)
		return
	}

	if request.Method == http.MethodConnect {
		serveHTTPConnect(ctx, server, conn, request, headerReader, socketReader)
		return
	}
	serveHTTPForward(ctx, server, conn, request, headerLimit)
}

// serveHTTPConnect establishes the opaque tunnel. Two buffered layers can hold
// bytes that follow the CONNECT header block: the reader handed to
// http.ReadRequest and the socket reader beneath it. Both are drained into the
// target before the byte relay starts, so pipelined tunnel data is not lost.
func serveHTTPConnect(ctx context.Context, server *proxyServer, conn net.Conn, request *http.Request, headerReader, socketReader *bufio.Reader) {
	// A request body would alias the tunnel stream; refuse instead of guessing
	// which bytes belong to the tunnel. request.Body is deliberately not closed.
	if request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeHTTPStatus(conn, http.StatusBadRequest)
		return
	}
	host, port, err := httpConnectTarget(request)
	if err != nil {
		if errors.Is(err, errForbiddenTarget) {
			writeHTTPStatus(conn, http.StatusForbidden)
			return
		}
		writeHTTPStatus(conn, http.StatusBadRequest)
		return
	}
	upstream, _, err := server.dialProxyTarget(ctx, host, port)
	if err != nil {
		if errors.Is(err, ErrTargetDenied) {
			server.stats.policyDenied.Add(1)
			writeHTTPStatus(conn, http.StatusForbidden)
			return
		}
		server.stats.dialFailures.Add(1)
		writeHTTPStatus(conn, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	if err := writeAll(conn, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// The handshake deadline must not bound the established tunnel.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	if err := forwardBuffered(upstream, headerReader); err != nil {
		return
	}
	if err := forwardBuffered(upstream, socketReader); err != nil {
		return
	}
	relay(ctx, conn, upstream)
}

// serveHTTPForward streams one normal forward-proxy request to the origin
// server and streams the response back. The body is never buffered whole.
func serveHTTPForward(ctx context.Context, server *proxyServer, conn net.Conn, request *http.Request, headerLimit *io.LimitedReader) {
	host, port, status := forwardHTTPTarget(request)
	if status != 0 {
		server.stats.unsupported.Add(1)
		writeHTTPStatus(conn, status)
		return
	}
	expect := strings.TrimSpace(request.Header.Get("Expect"))
	if expect != "" && !strings.EqualFold(expect, "100-continue") {
		writeHTTPStatus(conn, http.StatusExpectationFailed)
		return
	}

	upstream, _, err := server.dialProxyTarget(ctx, host, port)
	if err != nil {
		if errors.Is(err, ErrTargetDenied) {
			server.stats.policyDenied.Add(1)
			writeHTTPStatus(conn, http.StatusForbidden)
			return
		}
		server.stats.dialFailures.Add(1)
		writeHTTPStatus(conn, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Once admitted, the exchange is a stream: the handshake deadline must not
	// bound a slow upload or a long-lived response, and the header byte limit
	// must not truncate the body. Agent.Close cancels ctx and closes both
	// connections, so a dead peer cannot pin this handler.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		_ = upstream.Close()
	})
	defer stop()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	headerLimit.N = unlimitedHTTPBodyBytes
	if expect != "" {
		// The proxy is the HTTP server for this client, so it answers the single
		// bounded 100-continue expectation itself and does not forward Expect.
		if err := writeAll(conn, []byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
			return
		}
	}
	if err := forwardHTTPRequest(upstream, request); err != nil {
		return
	}

	responseReader := bufio.NewReader(upstream)
	for interim := 0; ; interim++ {
		response, err := http.ReadResponse(responseReader, request)
		if err != nil {
			writeHTTPStatus(conn, http.StatusBadGateway)
			return
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			// Plain-HTTP Upgrade is out of scope and the Upgrade/Connection hop
			// headers were stripped from the request, so this 101 cannot be
			// completed as an upgrade. Fail closed instead of relaying a 101 the
			// client never negotiated.
			writeHTTPStatus(conn, http.StatusBadGateway)
			return
		}
		if response.StatusCode >= 100 && response.StatusCode < 200 {
			if interim >= maxHTTPInterimResponses {
				return
			}
			if err := writeInterimHTTPResponse(conn, response); err != nil {
				return
			}
			continue
		}
		_ = forwardHTTPResponse(conn, request, response)
		return
	}
}

// forwardHTTPTarget extracts the origin authority of one forward request. Only
// an http absolute-form URI or an origin-form request with a valid Host header
// is accepted; https:// and every other target form must use CONNECT.
func forwardHTTPTarget(request *http.Request) (string, uint16, int) {
	if request.URL == nil {
		return "", 0, http.StatusBadRequest
	}
	authority := request.URL.Host
	if request.URL.Scheme != "" {
		if !strings.EqualFold(request.URL.Scheme, "http") || authority == "" {
			return "", 0, http.StatusBadRequest
		}
	} else {
		authority = request.Host
		if authority == "" || request.URL.Path == "*" || request.URL.Opaque == "*" {
			return "", 0, http.StatusBadRequest
		}
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.Contains(authority, ":") {
			return "", 0, http.StatusBadRequest
		}
		host, port = authority, "80"
	}
	if !printableHost(host) || ipv6LiteralHost(host) {
		return "", 0, http.StatusBadRequest
	}
	if !isDecimal(port) {
		return "", 0, http.StatusBadRequest
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", 0, http.StatusBadRequest
	}
	return host, uint16(number), 0
}

// forwardHTTPRequest writes one streamed origin-form request. Hop-by-hop headers
// and private proxy credentials are removed first, the request target is reduced
// to path?query, Host keeps the original authority, and the body is copied
// incrementally with its original framing.
func forwardHTTPRequest(dst io.Writer, request *http.Request) error {
	removeHopByHopHeaders(request.Header)
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Expect")

	target := "/"
	if uri := request.URL.RequestURI(); uri != "" {
		target = uri
	}
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}

	chunked := hasChunkedTransfer(request.TransferEncoding)
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\n", request.Method, target)
	fmt.Fprintf(&head, "Host: %s\r\n", host)
	switch {
	case chunked:
		head.WriteString("Transfer-Encoding: chunked\r\n")
		if names := trailerNames(request.Trailer); len(names) > 0 {
			fmt.Fprintf(&head, "Trailer: %s\r\n", strings.Join(names, ", "))
		}
	case request.ContentLength > 0:
		fmt.Fprintf(&head, "Content-Length: %d\r\n", request.ContentLength)
	case request.ContentLength == 0 && request.Header.Get("Content-Length") != "":
		head.WriteString("Content-Length: 0\r\n")
	}
	for name, values := range request.Header {
		if isFramingOrHopHeader(name) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&head, "%s: %s\r\n", name, value)
		}
	}
	head.WriteString("\r\n")
	if _, err := io.WriteString(dst, head.String()); err != nil {
		return err
	}

	switch {
	case chunked:
		return writeChunkedBody(dst, request.Body, request.Trailer)
	case request.ContentLength > 0:
		_, err := io.CopyN(dst, request.Body, request.ContentLength)
		return err
	default:
		return nil
	}
}

// forwardHTTPResponse writes one streamed response back to the client. It always
// announces Connection: close because this adapter serves exactly one exchange
// per client connection, and it re-encodes chunked framing instead of buffering
// the body.
func forwardHTTPResponse(dst io.Writer, request *http.Request, response *http.Response) error {
	removeHopByHopHeaders(response.Header)

	noBody := request.Method == http.MethodHead || !httpBodyAllowedForStatus(response.StatusCode)
	chunked := !noBody && hasChunkedTransfer(response.TransferEncoding)
	if request.ProtoMajor == 1 && request.ProtoMinor == 0 {
		// An HTTP/1.0 client does not understand chunked framing; the
		// Connection: close below makes the reply close-delimited instead.
		chunked = false
	}

	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/1.1 %s\r\n", responseStatusLine(response))
	for name, values := range response.Header {
		if isFramingOrHopHeader(name) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&head, "%s: %s\r\n", name, value)
		}
	}
	switch {
	case noBody:
		if request.Method == http.MethodHead && response.ContentLength >= 0 {
			fmt.Fprintf(&head, "Content-Length: %d\r\n", response.ContentLength)
		}
	case chunked:
		head.WriteString("Transfer-Encoding: chunked\r\n")
		if names := trailerNames(response.Trailer); len(names) > 0 {
			fmt.Fprintf(&head, "Trailer: %s\r\n", strings.Join(names, ", "))
		}
	case response.ContentLength >= 0:
		fmt.Fprintf(&head, "Content-Length: %d\r\n", response.ContentLength)
	}
	head.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(dst, head.String()); err != nil {
		return err
	}

	switch {
	case noBody:
		return nil
	case chunked:
		return writeChunkedBody(dst, response.Body, response.Trailer)
	case response.ContentLength >= 0:
		if _, err := io.CopyN(dst, response.Body, response.ContentLength); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	default:
		_, err := io.Copy(dst, response.Body)
		return err
	}
}

// writeInterimHTTPResponse relays one 1xx response without announcing a
// connection close, because the final response is still to come.
func writeInterimHTTPResponse(dst io.Writer, response *http.Response) error {
	removeHopByHopHeaders(response.Header)
	var head strings.Builder
	fmt.Fprintf(&head, "HTTP/1.1 %s\r\n", responseStatusLine(response))
	for name, values := range response.Header {
		if isFramingOrHopHeader(name) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&head, "%s: %s\r\n", name, value)
		}
	}
	head.WriteString("\r\n")
	_, err := io.WriteString(dst, head.String())
	return err
}

// writeChunkedBody copies src to dst as one HTTP/1.1 chunked body and writes the
// trailer section after EOF, when the trailer values are known.
func writeChunkedBody(dst io.Writer, src io.Reader, trailer http.Header) error {
	buffer := make([]byte, relayBufferSize)
	for {
		count, err := src.Read(buffer)
		if count > 0 {
			if _, writeErr := fmt.Fprintf(dst, "%x\r\n", count); writeErr != nil {
				return writeErr
			}
			if _, writeErr := dst.Write(buffer[:count]); writeErr != nil {
				return writeErr
			}
			if _, writeErr := io.WriteString(dst, "\r\n"); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	if _, err := io.WriteString(dst, "0\r\n"); err != nil {
		return err
	}
	if err := writeTrailers(dst, trailer); err != nil {
		return err
	}
	_, err := io.WriteString(dst, "\r\n")
	return err
}

func writeTrailers(dst io.Writer, trailer http.Header) error {
	for name, values := range trailer {
		for _, value := range values {
			if _, err := fmt.Fprintf(dst, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func trailerNames(trailer http.Header) []string {
	if len(trailer) == 0 {
		return nil
	}
	names := make([]string, 0, len(trailer))
	for name := range trailer {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// removeHopByHopHeaders deletes the fields named by Connection plus the fixed
// hop-by-hop set from one header block before it is forwarded.
func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

// isFramingOrHopHeader reports whether a header is written by this adapter's own
// framing or is hop-by-hop, and must therefore be skipped while copying fields.
func isFramingOrHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Host", "Content-Length", "Transfer-Encoding", "Trailer",
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Upgrade":
		return true
	default:
		return false
	}
}

func hasChunkedTransfer(encodings []string) bool {
	return len(encodings) > 0 && strings.EqualFold(encodings[0], "chunked")
}

func responseStatusLine(response *http.Response) string {
	if response.Status != "" {
		return response.Status
	}
	return fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode))
}

// httpBodyAllowedForStatus mirrors net/http's bodyAllowedForStatus, which is not
// exported.
func httpBodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	default:
		return true
	}
}

// checkProxyAuthorization validates one Proxy-Authorization header. Every
// failure mode returns the same client-visible 407 so a caller cannot probe
// which stage failed, and the comparison itself is constant time.
func checkProxyAuthorization(header string, credentials Credentials) error {
	const scheme = "Basic "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return fmt.Errorf("%w: Proxy-Authorization must use the Basic scheme", ErrAuthentication)
	}
	encoded := strings.TrimSpace(header[len(scheme):])
	if encoded == "" || len(encoded) > maxProxyAuthorizationBytes {
		return fmt.Errorf("%w: malformed Proxy-Authorization value", ErrAuthentication)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: Proxy-Authorization is not valid base64", ErrAuthentication)
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" {
		return fmt.Errorf("%w: Proxy-Authorization must carry username:password", ErrAuthentication)
	}
	if !credentials.Matches(username, password) {
		return fmt.Errorf("%w: credentials do not match this inbound", ErrAuthentication)
	}
	return nil
}

// httpConnectTarget extracts the authority of a CONNECT request. Domain names
// and IPv4 literals are accepted; resolution stays with the outbound policy port
// and the Dialer. IPv6 literals are refused before any dial because this version
// is IPv4-only.
func httpConnectTarget(request *http.Request) (string, uint16, error) {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, fmt.Errorf("%w: authority %q must be host:port", errInvalidTarget, authority)
	}
	if !printableHost(host) {
		return "", 0, fmt.Errorf("%w: authority %q has an unusable host", errInvalidTarget, authority)
	}
	if ipv6LiteralHost(host) {
		return "", 0, fmt.Errorf("%w: IPv6 target %q", errForbiddenTarget, host)
	}
	if !isDecimal(port) {
		return "", 0, fmt.Errorf("%w: authority %q has a non-decimal port", errInvalidTarget, authority)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", 0, fmt.Errorf("%w: authority %q has an out-of-range port", errInvalidTarget, authority)
	}
	return host, uint16(number), nil
}

// forwardBuffered hands every byte already buffered by one reader to dst so the
// relay can continue reading from the socket itself.
func forwardBuffered(dst net.Conn, src *bufio.Reader) error {
	buffered := src.Buffered()
	if buffered == 0 {
		return nil
	}
	_, err := io.CopyN(dst, src, int64(buffered))
	return err
}

// writeHTTPStatus writes one terminal HTTP error response. The write is bounded
// by its own deadline and the connection is always closed by the caller.
func writeHTTPStatus(conn net.Conn, status int, headers ...string) {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, header := range headers {
		builder.WriteString(header)
		builder.WriteString("\r\n")
	}
	builder.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(httpErrorWriteTimeout))
	_, _ = io.WriteString(conn, builder.String())
}

// rejectOverLimitProxyConn refuses one connection beyond a configured limit. An
// HTTP client gets a bounded 503; a SOCKS5 client is closed before any response
// because no reply code exists outside a request exchange.
func rejectOverLimitProxyConn(kind ProxyKind, conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(rejectWriteTimeout))
	if kind == ProxyHTTP {
		writeHTTPStatus(conn, http.StatusServiceUnavailable)
	}
	_ = conn.Close()
}
