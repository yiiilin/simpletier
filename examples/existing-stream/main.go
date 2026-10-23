package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

func main() {
	transport := flag.String("transport", "tcp", "host-established transport: tcp, pipe or websocket")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, *transport, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, transport string, output io.Writer) (err error) {
	// The HOST establishes the connection, before the SDK sees either stream.
	left, right, err := establishedPair(ctx, transport)
	if err != nil {
		return err
	}
	a, err := simpletier.NewStreamCarrier(ctx, left)
	if err != nil {
		return errors.Join(err, left.Close(), right.Close())
	}
	defer func() { err = errors.Join(err, a.Close()) }()
	b, err := simpletier.NewStreamCarrier(ctx, right)
	if err != nil {
		return errors.Join(err, right.Close())
	}
	defer func() { err = errors.Join(err, b.Close()) }()

	if _, err = fmt.Fprintf(output, "Host-established %s streams handed to StreamCarrier; connection types A=%s B=%s.\n", transport, left.Info().Type, right.Info().Type); err != nil {
		return err
	}
	// Synthetic outer-framing fixtures only: these bytes are NOT AEAD output,
	// and must never be interpreted as authenticated SimpleTier traffic.
	frame := simpletier.CarrierFrame{
		Kind: simpletier.FrameKindLinkControl,
		Body: bytes.Repeat([]byte{0xa5}, 32),
	}
	if err = exchange(a, b, frame); err != nil {
		return fmt.Errorf("A -> B: %w", err)
	}
	if _, err = fmt.Fprintf(output, "A -> B: synthetic frame, %d opaque body bytes\n", len(frame.Body)); err != nil {
		return err
	}
	frame.Body = bytes.Repeat([]byte{0x5a}, 32)
	if err = exchange(b, a, frame); err != nil {
		return fmt.Errorf("B -> A: %w", err)
	}
	_, err = fmt.Fprintf(output, "B -> A: synthetic frame, %d opaque body bytes\nCompleted framing-only exchange; not authenticated, no Network routes.\n", len(frame.Body))
	return err
}

func exchange(from, to *simpletier.StreamCarrier, want simpletier.CarrierFrame) error {
	// net.Pipe and some mux streams have no write buffering. Read concurrently
	// with WriteFrame; symmetric writes without readers would block both peers.
	written := make(chan error, 1)
	go func() { written <- from.WriteFrame(want) }()
	got, readErr := to.ReadFrame()
	if err := errors.Join(readErr, <-written); err != nil {
		return err
	}
	if got.Kind != want.Kind || got.HopHeader != want.HopHeader || !bytes.Equal(got.Envelope, want.Envelope) || !bytes.Equal(got.Body, want.Body) {
		return errors.New("frame changed during transport")
	}
	return nil
}

func establishedPair(ctx context.Context, transport string) (simpletier.Connection, simpletier.Connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	switch transport {
	case "pipe":
		a, b := net.Pipe()
		left, err := simpletier.NewConnection(a, simpletier.ConnectionInfo{Type: "pipe"})
		if err != nil {
			return nil, nil, errors.Join(err, a.Close(), b.Close())
		}
		right, err := simpletier.NewConnection(b, simpletier.ConnectionInfo{Type: "pipe"})
		if err != nil {
			return nil, nil, errors.Join(err, left.Close(), b.Close())
		}
		return left, right, nil
	case "tcp":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		connector := &simpletier.TCPConnector{}
		client, err := connector.Dial(ctx, listener.Addr().String())
		if err != nil {
			return nil, nil, errors.Join(err, listener.Close())
		}
		server, err := listener.Accept()
		if err != nil {
			return nil, nil, errors.Join(err, client.Close(), listener.Close())
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return nil, nil, errors.Join(err, client.Close(), server.Close())
		}
		incoming, err := simpletier.NewConnection(server, simpletier.ConnectionInfo{Type: "tcp"})
		if err != nil {
			return nil, nil, errors.Join(err, client.Close(), server.Close())
		}
		return client, incoming, nil
	case "websocket":
		return establishedWebSocketPair(ctx)
	default:
		return nil, nil, fmt.Errorf("unknown transport %q; use tcp, pipe or websocket", transport)
	}
}

func establishedWebSocketPair(ctx context.Context) (simpletier.Connection, simpletier.Connection, error) {
	type result struct {
		conn simpletier.Connection
		err  error
	}
	accepted := make(chan result)
	handoff, stopHandoff := context.WithCancel(ctx)
	const hostToken = "local-example-host-auth-fixture"
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is host HTTP authentication, not SimpleTier membership proof.
		if r.Header.Get("Authorization") != "Bearer "+hostToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			select {
			case accepted <- result{err: err}:
			case <-handoff.Done():
			}
			return
		}
		conn, err := simpletier.NewWebSocketConnection(raw)
		if err != nil {
			err = errors.Join(err, raw.Close())
		}
		select {
		case accepted <- result{conn: conn, err: err}:
		case <-handoff.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}))
	defer func() {
		stopHandoff()
		server.Close()
	}()
	connector := &simpletier.WebSocketConnector{Header: http.Header{"Authorization": {"Bearer " + hostToken}}}
	client, err := connector.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		return nil, nil, err
	}
	select {
	case incoming := <-accepted:
		if incoming.err != nil {
			return nil, nil, errors.Join(incoming.err, client.Close())
		}
		return client, incoming.conn, nil
	case <-ctx.Done():
		return nil, nil, errors.Join(ctx.Err(), client.Close())
	}
}
