// Command network-runtime runs one node of a real three-process SimpleTier
// source -> relay -> target chain. It performs no application framing of its
// own: every byte on the virtual stream is produced by the SDK data plane, so a
// test that drives three of these processes exercises real cross-process
// authenticated links, a real relay hop and a real 80 KiB echo.
//
// Roles:
//
//	target      listens on its fixed VirtualIP and echoes every received byte back
//	relay       dials -upstream and waits, forwarding opaque E2E frames
//	source      dials the target VirtualIP, writes -bytes, verifies the echo and
//	            prints "PROCESS-CHAIN-OK <sha256>" on success
//	udp-target  listens with Network.ListenPacket and echoes every datagram back
//	            to the peer it received it from (a real Flow reply)
//	udp-source  sends -bytes datagrams to the target VirtualIP:port with
//	            Network.ListenPacket and verifies the echo, then prints
//	            "UDP-CHAIN-OK <sha256>"
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "network-runtime: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	role        string
	listen      string
	upstream    string
	fixedIP     string
	name        string
	cidr        string
	token       string
	targetIP    string
	targetPort  int
	localPort   int
	bytes       int
	dialTimeout time.Duration
}

func run() error {
	var o options
	flag.StringVar(&o.role, "role", "", "source|relay|target")
	flag.StringVar(&o.listen, "listen", "", "tcp:// carrier listen address")
	flag.StringVar(&o.upstream, "upstream", "", "tcp:// upstream carrier address")
	flag.StringVar(&o.fixedIP, "fixed-ip", "", "canonical virtual IPv4 of this node")
	flag.StringVar(&o.name, "name", "process-chain", "network name")
	flag.StringVar(&o.cidr, "cidr", "10.249.0.0/24", "canonical IPv4 network")
	flag.StringVar(&o.token, "token", "", "shared network token")
	flag.StringVar(&o.targetIP, "target-ip", "", "target virtual IPv4")
	flag.IntVar(&o.targetPort, "target-port", 0, "target virtual port")
	flag.IntVar(&o.localPort, "local-port", 41001, "local virtual UDP port of the udp-source")
	flag.IntVar(&o.bytes, "bytes", 80<<10, "payload bytes to echo")
	flag.DurationVar(&o.dialTimeout, "dial-timeout", 60*time.Second, "source dial convergence window")
	flag.Parse()

	if o.role == "" || o.listen == "" || o.fixedIP == "" || o.token == "" {
		return fmt.Errorf("role, listen, fixed-ip and token are required")
	}

	cfg := simpletier.Config{
		Listen:  []string{o.listen},
		Network: simpletier.NetworkConfig{Name: o.name, CIDR: o.cidr, Token: o.token},
		Options: simpletier.RuntimeOptions{FixedIP: o.fixedIP},
	}
	if o.upstream != "" {
		cfg.Upstreams = []string{o.upstream}
	}
	handle, err := simpletier.NewNetwork(cfg)
	if err != nil {
		return fmt.Errorf("NewNetwork(%s): %w", o.role, err)
	}
	defer handle.Close()

	switch o.role {
	case "target":
		listener, err := handle.Listen("tcp", fmt.Sprintf("%s:%d", o.fixedIP, o.targetPort))
		if err != nil {
			return fmt.Errorf("target Listen: %w", err)
		}
		defer listener.Close()
		fmt.Println("READY")
		return serveEcho(listener, o.bytes)
	case "relay":
		fmt.Println("READY")
		<-handle.Done()
		return nil
	case "source":
		return dialEcho(handle, o)
	case "udp-target":
		conn, err := handle.ListenPacket("udp", fmt.Sprintf("%s:%d", o.fixedIP, o.targetPort))
		if err != nil {
			return fmt.Errorf("udp-target ListenPacket: %w", err)
		}
		defer conn.Close()
		fmt.Println("READY")
		return serveUDPEcho(conn)
	case "udp-source":
		return dialUDPEcho(handle, o)
	default:
		return fmt.Errorf("unknown role %q", o.role)
	}
}

// serveEcho echoes every received byte until the peer's CloseWrite/FIN, then
// half-closes its own direction so the source can see the complete echo.
func serveEcho(listener simpletier.StreamListener, total int) error {
	for {
		stream, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(stream simpletier.Stream) {
			defer stream.Close()
			buf := make([]byte, 4<<10)
			read := 0
			for read < total {
				n, err := stream.Read(buf)
				if n > 0 {
					read += n
					if _, werr := stream.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					break
				}
			}
			_ = stream.CloseWrite()
		}(stream)
	}
}

func dialEcho(n simpletier.Network, o options) error {
	address := fmt.Sprintf("%s:%d", o.targetIP, o.targetPort)
	deadline := time.Now().Add(o.dialTimeout)
	var stream simpletier.Stream
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := n.DialContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			stream = s
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if stream == nil {
		return fmt.Errorf("DialContext(%s) never succeeded: %w", address, lastErr)
	}
	defer stream.Close()

	payload := chainPayload(o.bytes)
	written := 0
	for written < len(payload) {
		end := written + (16 << 10)
		if end > len(payload) {
			end = len(payload)
		}
		got, err := stream.Write(payload[written:end])
		if err != nil {
			return fmt.Errorf("write at %d: %w", written, err)
		}
		written += got
	}
	if err := stream.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echoed); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if !bytes.Equal(payload, echoed) {
		return fmt.Errorf("echo mismatch over %d bytes", len(payload))
	}
	sum := sha256.Sum256(echoed)
	fmt.Printf("PROCESS-CHAIN-OK %s\n", hex.EncodeToString(sum[:]))
	return nil
}

// chainPayload is the deterministic payload both the helper and its test use.
func chainPayload(total int) []byte {
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte((i*13 + 7) % 251)
	}
	return payload
}

// serveUDPEcho answers every datagram with the same payload, using the real
// overlay peer address the datagram came from. The public WriteTo spends that
// peer's reply capability through the Flow plane.
func serveUDPEcho(conn net.PacketConn) error {
	buffer := make([]byte, 65507)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(buffer[:n], from); err != nil {
			return err
		}
	}
}

// dialUDPEcho sends one datagram of -bytes to the target virtual endpoint and
// verifies the exact echo. Until the target route and packet lane converge, a
// send or a read simply times out and is retried.
func dialUDPEcho(n simpletier.Network, o options) error {
	conn, err := n.ListenPacket("udp", fmt.Sprintf("%s:%d", o.fixedIP, o.localPort))
	if err != nil {
		return fmt.Errorf("udp-source ListenPacket: %w", err)
	}
	defer conn.Close()

	payload := chainPayload(o.bytes)
	destination, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", o.targetIP, o.targetPort))
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	deadline := time.Now().Add(o.dialTimeout)
	buffer := make([]byte, len(payload))
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := conn.WriteTo(payload, destination); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			lastErr = err
			continue
		}
		if !bytes.Equal(buffer[:n], payload) {
			return fmt.Errorf("UDP echo mismatch: %d bytes echoed, want %d", n, len(payload))
		}
		sum := sha256.Sum256(buffer[:n])
		fmt.Printf("UDP-CHAIN-OK %s\n", hex.EncodeToString(sum[:]))
		return nil
	}
	return fmt.Errorf("udp echo never completed: %w", lastErr)
}
