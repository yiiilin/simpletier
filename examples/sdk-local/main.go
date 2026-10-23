package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	carrier := flag.String("listen", "tcp://127.0.0.1:39751", "TCP carrier listen address")
	name := flag.String("name", "sdk-example", "network name")
	cidr := flag.String("cidr", "10.254.0.0/24", "canonical IPv4 network")
	virtualPort := flag.Int("virtual-port", 8080, "local virtual port to register")
	flag.Parse()

	var secret [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate example token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])

	network, err := simpletier.NewNetwork(simpletier.Config{
		Listen: []string{*carrier},
		Network: simpletier.NetworkConfig{
			Name:  *name,
			CIDR:  *cidr,
			Token: token,
		},
		Options: simpletier.RuntimeOptions{},
	})
	if err != nil {
		return fmt.Errorf("start SimpleTier Network: %w", err)
	}

	listener, err := network.Listen("tcp", fmt.Sprintf(":%d", *virtualPort))
	if err != nil {
		return errors.Join(fmt.Errorf("register local virtual listener: %w", err), network.Close())
	}
	fmt.Printf("Provisional local endpoint: %s\n", listener.Addr())
	fmt.Println("Listening on this VirtualIP. A peer with the same name, CIDR and token can Dial this port.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	if err := network.Close(); err != nil {
		return fmt.Errorf("close SimpleTier Network: %w", err)
	}
	return nil
}
