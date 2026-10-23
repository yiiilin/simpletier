package simpletier_test

import (
	"net"
	"testing"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// externalRuntimeOwnerConfig builds a real Config through the exported SDK
// surface only: a fresh loopback listener, an explicit canonical state
// directory and a fixed network identity. The external test package cannot see
// internal fixtures, so this is the same construction an SDK user would write.
func externalRuntimeOwnerConfig(t *testing.T, stateDir string) simpletier.Config {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return simpletier.Config{
		Listen:  []string{"tcp://" + address},
		Network: simpletier.NetworkConfig{Name: "external-owner", CIDR: "10.44.0.0/24", Token: "external-owner-token"},
		Options: simpletier.RuntimeOptions{FixedIP: "10.44.0.7"},
	}
}
