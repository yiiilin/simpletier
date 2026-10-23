package benchmarks_test

import (
	"fmt"
	"testing"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// BenchmarkNewNetworkStartup reports SDK construction/Close startup separately
// from every business benchmark. The business benchmarks exclude this phase by
// warming the actual route and dial before their b.ResetTimer; this benchmark is
// the only place the fixed carrier bind and durable identity creation are
// measured. It never uses an arbitrary startup nonce or budget policy.
func BenchmarkNewNetworkStartup(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		port := freeLoopbackPort(b)
		n, err := simpletier.NewNetwork(simpletier.Config{
			Listen: []string{fmt.Sprintf("tcp://127.0.0.1:%d", port)},
			Network: simpletier.NetworkConfig{
				Name:  benchNetworkName,
				CIDR:  benchCIDR,
				Token: benchToken,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP:  nodeBIP,
				LogLevel: "error",
			},
		})
		if err != nil {
			b.Fatalf("NewNetwork startup: %v", err)
		}
		if !n.LocalVirtualIP().IsValid() {
			b.Fatalf("LocalVirtualIP is invalid immediately after NewNetwork")
		}
		if err := n.Close(); err != nil {
			classifyFatal(b, "startup Close", err)
		}
		select {
		case <-n.Done():
		default:
			b.Fatalf("UNEXPECTED: Done is not closed after Close returned")
		}
	}
}
