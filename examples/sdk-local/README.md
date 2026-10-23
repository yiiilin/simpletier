# Local SDK Startup Example

Run from the repository root:

```sh
go run ./examples/sdk-local -listen tcp://127.0.0.1:39751 -virtual-port 8080
```

The host builds a typed `simpletier.Config`, generates a fresh 128-bit token with `crypto/rand`, starts `NewNetwork`, and registers `Listen("tcp", ":8080")` on the instance's provisional VirtualIP. `-state-dir` can be supplied as a host option; an empty value uses the SDK's platform default. No configuration file is read or expanded.

The program prints the provisional endpoint and exits cleanly on Ctrl-C. The token
is intentionally not printed, and each run creates a new one, so this is a local
startup example rather than a peer-join recipe: a second node can only join if it
is given the same name, CIDR and token.

Link authentication, fact publication and remote Stream delivery are implemented
and exercised by the other examples and by the benchmark suite. For a two-node
transfer, see `../network-runtime`; for a relayed three-node path, see
`../tun-chain`; for one process serving both a WebSocket peer and a TCP peer, see
`../gin-edge`.
