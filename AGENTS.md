# Working in this repository

## Read first

`docs/README.md` maps the whole doc set. For a change, open the module doc under
`docs/internals/` that covers the code you are touching, plus `docs/architecture.md`
for how the parts fit together.

## Layout

```
pkg/simpletier/     SDK: Network, Agent, config, relay/ and room/
internal/           one package per mechanism: wire, link, topology, circuit,
                    session, path, security, agent, flow, packet, budget
tests/              end-to-end acceptance and the benchmark harness
examples/           nine runnable programs, each `go run ./examples/<name>`
docs/               user guide, architecture, per-module internals, measurements
```

## Verify before claiming done

```bash
go build ./... && go vet ./...
go test ./internal/... ./pkg/...     # unit and integration
go test ./tests/...                  # end-to-end over real TCP
go test ./tests/tun_acceptance/      # real TUN device; needs root
go test -race ./pkg/simpletier/      # race detector
```

End-to-end means real processes and real network interfaces. A test that mocks the
carrier or skips when an interface is missing proves nothing about this system; note
the gap instead of pretending coverage.

## Rules the code follows

**Runtime state is process-local.** Nothing is written to disk. A restart therefore
presents a new NodeID and re-derives the virtual address, and no state survives to
protect against replay across restarts. Deployments that need a stable address pin it
with `RuntimeOptions.FixedIP`. Do not reintroduce a state directory without deciding
what the file format, locking and crash recovery are.

**Document what is true.** A doc states how the system behaves now. Planned work is
either absent or explicitly labelled as planned. When code and doc disagree, the code
is right and the doc needs fixing.

**Do not record the process.** Who decided what, in which conversation, under which
identifier, is not part of the deliverable. Keep the conclusion and the reason it
holds; drop the trail that led there.

**Numbers come from a run.** Performance claims in `docs/benchmarks/` name the
benchmark function in `tests/benchmarks/` that produces them. If a number has no
reproducing command, remove it or add the benchmark.

## Commit style

One change per commit. The body says what was wrong and how it was verified, not which
files moved.
