package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestExistingStreamExample(t *testing.T) {
	for _, transport := range []string{"tcp", "pipe", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			if err := run(ctx, transport, &output); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"A -> B", "B -> A", "connection types A=" + transport + " B=" + transport, "synthetic", "not authenticated"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("example output missing %q: %s", want, &output)
				}
			}
		})
	}
}

func TestExistingStreamExampleRejectsUnknownTransport(t *testing.T) {
	if err := run(context.Background(), "udp", &bytes.Buffer{}); err == nil {
		t.Fatal("unknown transport was accepted")
	}
}
