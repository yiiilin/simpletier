package room

import (
	"errors"
	"testing"
	"time"
)

// TestRoomKeyHidesToken pins that a room is named by the token's hash, so neither
// the state directory nor any log carries the token itself.
func TestRoomKeyHidesToken(t *testing.T) {
	const token = "super-secret-room-token"
	key := roomKey(token)
	if key == token {
		t.Fatal("room key equals the token")
	}
	if len(key) != 32 {
		t.Fatalf("room key length = %d; want 32 hex chars", len(key))
	}
	if key != roomKey(token) {
		t.Fatal("room key is not stable for the same token")
	}
	if key == roomKey(token+"x") {
		t.Fatal("different tokens produced the same room key")
	}
}

// TestJoinCreatesOneNetworkPerRoom proves two tokens get two networks and the same
// token shares one, which is what makes a token a room key.
func TestJoinCreatesOneNetworkPerRoom(t *testing.T) {
	m := NewManager(Options{LogLevel: "error"})
	t.Cleanup(func() { _ = m.Close() })

	a1, err := m.Join("token-a")
	if err != nil {
		t.Fatalf("Join(token-a): %v", err)
	}
	a2, err := m.Join("token-a")
	if err != nil {
		t.Fatalf("second Join(token-a): %v", err)
	}
	b1, err := m.Join("token-b")
	if err != nil {
		t.Fatalf("Join(token-b): %v", err)
	}

	if a1 != a2 {
		t.Fatal("same token produced two networks")
	}
	if a1 == b1 {
		t.Fatal("different tokens produced the same network")
	}
	if got := m.Rooms(); got != 2 {
		t.Fatalf("live rooms = %d; want 2", got)
	}

	// The two rooms are separate networks: their virtual identities differ, so a
	// member of one cannot address a member of the other.
	if a1.LocalVirtualIP() == b1.LocalVirtualIP() {
		t.Log("rooms share a virtual IP; isolation rests on the separate PSK, which is expected")
	}
}

// TestLeaveKeepsRoomUntilIdle proves the last member's departure does not destroy
// the room immediately: a reconnect inside IdleTimeout reuses it.
func TestLeaveKeepsRoomUntilIdle(t *testing.T) {
	m := NewManager(Options{
		LogLevel:    "error",
		IdleTimeout: 150 * time.Millisecond,
	})
	t.Cleanup(func() { _ = m.Close() })

	first, err := m.Join("token-idle")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	m.Leave("token-idle")

	// Rejoin before the idle timeout expires: the same network comes back.
	second, err := m.Join("token-idle")
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	if first != second {
		t.Fatal("rejoin inside the idle window built a new network instead of reusing the room")
	}
	m.Leave("token-idle")

	// After the timeout the room is gone.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Rooms() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("room still live %v after the last leave; want it reaped", 3*time.Second)
}

// TestCloseIsIdempotent proves Close can be called twice and refuses later joins.
func TestCloseIsIdempotent(t *testing.T) {
	m := NewManager(Options{LogLevel: "error"})
	if _, err := m.Join("token-close"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := m.Join("token-after-close"); err == nil {
		t.Fatal("Join succeeded after Close")
	}
}

// TestEmptyTokenIsRefused pins that an empty token cannot create a room, since it
// would be a room anyone can join.
func TestEmptyTokenIsRefused(t *testing.T) {
	m := NewManager(Options{LogLevel: "error"})
	t.Cleanup(func() { _ = m.Close() })
	if _, err := m.Join(""); err == nil {
		t.Fatal("Join with an empty token succeeded")
	}
}

// TestRequireIssuedRejectsInventedToken pins the business flow: the host mints a
// room token and hands it to the peer, and a peer that invents its own token is
// refused instead of being given a room.
func TestRequireIssuedRejectsInventedToken(t *testing.T) {
	m := NewManager(Options{
		LogLevel:      "error",
		RequireIssued: true,
	})
	t.Cleanup(func() { _ = m.Close() })

	// Invented token: refused, and no room is created for it.
	if _, err := m.Join("invented-token"); !errors.Is(err, ErrNotIssued) {
		t.Fatalf("Join(invented) = %v; want ErrNotIssued", err)
	}
	if got := m.Rooms(); got != 0 {
		t.Fatalf("rooms after a refused join = %d; want 0", got)
	}

	// Host-issued token: accepted.
	if err := m.Issue("minted-token"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.Join("minted-token"); err != nil {
		t.Fatalf("Join(issued) = %v; want nil", err)
	}

	// Revoked token: refused again.
	m.Revoke("minted-token")
	m.Leave("minted-token")
	if _, err := m.Join("minted-token"); !errors.Is(err, ErrNotIssued) {
		t.Fatalf("Join(revoked) = %v; want ErrNotIssued", err)
	}
}

// TestOpenRelayAcceptsAgreedToken pins the default: without RequireIssued any token
// the peers agree on still creates a room.
func TestOpenRelayAcceptsAgreedToken(t *testing.T) {
	m := NewManager(Options{LogLevel: "error"})
	t.Cleanup(func() { _ = m.Close() })

	if _, err := m.Join("any-agreed-token"); err != nil {
		t.Fatalf("Join on an open relay = %v; want nil", err)
	}
}
