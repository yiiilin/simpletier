package security

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestGenerateIdentityDerivesNodeIDFromX25519Key(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	if len(identity.PrivateKey.Bytes()) != 32 || len(identity.PublicKey) != 32 {
		t.Fatalf("key lengths = %d/%d; want 32/32", len(identity.PrivateKey.Bytes()), len(identity.PublicKey))
	}
	derivedPublic, err := ecdh.X25519().NewPrivateKey(identity.PrivateKey.Bytes())
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	if !bytes.Equal(derivedPublic.PublicKey().Bytes(), identity.PublicKey[:]) {
		t.Fatal("public key does not match the private key")
	}
	digest := sha256.Sum256(identity.PublicKey[:])
	if !bytes.Equal(identity.NodeID[:], digest[:16]) {
		t.Fatalf("NodeID = %x; want first 16 SHA-256 bytes %x", identity.NodeID, digest[:16])
	}
}

func TestGenerateIdentityProducesFreshKeys(t *testing.T) {
	first, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.PublicKey[:], second.PublicKey[:]) {
		t.Fatal("two generated identities reused a public key")
	}
}

func TestNodeIDFromPublicKeyRequiresX25519KeyLength(t *testing.T) {
	if _, err := nodeIDFromPublicKey(make([]byte, 31)); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("nodeIDFromPublicKey(short) error = %v; want ErrInvalidIdentity", err)
	}
	if _, err := nodeIDFromPublicKey(make([]byte, 33)); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("nodeIDFromPublicKey(long) error = %v; want ErrInvalidIdentity", err)
	}
}
