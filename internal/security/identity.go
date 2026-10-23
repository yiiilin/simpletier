package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

var ErrInvalidIdentity = errors.New("invalid identity")

// Identity is an in-memory X25519 key and its stable 16-byte NodeID.
type Identity struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  [32]byte
	NodeID     [16]byte
}

// GenerateIdentity creates a fresh X25519 keypair using the system CSPRNG.
func GenerateIdentity() (Identity, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate X25519 identity: %w", err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	nodeID, err := nodeIDFromPublicKey(publicKey)
	if err != nil {
		return Identity{}, err
	}
	var public [32]byte
	copy(public[:], publicKey)
	return Identity{PrivateKey: privateKey, PublicKey: public, NodeID: nodeID}, nil
}

func nodeIDFromPublicKey(publicKey []byte) ([16]byte, error) {
	var nodeID [16]byte
	if len(publicKey) != 32 {
		return nodeID, fmt.Errorf("X25519 public key length %d: %w", len(publicKey), ErrInvalidIdentity)
	}
	digest := sha256.Sum256(publicKey)
	copy(nodeID[:], digest[:16])
	return nodeID, nil
}

// identityFromPrivateKey rebuilds an Identity from a 32-byte X25519 private key.
// It exists so a test can pin a deterministic NodeID; production paths generate
// their key with GenerateIdentity.
func identityFromPrivateKey(raw []byte) (Identity, error) {
	if len(raw) != 32 {
		return Identity{}, fmt.Errorf("X25519 private key length %d: %w", len(raw), ErrInvalidIdentity)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return Identity{}, fmt.Errorf("load X25519 identity: %w", err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	nodeID, err := nodeIDFromPublicKey(publicKey)
	if err != nil {
		return Identity{}, err
	}
	var public [32]byte
	copy(public[:], publicKey)
	return Identity{PrivateKey: privateKey, PublicKey: public, NodeID: nodeID}, nil
}
