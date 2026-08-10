// Package scopepact implements the portable ScopePact v0 envelope transcript.
package scopepact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

const envelopeDomain = "SCOPEPACT-ENVELOPE-V0\x00"

// Envelope contains every field authenticated by a ScopePact v0 signature.
type Envelope struct {
	ProtocolMajor      uint16   `json:"protocol_major"`
	ProtocolMinor      uint16   `json:"protocol_minor"`
	Session            string   `json:"session"`
	Interaction        *string  `json:"interaction"`
	Sequence           uint64   `json:"sequence"`
	Nonce              string   `json:"nonce"`
	IssuedAtMS         int64    `json:"issued_at_ms"`
	ExpiresAtMS        int64    `json:"expires_at_ms"`
	Sender             string   `json:"sender"`
	Audience           string   `json:"audience"`
	PolicyEpoch        uint64   `json:"policy_epoch"`
	MessageKind        uint16   `json:"message_kind"`
	PayloadSchema      string   `json:"payload_schema"`
	PayloadDigest      string   `json:"payload_digest"`
	CriticalExtensions []string `json:"critical_extensions"`
}

// SigningTranscript returns the exact domain-separated bytes signed by v0.
func (e Envelope) SigningTranscript() ([]byte, error) {
	session, err := decodeHex(e.Session, 16, "session")
	if err != nil {
		return nil, err
	}
	nonce, err := decodeHex(e.Nonce, 16, "nonce")
	if err != nil {
		return nil, err
	}
	sender, err := decodeHex(e.Sender, 32, "sender")
	if err != nil {
		return nil, err
	}
	audience, err := decodeHex(e.Audience, 32, "audience")
	if err != nil {
		return nil, err
	}
	schema, err := decodeHex(e.PayloadSchema, 32, "payload_schema")
	if err != nil {
		return nil, err
	}
	digest, err := decodeHex(e.PayloadDigest, 32, "payload_digest")
	if err != nil {
		return nil, err
	}

	var transcript bytes.Buffer
	transcript.WriteString(envelopeDomain)
	writeUint16(&transcript, e.ProtocolMajor)
	writeUint16(&transcript, e.ProtocolMinor)
	writeBytes(&transcript, session)
	if e.Interaction == nil {
		transcript.WriteByte(0)
	} else {
		interaction, err := decodeHex(*e.Interaction, 16, "interaction")
		if err != nil {
			return nil, err
		}
		transcript.WriteByte(1)
		writeBytes(&transcript, interaction)
	}
	writeUint64(&transcript, e.Sequence)
	writeBytes(&transcript, nonce)
	writeUint64(&transcript, uint64(e.IssuedAtMS))
	writeUint64(&transcript, uint64(e.ExpiresAtMS))
	writeBytes(&transcript, sender)
	writeBytes(&transcript, audience)
	writeUint64(&transcript, e.PolicyEpoch)
	writeUint16(&transcript, e.MessageKind)
	writeBytes(&transcript, schema)
	writeBytes(&transcript, digest)
	if uint64(len(e.CriticalExtensions)) > math.MaxUint32 {
		return nil, fmt.Errorf("too many critical extensions")
	}
	writeUint32(&transcript, uint32(len(e.CriticalExtensions)))
	for _, extension := range e.CriticalExtensions {
		if uint64(len(extension)) > math.MaxUint32 {
			return nil, fmt.Errorf("critical extension is too large")
		}
		writeBytes(&transcript, []byte(extension))
	}
	return transcript.Bytes(), nil
}

// Sign signs an envelope using an RFC 8032 Ed25519 private key.
func Sign(envelope Envelope, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must contain %d bytes", ed25519.PrivateKeySize)
	}
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privateKey, transcript), nil
}

// Verify checks an envelope signature using an RFC 8032 Ed25519 public key.
func Verify(envelope Envelope, signature []byte, publicKey ed25519.PublicKey) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key must contain %d bytes", ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return false, nil
	}
	transcript, err := envelope.SigningTranscript()
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, transcript, signature), nil
}

// KeyID returns the SHA-256 identity used to bind a raw Ed25519 public key.
func KeyID(publicKey ed25519.PublicKey) ([sha256.Size]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return [sha256.Size]byte{}, fmt.Errorf(
			"public key must contain %d bytes", ed25519.PublicKeySize,
		)
	}
	return sha256.Sum256(publicKey), nil
}

func decodeHex(value string, expected int, field string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != expected || hex.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be lowercase hexadecimal containing %d bytes", field, expected)
	}
	return decoded, nil
}

func writeBytes(output *bytes.Buffer, value []byte) {
	writeUint32(output, uint32(len(value)))
	output.Write(value)
}

func writeUint16(output *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	output.Write(encoded[:])
}

func writeUint32(output *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	output.Write(encoded[:])
}

func writeUint64(output *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	output.Write(encoded[:])
}
