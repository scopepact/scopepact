package scopepact

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type sharedVector struct {
	SenderSeedHex      string `json:"sender_seed_hex"`
	SenderPublicKeyHex string `json:"sender_public_key_hex"`
	TranscriptHex      string `json:"transcript_hex"`
	Frame              struct {
		Envelope  Envelope `json:"envelope"`
		Signature string   `json:"signature"`
	} `json:"frame"`
}

func loadVector(t *testing.T) sharedVector {
	t.Helper()
	encoded, err := os.ReadFile("../../conformance/vectors/envelope-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector sharedVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestSharedTranscript(t *testing.T) {
	vector := loadVector(t)
	transcript, err := vector.Frame.Envelope.SigningTranscript()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(transcript); got != vector.TranscriptHex {
		t.Fatalf("transcript mismatch\nwant: %s\n got: %s", vector.TranscriptHex, got)
	}
}

func TestSharedSignatureAndLocalSigning(t *testing.T) {
	vector := loadVector(t)
	seed := mustHex(t, vector.SenderSeedHex)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(publicKey); got != vector.SenderPublicKeyHex {
		t.Fatalf("public key mismatch: %s", got)
	}

	signature, err := Sign(vector.Frame.Envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(signature); got != vector.Frame.Signature {
		t.Fatalf("signature mismatch: %s", got)
	}
	valid, err := Verify(vector.Frame.Envelope, signature, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("shared signature did not verify")
	}
}

func TestAuthenticatedMutationIsRejected(t *testing.T) {
	vector := loadVector(t)
	publicKey := ed25519.PublicKey(mustHex(t, vector.SenderPublicKeyHex))
	altered := vector.Frame.Envelope
	altered.PolicyEpoch++
	valid, err := Verify(altered, mustHex(t, vector.Frame.Signature), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("signature verified after policy epoch mutation")
	}
}
