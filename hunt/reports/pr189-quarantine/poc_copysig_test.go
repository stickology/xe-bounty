package net

import (
	"testing"

	"github.com/xeprotocol/xe/core"
)

// TestQuarantineCopiedSignaturePoison demonstrates that PR #189's
// signature-keyed quarantine (blockQuarantineKey = hash + ":" + signature)
// does NOT stop quarantine poisoning: the signature is public and travels
// with every copy of a block, so an attacker copies BOTH the genuine hash
// and the genuine signature, tampers the body, and the genuine block is
// suppressed under the identical key — exactly the XE-6998 / XE-0098 attack.
func TestQuarantineCopiedSignaturePoison(t *testing.T) {
	core.SetNetworkID("testnet-0005")

	// A genuine, fully signed first (open) send block from a real key.
	kp := core.KeyPairFromSeed(make([]byte, 32)) // deterministic seed
	dstKp := core.KeyPairFromSeed(append(make([]byte, 31), 1))

	genuine := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    "0",
		Balance:     900,
		Timestamp:   1,
		Asset:       "XE",
		Destination: dstKp.Address(),
		Amount:      100,
	}
	core.MustSignBlock(genuine, kp) // sets genuine.Hash (H) and genuine.Signature (S)

	if err := core.VerifyBlock(genuine); err != nil {
		t.Fatalf("genuine block should verify, got: %v", err)
	}
	H := genuine.Hash
	S := genuine.Signature

	// Attacker's tampered copy: SAME claimed Hash H, SAME signature S
	// (both copied verbatim — they are not secret), but a different body
	// field (Balance). The attacker does not need to forge anything.
	attacker := *genuine
	attacker.Balance = 999 // body tampered; Hash/Signature fields left = H/S

	// 1) The tampered copy triggers a non-retryable rejection, so the sync
	//    client quarantines it (net/sync.go requestSync path).
	verr := core.VerifyBlock(&attacker)
	if verr == nil {
		t.Fatalf("tampered copy must fail verification")
	}
	if isRetryableError(verr) {
		t.Fatalf("hash mismatch must be non-retryable (so it is quarantined), got retryable: %v", verr)
	}

	// 2) The key the fix quarantines the tampered copy under...
	poisonKey := blockQuarantineKey(&attacker)
	// ...is byte-identical to the genuine block's key, because the fix keys
	//    on the claimed (public, attacker-copied) hash+signature.
	genuineKey := blockQuarantineKey(genuine)

	if poisonKey != genuineKey {
		t.Fatalf("expected identical keys (copied sig), poison=%q genuine=%q", poisonKey, genuineKey)
	}

	// 3) End-to-end: feed the tampered copy to the real quarantine, then
	//    check whether the genuine block would be pre-filtered on sync.
	q := newBlockQuarantine()
	q.add(poisonKey) // what requestSync does on the non-retryable rejection
	if !q.contains(genuineKey) {
		t.Fatalf("genuine block NOT suppressed — fix would be effective")
	}

	t.Logf("POISONED: hash=%s", H)
	t.Logf("genuine signature S copied verbatim by attacker: %s", S[:16]+"...")
	t.Logf("quarantine key (genuine == attacker): %s", poisonKey)
	t.Logf("=> genuine block is pre-filtered from every peer; PR #189 fix bypassed")
}
