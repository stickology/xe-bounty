## Summary

This is a pre-merge fix-bypass report for **PR #189** ("fix(net): bind sync
quarantine keys to block signatures to prevent poisoning"), the proposed patch
for XE-0098 / XE-6998. The patch does not stop the poisoning.

PR #189 changes the sync block-quarantine key from the claimed `Hash` to
`Hash + ":" + Signature` (`blockQuarantineKey`, net/sync.go). The intent is that
an attacker cannot make a poison entry collide with a genuine block. But a
block's signature is **not secret**: it travels in the clear with every gossiped
and synced copy of the block. An attacker who has seen a genuine block H (any
peer on the sync or gossip path has) copies **both** its `Hash` and its
`Signature` verbatim, tampers one unrelated body field, and serves that. The
sync client recomputes the hash from the body, gets a non-retryable "hash
mismatch", and quarantines the block under key `H:S` — byte-identical to the
genuine block's key. Every later genuine copy of H is then pre-filtered before
`AddSyncedBlock`, from every peer. The outcome is identical to XE-0098 / XE-6998;
the fix changes nothing.

## Mechanism (PR #189 head 356a7df)

- `net/sync.go` `blockQuarantineKey(b)` returns `fmt.Sprintf("%s:%s", b.Hash,
  b.Signature)` for single-sig blocks (and `"%s:ms:%s"` over `b.Signatures[].Sig`
  for multisig). Both inputs are the **claimed** fields of the received block, so
  both are attacker-controlled and both are copyable from the genuine block.
- `net/sync.go` requestSync: pre-filter `quarantine.contains(blockQuarantineKey(b))`;
  on a non-retryable rejection, `quarantine.add(blockQuarantineKey(b))`.
- `core/crypto.go` `VerifyBlock`: a body-tampered copy whose `Hash` field is left
  = H fails with `"hash mismatch: got H, want H''"`.
- `core/retryable.go`: the retryable set has no `"hash mismatch"` entry, so that
  rejection is non-retryable → the block is quarantined.
- Because the attacker copied S, `blockQuarantineKey(tampered)` ==
  `blockQuarantineKey(genuine)`.

The PR's own test (`net/quarantine_poison_test.go`) only exercises an attacker
who invents a *random* bad signature ("bad_signature_from_malicious_peer_1"),
which is why it passes while the real attack still works: the attacker reuses the
genuine signature instead of inventing one.

## Impact

Persistent per-account sync suppression / eclipse of the victim, unchanged from
XE-0098. Worst for historical blocks, which are never re-gossiped: once the
genuine copy is pre-filtered on the sync path, nothing retries it. Suppression
only, not integrity. The entry lasts until FIFO eviction at 8,192 later entries
or a node restart (no TTL). Same class and severity the desk assigned to XE-0098
(Medium).

## Simplest trigger

One unauthenticated peer serves the victim, during the victim's sync, a copy of a
real block with its `Hash` and `Signature` fields left exactly as the genuine
block and any one body field changed (e.g. `Balance`). No forging, no key, no PoW.

## Proof

Verified in code at PR #189 head 356a7df, and run live in-memory against the real
net+core packages on the pr189 branch. The attached Go test
(`poc_copysig_test.go`, drop into package `net`):

1. builds a genuine signed block (real ed25519 key),
2. makes an attacker copy that reuses the genuine `Hash` and `Signature` with a
   tampered `Balance`,
3. shows the copy fails verification with a non-retryable error (so it is
   quarantined), and
4. shows `blockQuarantineKey(tampered) == blockQuarantineKey(genuine)`, so the
   real `blockQuarantine` then reports the genuine block as quarantined.

Command (on pr189 branch 356a7df):
`CGO_ENABLED=0 go test ./net/ -run TestQuarantineCopiedSignaturePoison -v` → PASS.
The PR's own `TestBlockQuarantineSignatureKeying` also still passes — the two
tests cover different threat models (random bad sig vs copied genuine sig).

Not proven live: a two-node libp2p sync over a socket. The proof drives the real
`blockQuarantineKey`, `blockQuarantine` and `VerifyBlock`/`isRetryableError`
directly; the step from a non-retryable sync rejection to `quarantine.add` is
read from net/sync.go, not exercised over the wire.

## Suggested fix

Key the quarantine on something the attacker cannot make collide with a genuine
block: the server-recomputed `HashBlock(body)` of the body actually received
(not the claimed `Hash`), or simply do not quarantine on a hash-mismatch at all —
such a block is self-identifying and cheap to re-reject, so it need not censor a
key. Binding to the signature is ineffective because the signature is public and
ships with the block.

## Not a duplicate

No existing ticket covers the signature-keyed quarantine or an incomplete PR #189
(searched the board for "signature keying", "blockQuarantineKey", "copied
signature" — 0 results). XE-0098 / XE-6998 report the original hash-keyed
poisoning; this report shows their proposed patch does not fix it.
