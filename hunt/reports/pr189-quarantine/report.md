# DRAFT — hold until PR #189 merges

**Status: NOT yet reportable.** At shipped HEAD `89a542e` the sync quarantine is
keyed on `b.Hash` alone — that is the already-filed XE-6998 / XE-0098. This
finding only becomes a *live, shipped* bug (and first-to-report) the moment
PR #189 (`fix(net): bind sync quarantine keys to block signatures`) merges and
changes the quarantine key to `hash + ":" + signature`. File it against the
merge commit, not before.

Claimed tier: **Medium** (same class as XE-0098: sync-path suppression / eclipse,
no integrity break, needs a relay/sync-serving position).

---

## Title

net/sync: PR #189's signature-keyed quarantine does not stop poisoning — the
signature is public, so a copied-signature tampered block suppresses the genuine
block under an identical key (XE-0098 / XE-6998 still live after the fix)

## Summary

PR #189 changes the sync block quarantine key from the block's claimed `Hash`
to `Hash + ":" + Signature` (`blockQuarantineKey`, net/sync.go), intending to
stop an attacker from poisoning a genuine block's hash. But a block's signature
is **not secret**: it travels in the clear with every gossiped and synced copy
of the block. An attacker who has seen a genuine block H (any peer on the sync
or gossip path has) copies **both** its `Hash` and its `Signature` verbatim,
tampers an unrelated body field, and serves that. The sync client recomputes the
hash from the body, gets "hash mismatch" (non-retryable), and quarantines the
block under key `H:S` — byte-identical to the genuine block's key. Every later
genuine copy of H is then pre-filtered before `AddSyncedBlock`, from every peer.
The fix therefore does not change the outcome of XE-0098 / XE-6998 at all.

## Mechanism (code at PR #189 head `356a7df`)

- `net/sync.go` `blockQuarantineKey(b)` → `fmt.Sprintf("%s:%s", b.Hash, b.Signature)`
  for single-sig blocks (and `"%s:ms:%s"` over `b.Signatures[].Sig` for multisig).
  Both inputs are the **claimed** fields of the received block — attacker-controlled.
- `net/sync.go` requestSync: pre-filter `if quarantine.contains(blockQuarantineKey(b))`
  and, on a non-retryable rejection, `quarantine.add(blockQuarantineKey(b))`.
- `core/crypto.go` `VerifyBlock`: a body-tampered copy with claimed `Hash = H`
  fails `"hash mismatch: got H, want H''"`.
- `core/retryable.go`: the retryable set has no `"hash mismatch"` entry, so the
  rejection is non-retryable → the block is quarantined.
- Because the attacker copied S, `blockQuarantineKey(tampered) == blockQuarantineKey(genuine)`.

The PR's own test (`net/quarantine_poison_test.go`) only exercises an attacker
who uses a *random* bad signature (`"bad_signature_from_malicious_peer_1"`),
which is why it passes while the real attack still works: the attacker simply
reuses the genuine signature instead of inventing one.

## Impact

Persistent per-account sync suppression / eclipse of the victim, unchanged from
XE-0098. Worst for historical blocks, which are never re-gossiped: once the
genuine copy is pre-filtered on the sync path, nothing retries it. Suppression
only, not integrity. Entry lasts until FIFO eviction at 8,192 later entries or a
node restart (no TTL). Matches the Medium the desk already assigned to XE-0098.

## Simplest trigger

One unauthenticated peer serves the victim, during the victim's sync, a copy of
a real block with its `Hash` and `Signature` fields left exactly as the genuine
block and any one body field changed (e.g. `Balance`). No forging, no key, no
PoW work.

## Proof status

- **Verified in code** at PR #189 head `356a7df`: the key is built from the
  claimed public hash+signature; "hash mismatch" is non-retryable.
- **Run live (in-memory, real net+core packages, pr189 branch):**
  `net/quarantine_copysig_poison_test.go` (attached as `poc_copysig_test.go`)
  builds a genuine signed block, makes an attacker copy that reuses the genuine
  `Hash` and `Signature` with a tampered `Balance`, and shows:
  1. the tampered copy fails verification with a non-retryable error (so it is
     quarantined), and
  2. `blockQuarantineKey(tampered) == blockQuarantineKey(genuine)`, so the real
     `blockQuarantine` then reports the genuine block as quarantined.
  Command: `CGO_ENABLED=0 go test ./net/ -run TestQuarantineCopiedSignaturePoison -v`
  Result: PASS. The PR's own `TestBlockQuarantineSignatureKeying` also still
  passes, confirming the two tests cover different threat models.
- **NOT proven live:** a two-node libp2p end-to-end sync (the unit proof uses the
  real requestSync helpers and the real quarantine, but drives them directly
  rather than over a socket). The code path from a non-retryable sync rejection
  to `quarantine.add` is read from net/sync.go, not exercised over a wire.

## Suggested fix

Key the quarantine on a value the attacker cannot make collide with a genuine
block: the recomputed `HashBlock(b)` of the *body actually received* (not the
claimed `Hash`), or do not quarantine on hash-mismatch at all (a hash-mismatch
block is self-identifying and cheap to re-reject; it need not censor a key).
Binding to the signature is ineffective because the signature is public.
