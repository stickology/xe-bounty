# XE bounty hunt state

last_audited_commit: 89a542ea51d38375299aee54c6c99102e9bfa666
target_repo: https://github.com/xeprotocol/xe (default branch)
board: https://bounty.xe.network (API: /v1/tickets?kind=bounty&status=all&limit=100&offset=N)

## Already-checked candidates at 89a542e (all duplicates, do not report)
- Marketplace offer hijack / no offer-vs-request check: XE-0106, XE-7695, XE-12199, XE-13042, XE-13372
- Messenger 64 KiB response cap: XE-0436, XE-13238
- certsync goroutine per connection: XE-5430
- PullBlocks/PullVotes pre-checks: XE-13226
- Quorum withhold (89a542e): XE-4145, XE-5062, XE-13528
- Rep allowlist fail-open: XE-2862, XE-5667
- SpendableBalances: XE-13663, XE-2375
- lease_renew attestation/cert/LockedR: XE-0010, XE-0085, XE-10904, XE-13248, XE-8377
- VM hostfwd 0.0.0.0 / GPU FLR / SLIRP / template injection: XE-1438, XE-6783, XE-11315

## Deep sweep at 89a542e (session 2) — all shipped-code candidates are duplicates
- Badger key layout / vote hex case / composite keys: XE-7696, XE-9117, XE-2862 class
- Canonical-encoding non-injectivity (Asset 8-byte pad, Previous/AccessPubKey/Representative zero): XE-6855, XE-11466, XE-0060
- Sync quarantine keyed on hash: XE-6998, XE-0098 (fix proposed in PR #189, unmerged)
- isRetryableError misclassification: XE-8699, XE-10240
- Rep allowlist / spendable: XE-2862, XE-13663

## HELD FINDING (not a shipped bug yet) — file on PR #189 merge
- Candidate: PR #189 signature-keyed quarantine is an INCOMPLETE FIX. Key = hash+":"+signature,
  but signature is public and travels with the block. Attacker copies genuine hash+signature,
  tampers a body field -> same quarantine key -> genuine block suppressed (XE-0098/XE-6998 still live).
- Proof: hunt/reports/pr189-quarantine/ (report.md + poc_copysig_test.go). Test PASSES against
  pr189 branch (356a7df): go test ./net/ -run TestQuarantineCopiedSignaturePoison -v.
- Dedup: board has NO ticket on signature-keyed quarantine / incomplete #189 (searched
  signature+keying, blockQuarantineKey, copied+signature -> 0 results, 2026-11-15).
- ACTION: when xeprotocol/xe default branch merges PR #189 (quarantine key becomes hash:signature),
  this is live first-to-report. Claimed tier Medium (match XE-0098). User files privately from own browser.

## Open-PR fix-bypass audit (session 2, 2026-11-15) — no bypass found
- PR #564 (DecodeVote panic, XE-13401): COMPLETE — len(data) bound check present before copy.
- PR #556 (gossip multisig delivery + reject invalid): reasonable, no gap.
- PR #554 (tunnel consumer auth, XE-13200/13246): COMPLETE — peerID bound to PeerForAccount(consumer), fail-closed.
- PR #534 (reject phantom votes, XE-532): reasonable; early votes now rejected not buffered (liveness tradeoff, not a bug).
- PR #553 (keyset case normalization, XE-13193/13390): covers dao_keyset/oracle/minter/timekeepers + verification.
- Only clean finding this whole hunt: PR #189 incomplete fix => SUBMITTED as ticket XE-14009 (private) by user, 2026-11-15. DO NOT re-file.
