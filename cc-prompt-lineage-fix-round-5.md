# Claude Code prompt — request lineage FIX ROUND 5: one lifecycle, not another patch

Repo: observer, base = commit 504770f on main (the lineage work is now committed). Files in the repo root: `REVIEW.md` (round-4 adversarial review — read fully; its "Requested next implementation pass" section is the assignment) and `lineage_round4_additional_test.go` (four reproducing tests using the existing review-test helpers). Hand back uncommitted on top of 504770f.

Acceptance: all four TestRound4* PASS, plus every existing TestReview*/TestRound2*/TestRealPath* and the full suite. The TestRound4 tests are behavioral spec; if the ownership model changes their private mechanics, adapt the mechanics and preserve the assertions (reviewer's standing license). Adopt them permanently as `httpoutcomesink_round4_test.go` with an attributing header, then remove the root original.

## The assignment (verbatim intent from the review)

Define ONE coherent lifecycle for an accepted observation — ownership of pending notification, lineage-scoped attempt reservation/result, representative/independent/drop decision, detached write completion, and shutdown join — then implement and test that lifecycle. Stop trading directive-level patches. Callbacks that can block stay outside the global state owner, but never lose identity, ordering, result propagation, or shutdown accounting.

## Required design (decisions made — implement these)

**1. Per-lineage notification state machine (tracker-owned).** States: Idle → InFlight(attemptToken, sev, eventID) → Succeeded(notifiedSev). Rules:
- Fire is issued only from Idle (or from Succeeded as Upgrade when sev > notifiedSev). Issuing transitions to InFlight and mints a token.
- An eligible sibling arriving while InFlight does NOT get a directive; it registers as a pending-eligible waiter (highest severity retained).
- NotifyResult(token, ok): stale tokens ignored. ok ⇒ Succeeded(sev), waiter cleared if now covered. fail ⇒ Idle, and NotifyResult RETURNS directives — if an eligible waiter is queued, a fresh Fire/Upgrade for it (new token). The sink applies directives returned by NotifyResult like any others.
- Tombstones carry the same state (already have notified/notifiedSev; add InFlight awareness so a late sibling during an in-flight attempt waits rather than double-firing). Unanchored/poisoned independents keep their independent notifications — no cross-lineage serialization anywhere.
- Gate: TestRound4ConcurrentSiblingsNotifyOnce (one successful attempt), TestRound2FailedNotifyRetriesAfterSettle (retry still works), TestReviewFailedNotifyMustNotSuppressSibling.

**2. Detached-work registry = the single completion authority.** Every callback execution — Emit-applied, Tick-applied, drain-applied, NotifyResult-returned — is REGISTERED under the sink lock in the same critical section that created its directive (no gap between selection and registration), executed outside the lock, and marked complete. Terminal claim (parked-entry delete) transfers the work into the registry rather than discarding anything: a pending notify directive whose parked entry is claimed by settlement is still owned, still executes, still reports its result. Gate: TestRound4PendingNotifySurvivesTick.

**3. Representative writes wait for in-flight notification truth.** At settle/flush, if the lineage's notification state is InFlight, the representative's writeFinding is NOT executed with a guessed flag: it is parked in the registry keyed to the attempt and executed when NotifyResult lands, with the true outcome. (Bounded: callbacks complete; drain still suppresses NEW attempts but must wait out in-flight ones.) Gate: TestRound4NotifiedReflectsInFlightResult.

**4. Shutdown joins everything.** `inflight` accounting is replaced by the registry: Shutdown = stop admissions (closed), drain tracker (FlushAll, no fresh Fire directives, in-flight attempts awaited per #3), then wait until the registry is EMPTY — which by construction covers Emit-applied, Tick-applied, and drain-applied work — and JOIN the Run loop (Run signals exit; Shutdown waits on it) before returning. main.go closes the writer/DB only after Shutdown returns. Gate: TestRound4ShutdownJoinsTickWrites, TestRound2ShutdownWaitsForAcceptedLateEmit, TestReviewShutdownMustPersist.

**5. D8 amendment, stated not smuggled.** The enabled-but-no-ID path may take the sink lock ONLY for admission/registry accounting (constant work, no tracker, no group allocation). Amend the D8 comment block in the sink and the README's pass-through claim to say exactly that. Feature-off remains fully lock-free.

**6. Housekeeping in this changeset:** `git rm 'REVIEW.md:Zone.Identifier'` (a Windows metadata stray got committed in 504770f).

## Verification + handback

Full battery (build, gofmt, vet, `go test ./... -count=1`; attempt `CGO_ENABLED=1 go test -race` and state plainly if the environment can't — Drew's WSL covers it). Concurrency tests run 50× consecutively. Handback uncommitted: the lifecycle described as a state diagram in prose, per-gate test results, which prior tests changed and why, LOC delta, weakest-point self-assessment. No commit, no release.sh, no version bump.
