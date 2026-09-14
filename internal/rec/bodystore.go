// internal/rec/bodystore.go
//
// =============================================================================
// Refcounted body store (Part 3 - flood survivability)
// =============================================================================
//
// The flood stored ~thousands of copies of the same 858-byte fault body.
// This store shares body storage across ring entries and VIP copies while
// every response keeps its individual identity (timestamps, pairing
// metadata, status, CaptureID, flags). Interning is INVISIBLE to correlation
// semantics (Invariant 6): clone equality stays keyed on BodyPreviewHash
// string comparison, and nothing may consult reference equality - identical
// storage must never imply transaction equality, because identical request
// shapes can have different outcomes.
//
// Concurrency: the store has NO lock of its own. Every method MUST be called
// with the owning RingBuffer's rb.mu held; the collector's VIP paths go
// through rb.reacquire/rb.releaseBody, which take rb.mu (lock order
// vipMu → rb.mu, same as the pre-existing PrePin path).
//
// Byte accounting: a shared body's byteCharge (raw preview + intern-table
// overhead) is charged ONCE to the Part 2 byte budget when the body is first
// interned and released on the LAST owner's release. Ring eviction never
// frees or uncharges a body still held by VIP storage.

package rec

import (
	"crypto/sha256"
	"encoding/binary"
)

// bodyStoreOverheadBytes approximates per-unique-body intern-table cost: the
// map entry, the internedBody struct, the 32-byte key, and the disclosure
// analysis computed at intern time. Approximate, directionally honest.
const bodyStoreOverheadBytes = 256

// internedBody is one shared body: the raw truncated preview plus the
// disclosure analysis computed ONCE at intern time.
type internedBody struct {
	key [sha256.Size]byte // storage fingerprint - INTERNAL ONLY (see bodyStoreKey)

	rawPreview  []byte
	contentType string
	complete    bool

	// disclosure is computed exactly once, at intern time, by
	// classifyAndRedact, and is IMMUTABLE thereafter. Consumers copy the
	// struct value out (see disclosureForEntry) - re-running redaction on
	// captured input is forbidden: it could change counts and accidentally
	// unlock the Lane A durable cache.
	disclosure *DisclosureAnalysis

	refcount   int
	byteCharge int64
}

// bodyStoreKey computes the storage fingerprint: SHA-256 over the raw
// truncated preview bytes, content type, completeness flag, and the
// redactor version (each length-delimited so field boundaries are
// unambiguous).
//
// INTERNAL ONLY: this is a new, distinct hash. It must never be exposed as,
// compared with, or substituted for BodyPreviewHash, the redacted verdict
// hash, or any event identity - it exists solely to deduplicate storage.
func bodyStoreKey(preview []byte, contentType string, complete bool, version int) [sha256.Size]byte {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(preview)))
	h.Write(n[:])
	h.Write(preview)
	binary.BigEndian.PutUint64(n[:], uint64(len(contentType)))
	h.Write(n[:])
	h.Write([]byte(contentType))
	if complete {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	binary.BigEndian.PutUint64(n[:], uint64(version))
	h.Write(n[:])

	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

// bodyStore holds the interned bodies. Guarded entirely by the owning
// RingBuffer's rb.mu - see the package comment above.
type bodyStore struct {
	byKey map[[sha256.Size]byte]*internedBody

	// redactionsRun counts classifyAndRedact invocations performed at
	// intern time. Telemetry/white-box only: repeated Lookups of the same
	// interned body must never grow it (disclosure immutability).
	redactionsRun int64
}

func newBodyStore() *bodyStore {
	return &bodyStore{byKey: make(map[[sha256.Size]byte]*internedBody)}
}

// intern returns the shared body for (preview, contentType, complete),
// creating and classifying it on first sight. retain()-equivalent: the
// caller owns one reference on return. addedBytes is the byte charge newly
// added to the budget (0 on an intern hit - floods of identical bodies
// redact once and charge once).
func (bs *bodyStore) intern(preview []byte, contentType string, complete bool) (b *internedBody, addedBytes int64) {
	key := bodyStoreKey(preview, contentType, complete, redactorVersion)
	if existing, ok := bs.byKey[key]; ok {
		existing.refcount++
		return existing, 0
	}
	bs.redactionsRun++
	disclosure := classifyAndRedact(preview, contentType, complete)
	b = &internedBody{
		key:         key,
		rawPreview:  preview,
		contentType: contentType,
		complete:    complete,
		disclosure:  disclosure,
		refcount:    1,
		// FIX 2c: charge the ACTUAL retained allocations - the raw preview
		// AND the redacted preview the analysis retains - plus table
		// overhead. Worst-case admission estimates use
		// redactorMaxOutputBytes instead (an output cap, not MaxBodyBytes).
		byteCharge: int64(len(preview)) + int64(len(disclosure.RedactedPreview())) + bodyStoreOverheadBytes,
	}
	bs.byKey[key] = b
	return b, b.byteCharge
}

// resurrect re-inserts a fully-released body object into the store on behalf
// of a copy that still references it (the FIX 1 reacquire path). The object's
// immutable disclosure analysis is reused - redaction is never re-run on
// captured input - and its byteCharge is returned for the caller to charge.
// The caller (reacquire) has already performed budget admission. Along with
// intern/retain/release, this is one of the only places refcounts change.
func (bs *bodyStore) resurrect(b *internedBody) (chargedBytes int64) {
	if b.refcount != 0 {
		panic("rec: resurrect of a live interned body")
	}
	if _, exists := bs.byKey[b.key]; exists {
		panic("rec: resurrect would shadow a live body under the same key")
	}
	b.refcount = 1
	bs.byKey[b.key] = b
	return b.byteCharge
}

// retain adds one reference. The ONLY places refcounts change are intern,
// retain, and release - every copy that outlives its ring slot (VIP) must
// hold its own reference.
func (bs *bodyStore) retain(b *internedBody) {
	if b.refcount <= 0 {
		panic("rec: retain of released interned body")
	}
	b.refcount++
}

// release drops one reference. On the last release the body leaves the
// store and its byte charge is returned so the caller can uncharge the
// budget (0 while other owners remain). Double-release panics - an
// accounting bug must be loud, not a silently corrupted budget.
func (bs *bodyStore) release(b *internedBody) (freedBytes int64) {
	if b.refcount <= 0 {
		panic("rec: double release of interned body")
	}
	b.refcount--
	if b.refcount == 0 {
		delete(bs.byKey, b.key)
		return b.byteCharge
	}
	return 0
}
