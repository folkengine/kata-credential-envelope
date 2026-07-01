//! # Credential Envelope kata — selective disclosure & the two-hash boundary
//!
//! You are standing in for the **substrate**: a fact has already been produced
//! by a pure domain kernel (here, just four plain strings — "musician M001
//! plays Cello for orchestra RSO, assigned to concert C01"), and your job is to
//! turn it into a verifiable credential that supports *holder-driven selective
//! disclosure*.
//!
//! The tool is a real [Gordian Envelope](https://www.blockchaincommons.com):
//! a tree of subject–predicate–object triples with a built-in digest tree. Its
//! defining trick is **elision** — replacing any subtree with its digest leaves
//! every ancestor digest (and any signature over the root) unchanged. So an
//! issuer signs a credential once; a holder later strips it to just the fields
//! a verifier needs, and the original signature still verifies.
//!
//! ## The two hashes (this is the whole point)
//!
//! | Digest        | Hash    | Computed over              | Answers                          |
//! |---------------|---------|----------------------------|----------------------------------|
//! | CAS address   | BLAKE3  | the envelope's dCBOR bytes | *where this exact blob lives*    |
//! | Envelope root | SHA-256 | the envelope's digest tree | *the seal that survives elision* |
//!
//! Eliding a subtree **rewrites the serialized bytes** (so the BLAKE3 CAS
//! address changes) but **leaves the SHA-256 root invariant** (so the issuer
//! signature still verifies). One credential therefore has *one seal* but *many
//! addresses* — the full disclosure and each elided projection are distinct CAS
//! blobs sharing one root. That is the boundary you will reconstruct and prove.
//!
//! ## Your task
//!
//! Work the seven steps in `README.md`, one at a time. Each step is a single
//! small change to one function below, and each turns exactly one more test in
//! `tests/two_hash.rs` green. Do the change, run just that one test, watch it
//! pass, move on. The `Step N` tags below tell you which function each step
//! touches; don't jump ahead.

use bc_components::SigningPrivateKey;
use bc_envelope::prelude::*;

/// **Steps 1 & 2** · Build the **salted, unsigned** credential envelope for an
/// assignment attestation.
///
/// Structure it as a Gordian Envelope:
/// - **subject:** the `musician` id
/// - **assertion:** `"assignedTo"` → `concert`
/// - **assertion:** `"orchestra"` → `orchestra`
/// - **assertion:** `"instrument"` → `instrument`
///
/// **Step 1** is just getting those three assertions in place (test:
/// `credential_has_three_assertions`).
///
/// **Step 2** is salting them. Every object here is *low-entropy* — a short id
/// or a constrained vocabulary whose whole value space could be enumerated.
/// Such fields MUST be **salted** at issuance: without salt, a verifier could
/// later brute-force an *elided* field by hashing candidate values until one
/// matches the leftover digest. Salt makes the privacy property structural
/// instead of hoped-for (test: `low_entropy_fields_are_salted`).
pub fn build_credential(
    musician: &str,
    concert: &str,
    orchestra: &str,
    instrument: &str,
) -> Envelope {
    todo!("Step 1: musician as subject + three assertions. Step 2: salt them.")
}

/// **Step 3** · Issue the credential by **wrapping it, then signing** with the
/// issuer's key (test: `signature_verifies_on_full_disclosure`).
///
/// Order matters: wrapping first means the signature covers the *entire*
/// credential as one wrapped-root digest, so it keeps verifying after a holder
/// later elides an inner field. (Signing the bare subject instead would only
/// attest the subject, not the assertions.)
pub fn issue(credential: &Envelope, issuer: &SigningPrivateKey) -> Envelope {
    todo!("Step 3: wrap the credential, then add the issuer's signature")
}

/// **Step 7** · The **CAS address**: a BLAKE3 hash over the envelope's dCBOR
/// serialization (test: `elision_changes_the_cas_address`).
///
/// This answers *where this exact blob lives*. It is computed over the
/// serialized bytes, so it changes whenever those bytes change — including
/// after elision.
pub fn cas_address(envelope: &Envelope) -> [u8; 32] {
    todo!("Step 7: BLAKE3 over the envelope's tagged-CBOR bytes")
}

/// **Step 4** · Holder-side **elision**: return a disclosure of `signed` with
/// the `"assignedTo"` (concert) assertion removed — proving the rest of the
/// credential without revealing *which* concert.
///
/// Elision works by digest: you locate the assertion to remove (its digest is
/// identical wherever that subtree appears, so take it from the original
/// unsigned `credential`) and tell the signed envelope to elide that target.
///
/// This one function is the payoff: implementing it turns on **three** tests at
/// once (steps 4, 5, 6) — `elision_preserves_the_envelope_root`,
/// `signature_survives_elision`, and `elided_disclosure_hides_the_concert` —
/// because they are all *consequences* of the same invariant.
pub fn elide_concert(signed: &Envelope, credential: &Envelope) -> Envelope {
    todo!("Step 4: find the assignedTo assertion and elide it from the signed envelope")
}
