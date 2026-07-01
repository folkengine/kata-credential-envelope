//! # Credential Envelope kata — reference solution
//!
//! This is the worked answer. Drop these four bodies into `src/lib.rs` to make
//! all seven tests pass. Read `SOLUTION.md` next to this file for the *why*.

use bc_components::SigningPrivateKey;
use bc_envelope::prelude::*;

/// Step 1–2 · Build the **salted, unsigned** credential envelope.
///
/// Subject is the musician; each fact is a salted assertion. Salt is what makes
/// two builds of the same facts differ (test 2) — drop it and elided low-entropy
/// fields become brute-forceable.
pub fn build_credential(
    musician: &str,
    concert: &str,
    orchestra: &str,
    instrument: &str,
) -> Envelope {
    Envelope::new(musician)
        .add_assertion_salted("assignedTo", concert, true)
        .add_assertion_salted("orchestra", orchestra, true)
        .add_assertion_salted("instrument", instrument, true)
}

/// Step 3 · Issue by **wrapping then signing**, so the signature covers the
/// whole credential as one root and survives later elision.
pub fn issue(credential: &Envelope, issuer: &SigningPrivateKey) -> Envelope {
    credential.wrap().add_signature(issuer)
}

/// Step 7 · The **CAS address**: BLAKE3 over the serialized dCBOR bytes.
pub fn cas_address(envelope: &Envelope) -> [u8; 32] {
    let bytes = envelope.tagged_cbor().to_cbor_data();
    *blake3::hash(&bytes).as_bytes()
}

/// Step 4 · Holder-side **elision**: remove the `assignedTo` subtree by digest.
/// Take the target from the *unsigned* credential — a subtree's digest is the
/// same wherever it appears, so it matches through the signed wrap.
pub fn elide_concert(signed: &Envelope, credential: &Envelope) -> Envelope {
    let target = credential
        .assertion_with_predicate("assignedTo")
        .expect("credential has an assignedTo assertion");
    signed.elide_removing_target(&target)
}
