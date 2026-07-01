# Solution walkthrough

The whole kata rests on one fact about Gordian Envelopes: **a subtree's digest
is fixed the moment you build it, and every ancestor digest is computed from
it.** Elision replaces a subtree with *just that digest* — so ancestors, and any
signature over the root, never notice. Below is how each step lands, in the
order the tests ask for them.

## Step 1 — `build_credential` (structure)

```rust
Envelope::new(musician)
    .add_assertion("assignedTo", concert)
    .add_assertion("orchestra", orchestra)
    .add_assertion("instrument", instrument)
```

Subject + three assertions. That alone passes `credential_has_three_assertions`.
This intermediate form is *not* the final answer — see step 2.

## Step 2 — `build_credential` (salt)

Swap every `add_assertion` for `add_assertion_salted(pred, obj, true)`:

```rust
Envelope::new(musician)
    .add_assertion_salted("assignedTo", concert, true)
    .add_assertion_salted("orchestra", orchestra, true)
    .add_assertion_salted("instrument", instrument, true)
```

Salt is random, so two builds of identical facts now produce different digests —
that is exactly what `low_entropy_fields_are_salted` checks. Without salt, an
attacker could brute-force an *elided* low-entropy field (a short id, a date) by
hashing candidates until one matches the leftover digest. Salting makes the
privacy property structural, not hoped-for.

## Step 3 — `issue` (wrap, then sign)

```rust
credential.wrap().add_signature(issuer)
```

Order is load-bearing. `wrap()` turns the whole credential into a single
subject whose digest is the root; signing *that* means the signature attests the
entire credential. Sign the bare subject instead and you'd only attest the
musician id, not the assertions — and the signature wouldn't survive elision.

## Step 4 — `elide_concert` (and the invariant)

```rust
let target = credential
    .assertion_with_predicate("assignedTo")
    .expect("credential has an assignedTo assertion");
signed.elide_removing_target(&target)
```

The subtle part: the signed envelope's top-level assertion is the *signature* —
`assignedTo` is now buried inside the wrap. But elision matches by **digest**,
and the `assignedTo` subtree has the same digest whether it sits in the raw
`credential` or inside the signed wrap. So we grab the target from the original
unsigned `credential` and hand it to `signed.elide_removing_target(...)`; it
finds and removes the matching subtree through the wrap.

Implementing this one function turns on three tests at once — each is a
*consequence* of the invariant, not new code:

- `elision_preserves_the_envelope_root` — the SHA-256 root is unchanged, because
  the digest tree was already built from the elided subtree's digest.
- `signature_survives_elision` — the signature is over that unchanged root, so it
  still verifies.
- `elided_disclosure_hides_the_concert` — the concert id is genuinely gone from
  the bytes; it shows as `ELIDED`.

## Step 7 — `cas_address`

```rust
let bytes = envelope.tagged_cbor().to_cbor_data();
*blake3::hash(&bytes).as_bytes()
```

BLAKE3 over the serialized dCBOR. This is the *other* hash. Elision rewrites the
serialized bytes, so `elision_changes_the_cas_address` sees a different address —
while the SHA-256 root (step 4) stayed put.

## The one-sentence takeaway

**BLAKE3 says where a disclosure lives; SHA-256 says which credential it is a
disclosure of.** Elision moves the first and pins the second — one seal, many
addresses.
