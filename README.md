[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE-APACHE)

# Credential Envelope Kata

> Rebuild the **two-hash boundary** that lets one signed credential be disclosed
> many ways without breaking its seal.

This kata is extracted from
[`examples/credential_envelope.rs`](https://github.com/folkengine/sycore/blob/main/examples/credential_envelope.rs)
in the SyCore repo, which demonstrates Part 4 of the FolkEngine spec
([`docs/SPEC-credential-envelope.md`](https://github.com/folkengine/sycore/blob/main/docs/SPEC-credential-envelope.md)).
You do not need the rest of the codebase to do it.

---

## The concept (from first principles)

A **credential** is a signed statement: an issuer attests some facts about a
subject. The hard part isn't signing — it's **selective disclosure**. A patient
holding a lab result wants to show a new doctor *only* the relevant fields, not
the whole record, and the doctor still wants the lab's original signature to
verify. How do you reveal a *subset* of signed data without re-signing?

The answer is a **Gordian Envelope**: a tree of `subject – predicate – object`
triples with a built-in Merkle-like **digest tree**. Each node's digest is
computed from its children's digests. The key operation is **elision**:

> Replace any subtree with *just its digest*. Every ancestor digest — including
> the root — stays the same, because the digest tree was already built from that
> subtree's digest. A signature over the root therefore still verifies.

That gives **holder-driven selective disclosure**: the issuer signs once; the
holder strips fields they don't want to share; the signature survives.

### Two hashes, two questions

This kata lives at a boundary where **two different hash functions** are in play,
and the whole design rests on understanding which operation touches which:

| Digest          | Hash    | Computed over              | Answers                          |
| --------------- | ------- | -------------------------- | -------------------------------- |
| **CAS address** | BLAKE3  | the envelope's dCBOR bytes | *where this exact blob lives*    |
| **Envelope root** | SHA-256 | the envelope's digest tree | *the seal that survives elision* |

The load-bearing consequence — the thing you will prove with tests:

> **Elision changes the CAS address but not the envelope root.** Eliding a
> subtree rewrites the serialized bytes (so the **BLAKE3 CAS address changes**),
> but is *defined* to leave every ancestor's SHA-256 digest unchanged (so the
> **SHA-256 root is invariant** and the signature still verifies).

So one credential has **one seal but many addresses**: the full disclosure and
each elided projection are distinct blobs sharing one root. BLAKE3 says *where a
disclosure lives*; SHA-256 says *which credential it is a disclosure of*.

### Why salt?

Elision relies on deterministic hashing — which means a **low-entropy** elided
field (a short id, a yes/no, a date) can be *brute-forced*: an attacker hashes
every candidate value until one matches the leftover digest, recovering the
"hidden" value. The countermeasure is **salt**: a random blob mixed into each
assertion at issuance, so its digest can't be reproduced from the value alone.
For credentials this is mandatory, not optional — the privacy property must be
*structural*, not hoped-for.

---

## The challenge

You implement the four functions in [`src/lib.rs`](src/lib.rs) (each currently
`todo!()`) and make the seven tests in
[`tests/two_hash.rs`](tests/two_hash.rs) pass. But don't try to do it all at
once. **Do it one step at a time**: make one small change, run the single test
for that step, watch it go green, then move on.

Run the whole suite any time with:

```bash
cargo test          # 7 tests; all fail until you implement the stubs
```

…but the point of this kata is the *ramp*. Each step below names one test — run
just that one with `cargo test <name>` — and tells you the one change that makes
it pass.

### The steps

> **Step 1 — three assertions.** In `build_credential`, return an
> `Envelope::new(musician)` with three plain assertions: `assignedTo → concert`,
> `orchestra → orchestra`, `instrument → instrument`.
> ```bash
> cargo test credential_has_three_assertions
> ```

> **Step 2 — salt them.** Still in `build_credential`: change each
> `add_assertion` to `add_assertion_salted(pred, obj, true)`. Salt is random, so
> the same facts now produce a different envelope every time — which is exactly
> what this test checks (and why an elided field can't be brute-forced).
> ```bash
> cargo test low_entropy_fields_are_salted
> ```

> **Step 3 — issue it.** In `issue`, `wrap()` the credential *then*
> `add_signature(issuer)`. Wrapping first makes the signature cover the whole
> credential as one root — that's what lets it survive elision later.
> ```bash
> cargo test signature_verifies_on_full_disclosure
> ```

> **Step 4 — elide the concert.** In `elide_concert`, get the `assignedTo`
> assertion from the *unsigned* `credential` (via
> `assertion_with_predicate("assignedTo")`) and pass it to
> `signed.elide_removing_target(&target)`. This one function is the payoff — it
> makes **three** tests pass at once (steps 4, 5, 6), because they're all
> consequences of the same invariant. Start with the root:
> ```bash
> cargo test elision_preserves_the_envelope_root   # SHA-256 is invariant — the insight
> ```

> **Step 5 — signature survives (no new code).** Because the root didn't move,
> the signature still verifies on the elided disclosure. Just confirm it:
> ```bash
> cargo test signature_survives_elision
> ```

> **Step 6 — the concert is gone (no new code).** The removed field shows as
> `ELIDED` and the id never leaks. Confirm it:
> ```bash
> cargo test elided_disclosure_hides_the_concert
> ```

> **Step 7 — the other hash.** In `cas_address`, BLAKE3-hash the serialized
> bytes: `blake3::hash(&envelope.tagged_cbor().to_cbor_data())`. Elision
> rewrote those bytes, so the CAS address changes — even though the SHA-256 root
> (step 4) stayed put. That contrast is the whole point of the kata.
> ```bash
> cargo test elision_changes_the_cas_address
> ```

You're done when all seven pass (`cargo test`). Notice the shape of the real
flow you just walked: **salt → sign → elide**. The issuer salts low-entropy
fields *before* signing; the holder elides *after*. Eliding an unsalted
low-entropy field would let a verifier recover it from its digest — which is why
step 2 comes before everything else.

---

## Hints (open only if stuck)

<details>
<summary>API map — which <code>bc-envelope</code> calls you need</summary>

- `Envelope::new(subject)` — start an envelope with a subject.
- `.add_assertion_salted(predicate, object, salted: bool)` — add a triple; pass
  `true` to salt it.
- `.wrap()` — wrap the whole envelope so a signature can cover it as one digest.
- `.add_signature(&signer)` — attach a `verifiedBy` signature.
- `.digest()` — the SHA-256 envelope root (a `Digest`).
- `.tagged_cbor().to_cbor_data()` — the serialized dCBOR bytes.
- `.assertion_with_predicate("assignedTo")` — locate an assertion by predicate.
- `.elide_removing_target(&target)` — elide the subtree with that digest.
- `blake3::hash(bytes).as_bytes()` — BLAKE3 → `&[u8; 32]`.

</details>

<details>
<summary>Stuck on <code>elide_concert</code>?</summary>

The signed envelope's top-level assertion is the *signature*, not `assignedTo`
(that's now inside the wrap). Elision works by **digest**, and a subtree's
digest is identical wherever it appears. So get the `assignedTo` assertion from
the original unsigned `credential`, then call `elide_removing_target` on the
`signed` envelope — it will find and remove the matching subtree through the
wrap.

</details>

<details>
<summary>Why does the salt test compare two whole builds?</summary>

Salt is random, so `build_credential(...).digest()` differs every call. If you
forgot to salt (or used `add_assertion` instead of `add_assertion_salted`), the
construction is deterministic and the two digests would be **equal** — which is
exactly the brute-forceable state the test is there to catch.

</details>

The full worked answer is in [`solution/`](solution/): the four function bodies
in [`solution/lib.rs`](solution/lib.rs) and a step-by-step walkthrough of the
*why* in [`solution/SOLUTION.md`](solution/SOLUTION.md).

---

## Where this lives in the real codebase

- **Source:** [`examples/credential_envelope.rs`](https://github.com/folkengine/sycore/blob/main/examples/credential_envelope.rs)
  — the runnable example (`cargo run --example credential_envelope`) that prints
  all six stages and asserts the same §4.2 vector.
- **Spec:** [`docs/SPEC-credential-envelope.md`](https://github.com/folkengine/sycore/blob/main/docs/SPEC-credential-envelope.md)
  §4.2 (the two-hash boundary), §4.6 (mandatory salting).

**How the real version differs:** in the repo, the four facts are not strings —
they come from the *pure SyCore kernel*. The example runs real `apply` calls
(`RegisterMusician → FoundOrchestra → AddToRoster → ProgramConcert →
AssignPlayer`) and pulls a typed `Event::PlayerAssigned` across the **seam**
between the kernel and the substrate. This kata simplifies that seam to plain
string inputs so you can focus on the envelope concept; everything from
"build the envelope" onward is faithful to the real code.
