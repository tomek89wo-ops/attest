# attest

[![tests](https://github.com/tomek89wo-ops/attest/actions/workflows/tests.yml/badge.svg)](https://github.com/tomek89wo-ops/attest/actions/workflows/tests.yml)

**A review statement that stops matching its own fingerprint the moment anyone edits it.**

An attestation you can edit after issuing it is not an attestation. This package
issues review statements over frozen evidence packages, and binds each statement
to a SHA-256 of its own canonical form — so changing the decision, the scope, the
date, the reviewer, or any single finding breaks the identifier the document is
known by.

```
python examples/demo.py
```

```
4. SOMEBODY EDITS THE VERDICT AFTERWARDS
------------------------------------------------------------------------
   statement now says     : ATTESTED
   fingerprint still valid: False
```

No dependencies. Standard library only — an instrument that certifies a package
is what it claims to be has no business dragging in a dependency tree of its own.

---

## The rule the whole thing is built around

**An absent verdict is never a pass.**

There are three outcomes, not two:

| decision | means |
|---|---|
| `ATTESTED` | nothing blocking was found **and** every claim was actually checked |
| `NOT_ATTESTED` | something blocking was found: a digest mismatch, a missing artifact, a claim resting on nothing, or a claim the evidence contradicts |
| `CANNOT_VERIFY` | the package does not let you reach a conclusion — a claim carries no verdict, or no reproduction, or there are no claims at all |

`CANNOT_VERIFY` exists because the alternative is worse than useless. A two-valued
review has to put "I could not check this" somewhere, and it always ends up on the
pass side, because that is the side with no consequences.

This is not a hypothetical. It is the defect this package was written after: a
review harness in which one verifier crashed mid-run, and the missing answer was
recorded as an ordinary result. Given enough runs, a system like that launders
silence into a conclusion. Here, an unchecked claim cannot produce `ATTESTED` —
a rule with [its own test](tests/test_core.py).

Precedence is fixed and tested too: a tampered package is `NOT_ATTESTED`, not
merely unverifiable. The weaker answer never masks the stronger one.

---

## What it checks

1. **Integrity.** Recomputes SHA-256 over every declared artifact and reports the
   computed digest beside the declared one.
2. **Consistency.** Every claim must trace to a declared artifact; artifacts that
   nothing rests on are reported too, because a package padded with unused
   evidence is telling you something.
3. **Reproducibility.** Every claim must carry a command a third party can run.
   A claim without one has been read, not verified.
4. **Scope.** Mandatory, and meant to be written adversarially: say what was *not*
   examined, because that is the sentence a reader needs and the one an author omits.

## What it does not check

Whether the evidence is any good. `attest` has no opinion on whether a strategy
works, a model is sound, or a number is impressive. It answers whether the package
is intact, internally consistent, and whether the statement in your hand is still
the one that was signed. Everything else is the reviewer's judgement, and this
package deliberately refuses to launder judgement into arithmetic.

---

## Two details that are easy to get wrong

**The directory digest binds paths, not only bytes.** Renaming `prices.csv` to
`returns.csv` changes the digest, because a rename is exactly what a reviewer is
supposed to catch. Path lengths are written into the hash before the paths, so
`ab/c` and `a/bc` cannot collide — a subtlety that silently defeats the naive
implementation.

**File digests and tree digests live in separate domains.** Without a domain
separator, a file and a one-entry directory containing it can be made to hash
alike, and "the artifact matches" becomes true of the wrong kind of object.

Both have tests. So does the 1 MiB chunk boundary in the streaming reader, because
evidence packages routinely contain price files larger than the machine's memory,
and a tool that dies on the real input is not an instrument.

---

## Use

```python
from attest import Artifact, Claim, EvidenceChain, digest_file, issue_statement, render

chain = EvidenceChain()
chain.add_artifact(Artifact("returns", "returns.csv", digest_file("pkg/returns.csv")))
chain.add_claim(Claim(
    "C1",
    "every mark in the report exists in the price files",
    "returns",
    reproduction="python -m tools.trace_marks --evidence returns.csv",
    verdict="supported",          # omit it and the outcome is CANNOT_VERIFY
))

statement = issue_statement(
    chain, "pkg",
    subject="candidate/2026-09",
    scope="Demo evidence only. Does NOT cover live execution or broker connectivity.",
    reviewer="A. Reviewer",
)
print(render(statement))
```

Later, from the other side:

```python
from attest import verify_statement
verify_statement(json.load(open("statement.json")))   # False if anything moved
```

## Tests

```
python -m pytest -q
```

40 tests, on Linux, macOS and Windows, on Python 3.10 through 3.13. The whole
suite, every platform, no marker filters — a package that reports opt-in coverage
in other people's projects has no business shipping opt-in coverage of its own.

## Related

[edge-gate](https://github.com/tomek89wo-ops/edge-gate) — five tests every
candidate trading edge has to survive before anyone writes code. Same posture:
the expensive mistake is not missing something, it is certifying something that
was never there.

## Licence

MIT.
