"""Three things a review statement has to survive, run end to end.

    python examples/demo.py

Nothing here is mocked. A real package is written to a temporary directory,
really hashed, really reviewed, and then really tampered with.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attest import (  # noqa: E402
    ATTESTED,
    CANNOT_VERIFY,
    NOT_ATTESTED,
    Artifact,
    Claim,
    EvidenceChain,
    digest_file,
    issue_statement,
    render,
    verify_statement,
)

FIXED = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
SCOPE = (
    "Demo/paper evidence only. Covers artifact integrity, chain consistency and "
    "claim-to-artifact traceability. Does NOT cover live execution, broker "
    "connectivity, or whether the strategy is profitable."
)
RULE = "-" * 72


def build(root: Path) -> EvidenceChain:
    (root / "returns.csv").write_text(
        "date,ret\n2026-09-01,0.0012\n2026-09-02,-0.0004\n", encoding="utf-8"
    )
    (root / "spec.md").write_text(
        "# Candidate\n\nLong when the 20d mean exceeds the 100d mean.\n", encoding="utf-8"
    )

    chain = EvidenceChain()
    chain.add_artifact(Artifact("returns", "returns.csv", digest_file(root / "returns.csv")))
    chain.add_artifact(Artifact("spec", "spec.md", digest_file(root / "spec.md")))
    chain.add_claim(
        Claim(
            "C1",
            "every return in the specification comes from returns.csv",
            "returns",
            reproduction="python -m tools.trace_marks --evidence returns.csv",
            verdict="supported",
        )
    )
    chain.add_claim(
        Claim(
            "C2",
            "the rule in spec.md is the rule the candidate implements",
            "spec",
            reproduction="diff <(python -m candidate --describe) spec.md",
            verdict="supported",
        )
    )
    return chain


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        chain = build(root)

        print("1. AN INTACT PACKAGE, EVERY CLAIM CHECKED")
        print(RULE)
        good = issue_statement(
            chain, root, subject="candidate/demo", scope=SCOPE,
            reviewer="T. Wadowski (MQL5: Tomasz Jan)", now=FIXED,
        )
        print(render(good))
        assert good["decision"] == ATTESTED, good["decision"]
        assert verify_statement(good)

        print()
        print("2. THE SAME PACKAGE, ONE CLAIM LEFT UNCHECKED")
        print(RULE)
        chain.claims[1] = Claim(
            "C2",
            "the rule in spec.md is the rule the candidate implements",
            "spec",
            reproduction="diff <(python -m candidate --describe) spec.md",
        )
        silent = issue_statement(
            chain, root, subject="candidate/demo", scope=SCOPE,
            reviewer="T. Wadowski (MQL5: Tomasz Jan)", now=FIXED,
        )
        print(f"decision  : {silent['decision']}")
        for f in silent["findings"]:
            print(f"            {f['code']}: {f['detail']}")
        assert silent["decision"] == CANNOT_VERIFY, silent["decision"]
        print()
        print("   An absent verdict is not a pass. Nothing about the package got")
        print("   worse between 1 and 2 — the review got weaker, and the statement")
        print("   says so instead of rounding it up to ATTESTED.")

        print()
        print("3. ONE BYTE CHANGED AFTER FREEZING")
        print(RULE)
        (root / "returns.csv").write_text(
            "date,ret\n2026-09-01,0.0012\n2026-09-02,0.0004\n", encoding="utf-8"
        )
        tampered = issue_statement(
            chain, root, subject="candidate/demo", scope=SCOPE,
            reviewer="T. Wadowski (MQL5: Tomasz Jan)", now=FIXED,
        )
        print(f"decision  : {tampered['decision']}")
        for f in tampered["findings"]:
            if f["blocking"]:
                print(f"            {f['code']}: {f['detail']}")
        assert tampered["decision"] == NOT_ATTESTED, tampered["decision"]
        print()
        print("   A minus sign was removed from one number. No line count changed,")
        print("   no file was added, nothing looks different in a diff of the")
        print("   directory listing. The digest does not care what it looks like.")

        print()
        print("4. SOMEBODY EDITS THE VERDICT AFTERWARDS")
        print(RULE)
        forged = dict(tampered)
        forged["decision"] = ATTESTED
        print(f"   statement now says     : {forged['decision']}")
        print(f"   fingerprint still valid: {verify_statement(forged)}")
        assert not verify_statement(forged)
        print()
        print("   This is the point of the whole package. The document carries a")
        print("   SHA-256 over its own canonical form, so whoever is shown it later")
        print("   can tell in one call that the decision was changed after issue.")

    print()
    print(RULE)
    print("All four held. Run `python -m pytest -q` for the other 40 checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
