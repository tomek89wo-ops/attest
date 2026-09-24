"""Tests for attest.

These are written against the *rules*, not the happy path. The rules are the
product: a digest that binds paths as well as bytes, a decision that cannot
reach ATTESTED through silence, and a statement that stops matching its own
fingerprint the moment anyone edits it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from attest import (
    ATTESTED,
    CANNOT_VERIFY,
    NOT_ATTESTED,
    Artifact,
    Claim,
    EvidenceChain,
    digest_bytes,
    digest_file,
    digest_path,
    digest_tree,
    fingerprint,
    issue_statement,
    render,
    verify_statement,
)

FIXED_TIME = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


# --- helpers -----------------------------------------------------------------


def _package(tmp_path, body: bytes = b"evidence\n"):
    """A minimal valid package: one file, one claim resting on it."""
    root = tmp_path / "pkg"
    root.mkdir(parents=True)
    (root / "data.csv").write_bytes(body)
    chain = EvidenceChain()
    chain.add_artifact(
        Artifact("data", "data.csv", digest_file(root / "data.csv"))
    )
    chain.add_claim(
        Claim(
            "c1",
            "the series has 1 row",
            "data",
            reproduction="wc -l data.csv",
            verdict="supported",
        )
    )
    return root, chain


# --- digests -----------------------------------------------------------------


def test_digest_is_stable_across_calls(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 5000)
    assert digest_file(f) == digest_file(f)


def test_digest_changes_with_one_byte(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"hello")
    b.write_bytes(b"hellp")
    assert digest_file(a) != digest_file(b)


def test_file_digest_and_tree_digest_are_different_domains(tmp_path):
    """A file must not hash the same as a directory that happens to contain it.

    Without a domain separator these can be made to collide, and then
    'the artifact matches' is true of the wrong kind of object.
    """
    root = tmp_path / "d"
    root.mkdir()
    (root / "only").write_bytes(b"")
    assert digest_tree(root) != digest_file(root / "only")


def test_streamed_digest_matches_whole_file_digest(tmp_path):
    """Chunking must not change the answer, including across the chunk boundary."""
    big = tmp_path / "big.bin"
    big.write_bytes(b"ab" * ((1 << 20) + 17))
    assert digest_file(big) == digest_bytes(big.read_bytes())


def test_tree_digest_is_order_independent(tmp_path):
    """The same files created in a different order must hash identically."""
    one = tmp_path / "one"
    two = tmp_path / "two"
    for root, names in ((one, ["a", "b", "c"]), (two, ["c", "a", "b"])):
        root.mkdir()
        for n in names:
            (root / n).write_bytes(n.encode())
    assert digest_tree(one) == digest_tree(two)


def test_tree_digest_binds_the_path_not_only_the_bytes(tmp_path):
    """Renaming a file with identical content must change the tree digest."""
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "prices.csv").write_bytes(b"same")
    (two / "returns.csv").write_bytes(b"same")
    assert digest_tree(one) != digest_tree(two)


def test_tree_digest_resists_path_boundary_ambiguity(tmp_path):
    """`ab/c` and `a/bc` must not hash alike.

    Concatenating paths without writing their lengths first makes these two
    trees indistinguishable — exactly the rename a reviewer is supposed to see.
    """
    one = tmp_path / "one"
    two = tmp_path / "two"
    (one / "ab").mkdir(parents=True)
    (one / "ab" / "c").write_bytes(b"payload")
    (two / "a").mkdir(parents=True)
    (two / "a" / "bc").write_bytes(b"payload")
    assert digest_tree(one) != digest_tree(two)


def test_tree_digest_ignores_pycache_by_default(tmp_path):
    root = tmp_path / "pkg"
    (root / "__pycache__").mkdir(parents=True)
    (root / "mod.py").write_bytes(b"x = 1\n")
    before = digest_tree(root)
    (root / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"\x00\x01")
    assert digest_tree(root) == before


def test_digest_path_dispatches_on_what_the_path_is(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    f = root / "f.txt"
    f.write_bytes(b"data")
    assert digest_path(f) == digest_file(f)
    assert digest_path(root) == digest_tree(root)


def test_digest_tree_refuses_a_file(tmp_path):
    f = tmp_path / "f.txt"
    f.write_bytes(b"data")
    with pytest.raises(NotADirectoryError):
        digest_tree(f)


# --- construction guards -----------------------------------------------------


def test_artifact_rejects_a_digest_that_is_not_sha256():
    with pytest.raises(ValueError, match="SHA-256"):
        Artifact("a", "a.csv", "deadbeef")


def test_artifact_normalises_digest_case():
    art = Artifact("a", "a.csv", "A" * 8 + "0" * 56)
    assert art.declared_digest == "a" * 8 + "0" * 56


def test_claim_rejects_an_invented_verdict():
    with pytest.raises(ValueError, match="verdict"):
        Claim("c", "something", "a", verdict="probably")


def test_duplicate_ids_are_refused():
    chain = EvidenceChain()
    chain.add_artifact(Artifact("a", "a.csv", "0" * 64))
    with pytest.raises(ValueError, match="duplicate"):
        chain.add_artifact(Artifact("a", "b.csv", "1" * 64))
    chain.add_claim(Claim("c", "x", "a", verdict="supported"))
    with pytest.raises(ValueError, match="duplicate"):
        chain.add_claim(Claim("c", "y", "a", verdict="supported"))


# --- verification ------------------------------------------------------------


def test_intact_package_with_checked_claims_is_attested(tmp_path):
    root, chain = _package(tmp_path)
    findings = chain.verify(root)
    assert findings == []
    assert chain.decide(findings) == ATTESTED


def test_edited_artifact_is_caught_and_blocks(tmp_path):
    root, chain = _package(tmp_path)
    (root / "data.csv").write_bytes(b"evidence, but different\n")
    findings = chain.verify(root)
    codes = [f.code for f in findings]
    assert "DIGEST_MISMATCH" in codes
    assert chain.decide(findings) == NOT_ATTESTED


def test_missing_artifact_is_caught_and_blocks(tmp_path):
    root, chain = _package(tmp_path)
    (root / "data.csv").unlink()
    findings = chain.verify(root)
    assert "ARTIFACT_MISSING" in [f.code for f in findings]
    assert chain.decide(findings) == NOT_ATTESTED


def test_claim_on_an_unknown_artifact_blocks(tmp_path):
    root, chain = _package(tmp_path)
    chain.add_claim(Claim("c2", "rests on nothing", "ghost", "cmd", "supported"))
    findings = chain.verify(root)
    assert "CLAIM_ORPHAN" in [f.code for f in findings]
    assert chain.decide(findings) == NOT_ATTESTED


def test_contradicted_claim_blocks(tmp_path):
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim(
        "c1", "the series has 1 row", "data", "wc -l data.csv", "contradicted"
    )
    findings = chain.verify(root)
    assert "CLAIM_CONTRADICTED" in [f.code for f in findings]
    assert chain.decide(findings) == NOT_ATTESTED


def test_unreferenced_artifact_is_noted_but_does_not_block(tmp_path):
    root, chain = _package(tmp_path)
    (root / "spare.txt").write_bytes(b"unused\n")
    chain.add_artifact(
        Artifact("spare", "spare.txt", digest_file(root / "spare.txt"))
    )
    findings = chain.verify(root)
    assert "ARTIFACT_UNREFERENCED" in [f.code for f in findings]
    assert not any(f.blocking for f in findings)


def test_package_with_no_artifacts_blocks(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    chain = EvidenceChain()
    findings = chain.verify(root)
    assert "NO_ARTIFACTS" in [f.code for f in findings]
    assert chain.decide(findings) == NOT_ATTESTED


# --- the rule this package exists for ---------------------------------------


def test_unchecked_claim_can_never_be_attested(tmp_path):
    """An absent verdict is not a pass.

    This is the failure the module was written after: a verifier that dies
    mid-run leaves no answer, and a system that treats 'no answer' as an
    ordinary result will eventually launder silence into a conclusion.
    """
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim("c1", "the series has 1 row", "data", "wc -l data.csv")
    findings = chain.verify(root)
    assert "CLAIM_UNVERIFIED" in [f.code for f in findings]
    assert chain.decide(findings) == CANNOT_VERIFY
    assert chain.decide(findings) != ATTESTED


def test_package_asserting_nothing_cannot_be_attested(tmp_path):
    """A package with no claims is not a clean package; it is an unreviewable one."""
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "data.csv").write_bytes(b"rows\n")
    chain = EvidenceChain()
    chain.add_artifact(Artifact("data", "data.csv", digest_file(root / "data.csv")))
    findings = chain.verify(root)
    assert "NO_CLAIMS" in [f.code for f in findings]
    assert chain.decide(findings) == CANNOT_VERIFY


def test_claim_without_a_reproduction_cannot_be_attested(tmp_path):
    """A claim a third party cannot re-run has been read, not verified."""
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim(
        "c1", "the series has 1 row", "data", reproduction="  ", verdict="supported"
    )
    findings = chain.verify(root)
    assert "REPRODUCTION_MISSING" in [f.code for f in findings]
    assert chain.decide(findings) == CANNOT_VERIFY


def test_blocking_beats_unverified(tmp_path):
    """A tampered package is NOT_ATTESTED, not merely unverifiable.

    Precedence matters: the weaker answer must never mask the stronger one.
    """
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim("c1", "the series has 1 row", "data", "wc -l data.csv")
    (root / "data.csv").write_bytes(b"tampered\n")
    findings = chain.verify(root)
    assert "CLAIM_UNVERIFIED" in [f.code for f in findings]
    assert "DIGEST_MISMATCH" in [f.code for f in findings]
    assert chain.decide(findings) == NOT_ATTESTED


# --- the statement -----------------------------------------------------------


def test_statement_verifies_against_its_own_fingerprint(tmp_path):
    root, chain = _package(tmp_path)
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    assert verify_statement(st)
    assert st["decision"] == ATTESTED
    assert st["reviewed_at_utc"] == "2026-09-21T12:00:00Z"


@pytest.mark.parametrize(
    "field, value",
    [
        ("decision", ATTESTED),
        ("scope", "everything, in production"),
        ("reviewer", "somebody else"),
        ("reviewed_at_utc", "2030-01-01T00:00:00Z"),
        ("subject", "a different system"),
    ],
)
def test_editing_any_field_breaks_the_fingerprint(tmp_path, field, value):
    """The document is its own tamper-evidence. This is the whole product."""
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim(
        "c1", "the series has 1 row", "data", "wc -l data.csv", "contradicted"
    )
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    assert st["decision"] == NOT_ATTESTED
    st[field] = value
    assert not verify_statement(st)


def test_editing_a_nested_finding_breaks_the_fingerprint(tmp_path):
    """Tampering below the top level must be caught too."""
    root, chain = _package(tmp_path)
    (root / "data.csv").write_bytes(b"tampered\n")
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    st["findings"][0]["blocking"] = False
    assert not verify_statement(st)


def test_removing_the_fingerprint_does_not_pass(tmp_path):
    root, chain = _package(tmp_path)
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    del st["fingerprint"]
    assert not verify_statement(st)
    st["fingerprint"] = ""
    assert not verify_statement(st)


def test_fingerprint_survives_a_json_round_trip(tmp_path):
    """A statement is useless if saving and reloading it invalidates it."""
    root, chain = _package(tmp_path)
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    again = json.loads(json.dumps(st))
    assert verify_statement(again)
    assert fingerprint(again) == st["fingerprint"]


def test_fingerprint_is_independent_of_key_order(tmp_path):
    root, chain = _package(tmp_path)
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    shuffled = dict(reversed(list(st.items())))
    assert verify_statement(shuffled)


def test_two_packages_get_different_fingerprints(tmp_path):
    root_a, chain_a = _package(tmp_path / "a", body=b"alpha\n")
    root_b, chain_b = _package(tmp_path / "b", body=b"beta\n")
    a = issue_statement(chain_a, root_a, scope="Demo only", reviewer="T", now=FIXED_TIME)
    b = issue_statement(chain_b, root_b, scope="Demo only", reviewer="T", now=FIXED_TIME)
    assert a["fingerprint"] != b["fingerprint"]


def test_scope_is_mandatory(tmp_path):
    root, chain = _package(tmp_path)
    with pytest.raises(ValueError, match="scope"):
        issue_statement(chain, root, scope="   ", reviewer="T. Wadowski")


def test_reviewer_is_mandatory(tmp_path):
    root, chain = _package(tmp_path)
    with pytest.raises(ValueError, match="reviewer"):
        issue_statement(chain, root, scope="Demo only", reviewer="")


def test_naive_datetime_is_still_stamped_as_utc(tmp_path):
    root, chain = _package(tmp_path)
    st = issue_statement(
        chain,
        root,
        scope="Demo only",
        reviewer="T",
        now=datetime(2026, 9, 21, 15, 30, tzinfo=timezone.utc),
    )
    assert st["reviewed_at_utc"].endswith("Z")


def test_render_shows_the_decision_and_the_fingerprint(tmp_path):
    root, chain = _package(tmp_path)
    chain.claims[0] = Claim("c1", "the series has 1 row", "data", "wc -l data.csv")
    st = issue_statement(
        chain, root, scope="Demo only", reviewer="T. Wadowski", now=FIXED_TIME
    )
    text = render(st)
    assert CANNOT_VERIFY in text
    assert st["fingerprint"] in text
    assert "NOT CHECKED" in text
