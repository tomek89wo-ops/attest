"""Hash-bound review statements for frozen evidence packages.

Nothing here judges whether evidence is *good*. It answers three narrower
questions, and refuses to answer more than it can:

1. Is the package **intact** — does what is on disk match what was declared?
2. Is it **internally consistent** — does every claim trace to a declared
   artifact, and does every artifact carry a reproduction a third party can run?
3. Is the statement you hand someone still the statement that was signed?

The third question is the reason this module exists. A review that ends in a
PDF is a review that can be edited afterwards. A statement issued here carries
a fingerprint computed over its own canonical form, so altering any field —
including the decision — breaks the identifier the statement is known by.

One rule shapes the whole design: **an absent verdict is never a pass.** A claim
nobody checked makes the outcome ``CANNOT_VERIFY``, never ``ATTESTED``. That is
not defensive coding; it is the failure this module was written after. A review
harness that recorded a crashed verifier's missing answer as an ordinary result
will, given enough runs, launder silence into a conclusion.

Standard library only, deliberately. An instrument whose job is to certify that
a package is what it claims to be should not itself drag in a dependency tree.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

__all__ = [
    "ATTESTED",
    "NOT_ATTESTED",
    "CANNOT_VERIFY",
    "Artifact",
    "Claim",
    "Finding",
    "EvidenceChain",
    "digest_bytes",
    "digest_file",
    "digest_tree",
    "issue_statement",
    "fingerprint",
    "verify_statement",
    "render",
]

# --- decisions ---------------------------------------------------------------

ATTESTED = "ATTESTED"
NOT_ATTESTED = "NOT_ATTESTED"
CANNOT_VERIFY = "CANNOT_VERIFY"

#: Verdicts a reviewer may record against a claim. ``None`` means *not checked*
#: and is handled separately — it is not a verdict, it is the absence of one.
SUPPORTED = "supported"
CONTRADICTED = "contradicted"
_VERDICTS = (SUPPORTED, CONTRADICTED)

# Domain separators. Without them, a digest over a file and a digest over a
# one-entry tree containing that file could collide, and "the artifact matches"
# would be true of the wrong object.
_LEAF = b"attest/v1/leaf\x00"
_TREE = b"attest/v1/tree\x00"
_STMT = b"attest/v1/statement\x00"

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".git/*",
    "*/.git/*",
    "__pycache__",
    "__pycache__/*",
    "*/__pycache__/*",
    "*.pyc",
    ".pytest_cache",
    ".pytest_cache/*",
    "*/.pytest_cache/*",
)

_READ_CHUNK = 1 << 20


# --- digests -----------------------------------------------------------------


def digest_bytes(data: bytes) -> str:
    """SHA-256 of a byte string, tagged as a leaf."""
    h = hashlib.sha256()
    h.update(_LEAF)
    h.update(data)
    return h.hexdigest()


def digest_file(path: str | os.PathLike[str]) -> str:
    """SHA-256 of one file's contents, streamed.

    Streaming matters: evidence packages routinely contain price files larger
    than the machine's memory, and a tool that dies on the real input is not an
    instrument.
    """
    h = hashlib.sha256()
    h.update(_LEAF)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _excluded(rel: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def digest_tree(
    root: str | os.PathLike[str],
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
) -> str:
    """Deterministic SHA-256 over a directory's contents.

    The digest binds each file's *relative path* as well as its bytes, with
    lengths written before every field. Without the lengths, renaming
    ``ab/c`` to ``a/bc`` would leave the digest unchanged — a rename that a
    reviewer is specifically supposed to catch.

    Paths are normalised to forward slashes and sorted, so the same tree hashes
    identically on Windows and Linux. Symlinks are not followed: an evidence
    package that hashes differently depending on what a link happens to point at
    is not frozen.
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    entries: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        # Prune excluded directories in place so os.walk never descends them.
        dirnames[:] = [
            d
            for d in dirnames
            if not _excluded(f"{rel_dir}/{d}".lstrip("./") if rel_dir != "." else d, excludes)
        ]
        dirnames.sort()
        for name in sorted(filenames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if _excluded(rel, excludes):
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                continue
            entries.append((rel, digest_file(full)))

    h = hashlib.sha256()
    h.update(_TREE)
    h.update(len(entries).to_bytes(8, "big"))
    for rel, leaf in sorted(entries):
        raw = rel.encode("utf-8")
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
        h.update(bytes.fromhex(leaf))
    return h.hexdigest()


def digest_path(
    path: str | os.PathLike[str],
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
) -> str:
    """Digest a file or a directory, whichever the path happens to be."""
    p = Path(path)
    if p.is_dir():
        return digest_tree(p, excludes)
    return digest_file(p)


# --- the package -------------------------------------------------------------


@dataclass(frozen=True)
class Artifact:
    """One frozen thing, and the digest its author says it has."""

    artifact_id: str
    path: str
    declared_digest: str

    def __post_init__(self) -> None:
        if not self.artifact_id:
            raise ValueError("artifact_id must not be empty")
        d = self.declared_digest.strip().lower()
        if len(d) != 64 or any(c not in "0123456789abcdef" for c in d):
            raise ValueError(
                f"{self.artifact_id}: declared_digest is not a SHA-256 hex digest: "
                f"{self.declared_digest!r}"
            )
        object.__setattr__(self, "declared_digest", d)


@dataclass(frozen=True)
class Claim:
    """An assertion the package makes, and how a third party can re-run it.

    ``verdict`` is ``None`` until a reviewer records one. That is the whole
    point of the field: unchecked and checked-and-passed must not be the same
    value, or the difference disappears exactly when it matters.
    """

    claim_id: str
    statement: str
    artifact_id: str
    reproduction: str = ""
    verdict: str | None = None

    def __post_init__(self) -> None:
        if not self.claim_id:
            raise ValueError("claim_id must not be empty")
        if self.verdict is not None and self.verdict not in _VERDICTS:
            raise ValueError(
                f"{self.claim_id}: verdict must be one of {_VERDICTS} or None, "
                f"got {self.verdict!r}"
            )


@dataclass(frozen=True)
class Finding:
    """Something the review observed. ``blocking`` findings forbid ATTESTED."""

    code: str
    detail: str
    blocking: bool = False

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail, "blocking": self.blocking}


@dataclass
class EvidenceChain:
    """A set of artifacts and the claims that rest on them."""

    artifacts: list[Artifact] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)

    def add_artifact(self, artifact: Artifact) -> "EvidenceChain":
        if any(a.artifact_id == artifact.artifact_id for a in self.artifacts):
            raise ValueError(f"duplicate artifact_id: {artifact.artifact_id}")
        self.artifacts.append(artifact)
        return self

    def add_claim(self, claim: Claim) -> "EvidenceChain":
        if any(c.claim_id == claim.claim_id for c in self.claims):
            raise ValueError(f"duplicate claim_id: {claim.claim_id}")
        self.claims.append(claim)
        return self

    # -- verification ---------------------------------------------------------

    def verify(
        self,
        root: str | os.PathLike[str],
        excludes: Sequence[str] = DEFAULT_EXCLUDES,
    ) -> list[Finding]:
        """Recompute every digest and check the chain hangs together.

        Returns findings. An empty list means nothing was wrong *and* every
        claim carried a verdict — the caller still decides what that is worth.
        """
        root = Path(root)
        findings: list[Finding] = []

        if not self.artifacts:
            findings.append(
                Finding("NO_ARTIFACTS", "the package declares no artifacts", blocking=True)
            )

        known: set[str] = set()
        for art in self.artifacts:
            known.add(art.artifact_id)
            target = root / art.path
            if not target.exists():
                findings.append(
                    Finding(
                        "ARTIFACT_MISSING",
                        f"{art.artifact_id}: declared at {art.path!r}, not present",
                        blocking=True,
                    )
                )
                continue
            actual = digest_path(target, excludes)
            if actual != art.declared_digest:
                findings.append(
                    Finding(
                        "DIGEST_MISMATCH",
                        f"{art.artifact_id}: declared {art.declared_digest}, "
                        f"computed {actual}",
                        blocking=True,
                    )
                )

        referenced: set[str] = set()
        for claim in self.claims:
            referenced.add(claim.artifact_id)
            if claim.artifact_id not in known:
                findings.append(
                    Finding(
                        "CLAIM_ORPHAN",
                        f"{claim.claim_id}: rests on unknown artifact "
                        f"{claim.artifact_id!r}",
                        blocking=True,
                    )
                )
            if not claim.reproduction.strip():
                findings.append(
                    Finding(
                        "REPRODUCTION_MISSING",
                        f"{claim.claim_id}: no command a third party can run",
                    )
                )
            if claim.verdict is None:
                findings.append(
                    Finding(
                        "CLAIM_UNVERIFIED",
                        f"{claim.claim_id}: no verdict was recorded",
                    )
                )
            elif claim.verdict == CONTRADICTED:
                findings.append(
                    Finding(
                        "CLAIM_CONTRADICTED",
                        f"{claim.claim_id}: the evidence contradicts the claim",
                        blocking=True,
                    )
                )

        if not self.claims:
            findings.append(
                Finding("NO_CLAIMS", "the package asserts nothing that can be checked")
            )

        for art in self.artifacts:
            if art.artifact_id not in referenced:
                findings.append(
                    Finding(
                        "ARTIFACT_UNREFERENCED",
                        f"{art.artifact_id}: supplied but no claim rests on it",
                    )
                )

        return findings

    def decide(self, findings: Iterable[Finding]) -> str:
        """Turn findings into one of three outcomes.

        ``ATTESTED`` is the narrowest: it requires that nothing blocking was
        found *and* that every claim was actually checked. Anything unchecked —
        including a package with no claims at all — lands in ``CANNOT_VERIFY``,
        which is a real answer and the most honest one available when the
        package does not let you reach a conclusion.
        """
        findings = list(findings)
        if any(f.blocking for f in findings):
            return NOT_ATTESTED
        soft = {"CLAIM_UNVERIFIED", "NO_CLAIMS", "REPRODUCTION_MISSING"}
        if any(f.code in soft for f in findings):
            return CANNOT_VERIFY
        return ATTESTED


# --- the statement -----------------------------------------------------------


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def fingerprint(statement: dict) -> str:
    """SHA-256 over the statement's canonical form, excluding the fingerprint.

    This is what makes the document self-describing: recompute it and you learn
    whether a single character moved since it was issued.
    """
    body = {k: v for k, v in statement.items() if k != "fingerprint"}
    h = hashlib.sha256()
    h.update(_STMT)
    h.update(_canonical(body))
    return h.hexdigest()


def issue_statement(
    chain: EvidenceChain,
    root: str | os.PathLike[str],
    *,
    scope: str,
    reviewer: str,
    subject: str = "",
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    now: datetime | None = None,
) -> dict:
    """Run the review and return a fingerprinted statement.

    ``scope`` is mandatory and is meant to be read adversarially by whoever is
    shown the statement later: say what was *not* examined, because that is the
    sentence a reader needs and the one an author omits.
    """
    if not scope.strip():
        raise ValueError("scope must be stated explicitly; an unscoped attestation is not one")
    if not reviewer.strip():
        raise ValueError("reviewer must identify themselves")

    findings = chain.verify(root, excludes)
    decision = chain.decide(findings)
    ts = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    statement = {
        "schema": "attest/v1",
        "subject": subject,
        "scope": scope.strip(),
        "reviewer": reviewer.strip(),
        "reviewed_at_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "decision": decision,
        "artifacts": [
            {"artifact_id": a.artifact_id, "path": a.path, "digest": a.declared_digest}
            for a in chain.artifacts
        ],
        "claims": [
            {
                "claim_id": c.claim_id,
                "statement": c.statement,
                "artifact_id": c.artifact_id,
                "reproduction": c.reproduction,
                "verdict": c.verdict,
            }
            for c in chain.claims
        ],
        "findings": [f.as_dict() for f in findings],
    }
    statement["fingerprint"] = fingerprint(statement)
    return statement


def verify_statement(statement: dict) -> bool:
    """True when the statement still hashes to the fingerprint it carries."""
    claimed = statement.get("fingerprint")
    if not isinstance(claimed, str) or not claimed:
        return False
    return fingerprint(statement) == claimed


def render(statement: dict) -> str:
    """A plain-text rendering, for people who will read it rather than parse it."""
    lines = [
        "INDEPENDENT REVIEW STATEMENT",
        "=" * 60,
        f"subject   : {statement.get('subject') or '(unnamed)'}",
        f"reviewer  : {statement['reviewer']}",
        f"issued    : {statement['reviewed_at_utc']}",
        f"decision  : {statement['decision']}",
        "",
        "SCOPE",
        f"  {statement['scope']}",
        "",
        "ARTIFACTS",
    ]
    for a in statement["artifacts"]:
        lines.append(f"  {a['artifact_id']:<20} {a['digest']}")
        lines.append(f"  {'':<20} {a['path']}")
    lines.append("")
    lines.append("CLAIMS")
    for c in statement["claims"]:
        verdict = c["verdict"] or "NOT CHECKED"
        lines.append(f"  [{verdict:^13}] {c['claim_id']}: {c['statement']}")
        if c["reproduction"]:
            lines.append(f"                  $ {c['reproduction']}")
    findings = statement["findings"]
    lines.append("")
    lines.append(f"FINDINGS ({len(findings)})")
    if not findings:
        lines.append("  none")
    for f in findings:
        mark = "BLOCKING" if f["blocking"] else "note"
        lines.append(f"  [{mark}] {f['code']}: {f['detail']}")
    lines.append("")
    lines.append(f"fingerprint : {statement['fingerprint']}")
    lines.append("")
    lines.append(
        "This fingerprint is a SHA-256 over this statement's own canonical form."
    )
    lines.append(
        "Recompute it with attest.fingerprint(); any edit to any field breaks it."
    )
    return "\n".join(lines)
