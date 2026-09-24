"""attest — hash-bound review statements for frozen evidence packages.

An attestation that can be edited after it is issued is not one. Every
statement this package produces carries a fingerprint computed over its own
canonical form, so a single changed character breaks the identifier the
statement is known by.

The outcome is one of three, never two: ATTESTED, NOT_ATTESTED, or
CANNOT_VERIFY. The third exists because a claim nobody checked must not be
allowed to read as a claim that passed.
"""

from attest.core import (
    ATTESTED,
    CANNOT_VERIFY,
    NOT_ATTESTED,
    Artifact,
    Claim,
    EvidenceChain,
    Finding,
    digest_bytes,
    digest_file,
    digest_path,
    digest_tree,
    fingerprint,
    issue_statement,
    render,
    verify_statement,
)

__version__ = "0.1.0"

__all__ = [
    "ATTESTED",
    "NOT_ATTESTED",
    "CANNOT_VERIFY",
    "Artifact",
    "Claim",
    "EvidenceChain",
    "Finding",
    "digest_bytes",
    "digest_file",
    "digest_path",
    "digest_tree",
    "fingerprint",
    "issue_statement",
    "render",
    "verify_statement",
    "__version__",
]
