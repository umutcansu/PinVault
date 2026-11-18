-- Every CSR a renewal accepted, per identity (review 2026-11-17).
-- The recovery door takes no client certificate: the signed CSR is the proof,
-- so a copy of an accepted request must not renew again. Only the LAST
-- accepted request was remembered (client_identities.last_renewal_csr_sha256),
-- as the hash of its whole DER: an older copy renewed again once a newer
-- renewal had gone through, and so did the same request with its ECDSA
-- signature written the other way round ((r, n - s) verifies like (r, s)).
-- csr_key is the SHA-256 of what was signed plus the signature in one
-- canonical form (CertificateService.CsrCandidate.replayKey).
CREATE TABLE IF NOT EXISTS client_renewal_csrs (
    client_id   TEXT NOT NULL,
    csr_key     TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (client_id, csr_key)
);
