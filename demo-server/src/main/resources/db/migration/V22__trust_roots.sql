-- Managed trust roots (ATTESTATION.md §10): per Config API, a JSON array of
-- SHA-256 SPKI pins of root CAs. A library block with managedTrustRoots()
-- accepts, for a host that has no pin entry, a chain the platform validates
-- to one of these roots. Part of the signed pin config payload (`trustRoots`),
-- so a change rolls out like a pin change.
ALTER TABLE pin_config ADD COLUMN trust_roots TEXT NOT NULL DEFAULT '[]';
