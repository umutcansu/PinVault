package io.github.umutcansu.pinvault.model

/**
 * A signed pin config was refused because it answers another request than
 * the one this Config API block makes (its signed `view` field, M6).
 *
 * The server signs narrowed views — `wantPinsFor(...)` (`?hosts=`), a device's
 * host ACL (`X-Device-Id`), the config inside an attestation answer — and
 * names in the payload what narrowed them. Whoever can answer as the Config
 * API without the signing key (a pinned TLS key, a proxy or CDN in front)
 * could otherwise hand a device that asks for the full config a genuine,
 * fresh, narrow view, and every other host would lose its pins. Refused:
 *
 *  - a narrowed view (`view` present) for a block that asks for the full config;
 *  - for a block with `wantPinsFor(...)`, a view naming another host set or
 *    another device id (or a malformed `view`).
 *
 * The config in use and the store are left as they were. Reported like the
 * other signed-config refusals ([UpdateResult.Failed], `config_update_failed`).
 * A stored config whose view no longer matches the block (its `wantPinsFor`
 * list changed in an app update) is not refused this way: it is discarded and
 * fetched again.
 */
class ConfigViewMismatchException(message: String) : SecurityException(message)
