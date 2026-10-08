package com.example.pinvault.server.service.attestation

/**
 * What the server checks of an iOS report (ATTESTATION.md §3) in place of
 * what Android takes from the key attestation settings: an iOS report has
 * no security patch date and no signer digest.
 *
 *  - [minOsVersion] (`ATTESTATION_MIN_IOS_VERSION`, dotted, e.g. `17.4`):
 *    `old_patch_level` when `device.osVersion` is older or not a version;
 *    null = not checked.
 *  - [teamIds] (`ATTESTATION_IOS_TEAM_IDS`, comma separated): `app_integrity`
 *    when `app.teamId` is not one of them; empty = not checked. The bundle id
 *    is checked against `ATTESTATION_PACKAGE_NAMES`, like an Android package.
 */
class IosAttestationRules(
    val minOsVersion: List<Int>? = null,
    val teamIds: Set<String> = emptySet()
) {
    /** True when [osVersion] is below [minOsVersion] or not a dotted version; false when nothing is configured. */
    fun osVersionTooOld(osVersion: String?): Boolean {
        val min = minOsVersion ?: return false
        val version = osVersion?.let { parseVersion(it) } ?: return true
        return compare(version, min) < 0
    }

    companion object {
        private val VERSION = Regex("^\\d{1,4}(\\.\\d{1,4}){0,3}$")
        private val TEAM_ID = Regex("^[A-Z0-9]{10}$")

        /** `26.5` → [26, 5]; null when it is not a dotted version. */
        fun parseVersion(text: String): List<Int>? = text.trim().takeIf { VERSION.matches(it) }?.split('.')?.map { it.toInt() }

        /** Component by component; a missing component is 0 (`17` = `17.0`). */
        fun compare(a: List<Int>, b: List<Int>): Int {
            for (i in 0 until maxOf(a.size, b.size)) {
                val c = (a.getOrElse(i) { 0 }).compareTo(b.getOrElse(i) { 0 })
                if (c != 0) return c
            }
            return 0
        }

        /** From the environment; a malformed value is a start-up error. */
        fun fromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): IosAttestationRules {
            val min = env["ATTESTATION_MIN_IOS_VERSION"]?.trim()?.takeIf { it.isNotEmpty() }?.let {
                parseVersion(it) ?: throw IllegalArgumentException("ATTESTATION_MIN_IOS_VERSION must be a dotted iOS version, e.g. 17.4 (got '$it')")
            }
            val teams = env["ATTESTATION_IOS_TEAM_IDS"].orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            teams.forEach { require(TEAM_ID.matches(it)) { "ATTESTATION_IOS_TEAM_IDS: '$it' is not a 10-character Apple team id" } }
            return IosAttestationRules(min, teams)
        }
    }
}
