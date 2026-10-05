package com.example.pinvault.server.service

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** A fetch target the server will not connect to. The message is safe to show the admin. */
class EgressRefusedException(message: String) : IllegalArgumentException(message)

/**
 * Where "fetch the certificate of this URL" may connect.
 *
 * The fetch is a TLS handshake to a host an administrator names, made from
 * inside the server's network. Unfiltered, it answers "is something listening
 * there, and which certificate does it serve" for every address the server can
 * reach: the cloud metadata service, the database next door, the loopback
 * admin ports.
 *
 *  - Always refused: link-local (169.254.0.0/16, fe80::/10 — the cloud
 *    metadata addresses live there), 100.100.100.200 and `fd00:ec2::254`
 *    (other providers' metadata), the unspecified address, multicast and
 *    broadcast.
 *  - Refused unless [allowPrivate] (`FETCH_ALLOW_PRIVATE_TARGETS=true`):
 *    loopback, RFC 1918 (10/8, 172.16/12, 192.168/16), carrier-grade NAT
 *    (100.64/10) and IPv6 unique-local (fc00::/7). A lab that pins hosts on its
 *    own LAN turns this on.
 *
 * The name is resolved ONCE, here, and the caller connects to the address that
 * was checked: a name that answers with a public address for the check and a
 * private one for the connection (DNS rebinding) gets nowhere.
 */
class EgressFilter(
    val allowPrivate: Boolean = false,
    private val resolve: (String) -> Array<InetAddress> = InetAddress::getAllByName
) {
    /** The address to connect to for [host]. @throws EgressRefusedException when it may not be reached. */
    fun resolveChecked(host: String): InetAddress {
        val address = try {
            resolve(host).firstOrNull()
        } catch (e: java.net.UnknownHostException) {
            null
        } ?: throw EgressRefusedException("$host does not resolve to an address")
        refusal(address)?.let { throw EgressRefusedException("$host resolves to ${address.hostAddress}: $it") }
        return address
    }

    /** Why [address] is refused, or null when it may be reached. */
    fun refusal(address: InetAddress): String? = when {
        address.isAnyLocalAddress -> "the unspecified address is never fetched"
        address.isLinkLocalAddress || isMetadata(address) ->
            "link-local and cloud-metadata addresses are never fetched"
        address.isMulticastAddress || isBroadcast(address) -> "multicast and broadcast addresses are never fetched"
        allowPrivate -> null
        address.isLoopbackAddress -> "loopback targets need FETCH_ALLOW_PRIVATE_TARGETS=true"
        address.isSiteLocalAddress || isCarrierGradeNat(address) || isUniqueLocal(address) ->
            "private-network targets need FETCH_ALLOW_PRIVATE_TARGETS=true"
        else -> null
    }

    private fun isMetadata(address: InetAddress): Boolean {
        val bytes = address.address
        return when (address) {
            // 100.100.100.200 (inside 100.64/10, but refused even when private targets are allowed).
            is Inet4Address -> bytes[0] == 100.toByte() && bytes[1] == 100.toByte() && bytes[2] == 100.toByte() && bytes[3] == 200.toByte()
            // fd00:ec2::254
            is Inet6Address -> bytes[0] == 0xfd.toByte() && bytes[1] == 0.toByte() && bytes[2] == 0x0e.toByte() && bytes[3] == 0xc2.toByte() &&
                (4..13).all { bytes[it] == 0.toByte() } && bytes[14] == 0x02.toByte() && bytes[15] == 0x54.toByte()
            else -> false
        }
    }

    private fun isBroadcast(address: InetAddress): Boolean =
        address is Inet4Address && address.address.all { it == 0xff.toByte() }

    private fun isCarrierGradeNat(address: InetAddress): Boolean =
        address is Inet4Address && address.address[0] == 100.toByte() && (address.address[1].toInt() and 0xc0) == 0x40

    private fun isUniqueLocal(address: InetAddress): Boolean =
        address is Inet6Address && (address.address[0].toInt() and 0xfe) == 0xfc

    companion object {
        fun fromEnv(env: Map<String, String> = System.getenv()) = EgressFilter(env["FETCH_ALLOW_PRIVATE_TARGETS"] == "true")
    }
}
