package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.ssl.hardenHops
import okhttp3.OkHttpClient

/**
 * **Not public API.** For PinVault's own bridges (the React Native plugin);
 * it may change or go in any release, and apps have no use for it — an app
 * hands its builder to `PinVault.applyTo`, which does all of this.
 *
 * React Native builds its OkHttp clients itself, some of them before
 * `PinVault.init` and one per request, so the plugin cannot pass them to
 * `applyTo` (which needs an initialised library and makes a socket factory
 * per call). It copies the pinned socket factory and the interceptors of one
 * `applyTo` client onto React Native's builders instead. Two parts of
 * `applyTo` cannot be copied that way — the connection specs and the cookie
 * jar wrapper are not interceptors — and they are exactly what keeps a
 * client off plain HTTP and stops a redirected WebSocket upgrade. This hands
 * them over as the one implementation `applyTo` itself uses.
 */
object BridgeNetworking {

    /**
     * Gives [builder] the parts of `PinVault.applyTo` that need neither an
     * initialised library nor a pin config:
     *
     *  - the redirect guard (a redirect to another origin takes neither the
     *    request's own headers nor its body along) and the WebSocket upgrade
     *    guard (an upgrade redirected to another origin fails), each added
     *    once however often this is called;
     *  - with [httpsOnly], no cleartext connection spec — the builder's TLS
     *    specs are kept — so `http://` and `ws://` fail before anything is
     *    sent;
     *  - with [wrapCookieJar], the wrapper around the builder's cookie jar
     *    through which a redirected upgrade is stopped BEFORE it is sent
     *    (without it the upgrade is only failed afterwards). The builder's
     *    own jar keeps working behind it. Pass false for a client whose
     *    `cookieJar` something else reads back by type (React Native's base
     *    client: `CookieJarContainer`), and set the builder's cookie jar
     *    before this call, not after.
     *
     * Set the builder's `sslSocketFactory` first: with [httpsOnly] or
     * [wrapCookieJar] a client is built from the builder to read what it
     * holds.
     */
    @JvmStatic
    fun hardenBuilder(builder: OkHttpClient.Builder, httpsOnly: Boolean, wrapCookieJar: Boolean) {
        builder.hardenHops(httpsOnly, wrapCookieJar)
    }
}
