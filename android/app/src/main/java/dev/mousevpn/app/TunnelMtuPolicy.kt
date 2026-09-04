package dev.mousevpn.app

/** Keep the largest possible outer datagram within the physical link's MTU. */
internal fun calculateTunnelMtu(serverMtu: Int, underlyingMtu: Int?, morph: Boolean): Int {
    if (underlyingMtu == null || underlyingMtu <= 0) return serverMtu
    // IPv4 + UDP + MouseVPN header + inner kind + Noise authentication tag.
    val overhead = 65 + if (morph) 73 else 0
    // MouseMorph adds: route 8 + nonce 12 + inner header 6 + tag 16 + padding <= 31.
    val fits = underlyingMtu - overhead
    require(fits >= 576) { "MTU физической сети слишком мал для VPN" }
    // This tunnel carries IPv4 only; the IPv6 minimum of 1280 is not its floor.
    return minOf(serverMtu, fits)
}
