package dev.mousevpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelMtuPolicyTest {
    @Test
    fun protocolModesMarkMorphEnvelopeCorrectly() {
        assertTrue(VpnProtocol.MORPH_BALANCED.usesMorph)
        assertFalse(VpnProtocol.SPEEDY.usesMorph)
    }

    @Test
    fun normalLinksKeepTheNegotiatedMtu() {
        assertEquals(1420, calculateTunnelMtu(1420, 1500, false))
        assertEquals(1280, calculateTunnelMtu(1280, 1500, true))
    }

    @Test
    fun mobileLinksReserveTheEntireMorphEnvelope() {
        assertEquals(1242, calculateTunnelMtu(1280, 1380, true))
        assertEquals(1142, calculateTunnelMtu(1280, 1280, true))
        assertEquals(1215, calculateTunnelMtu(1280, 1280, false))
    }

    @Test
    fun unknownLinkMtuDoesNotOverrideTheServer() {
        assertEquals(1280, calculateTunnelMtu(1280, null, true))
        assertEquals(1280, calculateTunnelMtu(1280, 0, true))
    }

    @Test
    fun neverRaisesAnAlreadySmallerServerMtu() {
        assertEquals(1000, calculateTunnelMtu(1000, 1280, true))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsALinkThatCannotCarryMinimumIpv4Packets() {
        calculateTunnelMtu(1280, 600, true)
    }
}
