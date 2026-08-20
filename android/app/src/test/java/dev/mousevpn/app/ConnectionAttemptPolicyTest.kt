package dev.mousevpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionAttemptPolicyTest {
    @Test
    fun stopsAfterTheConfiguredNumberOfInitialFailures() {
        val budget = InitialConnectBudget(3)

        assertFalse(budget.recordFailure())
        assertFalse(budget.recordFailure())
        assertTrue(budget.recordFailure())
        assertEquals(3, budget.failures)
    }

    @Test
    fun reconnectsRemainUnlimitedAfterAWorkingSession() {
        val budget = InitialConnectBudget(3)
        budget.recordConnected()

        repeat(10) { assertFalse(budget.recordFailure()) }
        assertEquals(0, budget.failures)
    }

    @Test
    fun translatesTheNativeHandshakeTimeout() {
        assertEquals(
            "Сервер не ответил за 10 секунд",
            connectionErrorDetail("handshake timed out"),
        )
    }

    @Test
    fun explainsAndroidSocketProtectionFailure() {
        assertEquals(
            "Android не разрешил открыть транспорт VPN; отключите другой VPN и повторите",
            connectionErrorDetail("Android refused to protect or bind the UDP socket"),
        )
    }

    @Test
    fun limitsUnexpectedNativeErrorText() {
        assertEquals(180, connectionErrorDetail("x".repeat(500)).length)
    }
}
