package dev.mousevpn.app

internal class InitialConnectBudget(private val maximumFailures: Int) {
    init {
        require(maximumFailures > 0) { "maximumFailures must be positive" }
    }

    var failures: Int = 0
        private set

    var connected: Boolean = false
        private set

    fun recordConnected() {
        connected = true
    }

    /** Returns true when an initial manual connection must stop retrying. */
    fun recordFailure(): Boolean {
        if (connected) return false
        failures++
        return failures >= maximumFailures
    }
}

internal fun connectionErrorDetail(message: String?): String {
    val detail = message?.trim().orEmpty()
    val normalized = detail.lowercase()
    return when {
        "handshake timed out" in normalized -> "Сервер не ответил за 10 секунд"
        "network is unreachable" in normalized ||
            "network unreachable" in normalized ||
        "network is down" in normalized -> "Нет доступа к сети"
        "connection refused" in normalized -> "Сервер отклонил соединение"
        "android refused to protect" in normalized ->
            "Android не разрешил открыть транспорт VPN; отключите другой VPN и повторите"
        "udp connect failed" in normalized -> "Не удалось открыть UDP-соединение"
        detail.isBlank() -> "Неизвестная ошибка подключения"
        else -> detail.take(MAX_CONNECTION_ERROR_LENGTH)
    }
}

private const val MAX_CONNECTION_ERROR_LENGTH = 180
