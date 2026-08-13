package dev.mousevpn.app

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject

data class DiagnosticMetrics(
    val packetsSent: Long = 0,
    val bytesSent: Long = 0,
    val packetsReceived: Long = 0,
    val bytesReceived: Long = 0,
    val tunDrops: Long = 0,
    val udpSendDrops: Long = 0,
    val reconnects: Long = 0,
    val lastReconnectMs: Long = 0,
    val networkChanges: Long = 0,
    val sessionTimeouts: Long = 0,
    val peerUnreachable: Long = 0,
    val reconnectFailures: Long = 0,
    val invalidDatagrams: Long = 0,
    val keepalivesSent: Long = 0,
    val keepaliveResponses: Long = 0,
    val lastKeepaliveRttMs: Long = 0,
    val maxKeepaliveRttMs: Long = 0,
) {
    companion object {
        fun parse(json: String): DiagnosticMetrics = JSONObject(json).let { value ->
            DiagnosticMetrics(
                packetsSent = value.optLong("packetsSent"),
                bytesSent = value.optLong("bytesSent"),
                packetsReceived = value.optLong("packetsReceived"),
                bytesReceived = value.optLong("bytesReceived"),
                tunDrops = value.optLong("tunDrops"),
                udpSendDrops = value.optLong("udpSendDrops"),
                reconnects = value.optLong("reconnects"),
                lastReconnectMs = value.optLong("lastReconnectMs"),
                networkChanges = value.optLong("networkChanges"),
                sessionTimeouts = value.optLong("sessionTimeouts"),
                peerUnreachable = value.optLong("peerUnreachable"),
                reconnectFailures = value.optLong("reconnectFailures"),
                invalidDatagrams = value.optLong("invalidDatagrams"),
                keepalivesSent = value.optLong("keepalivesSent"),
                keepaliveResponses = value.optLong("keepaliveResponses"),
                lastKeepaliveRttMs = value.optLong("lastKeepaliveRttMs"),
                maxKeepaliveRttMs = value.optLong("maxKeepaliveRttMs"),
            )
        }
    }
}

/**
 * Small, local-only journal used to diagnose tunnel failures after they happen.
 *
 * There are no timers or network calls here. The VPN service writes one row at
 * connection start, updates it at most once per minute and completes it when
 * the session ends. Old rows are bounded by both age and count.
 */
class DiagnosticStore(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION,
) {
    override fun onCreate(database: SQLiteDatabase) {
        database.execSQL(
            """
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at INTEGER NOT NULL,
                connected_at INTEGER,
                ended_at INTEGER,
                profile_name TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                initial_network TEXT NOT NULL,
                final_network TEXT,
                outcome TEXT NOT NULL,
                detail TEXT,
                packets_sent INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                packets_received INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                tun_drops INTEGER NOT NULL DEFAULT 0,
                udp_send_drops INTEGER NOT NULL DEFAULT 0,
                reconnects INTEGER NOT NULL DEFAULT 0,
                last_reconnect_ms INTEGER NOT NULL DEFAULT 0,
                network_changes INTEGER NOT NULL DEFAULT 0,
                session_timeouts INTEGER NOT NULL DEFAULT 0,
                peer_unreachable INTEGER NOT NULL DEFAULT 0,
                reconnect_failures INTEGER NOT NULL DEFAULT 0,
                invalid_datagrams INTEGER NOT NULL DEFAULT 0,
                keepalives_sent INTEGER NOT NULL DEFAULT 0,
                keepalive_responses INTEGER NOT NULL DEFAULT 0,
                last_keepalive_rtt_ms INTEGER NOT NULL DEFAULT 0,
                max_keepalive_rtt_ms INTEGER NOT NULL DEFAULT 0
            )
            """.trimIndent(),
        )
        database.execSQL("CREATE INDEX sessions_started_at ON sessions(started_at DESC)")
    }

    override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun begin(profile: VpnProfile, network: String, now: Long = System.currentTimeMillis()): Long {
        val database = writableDatabase
        database.beginTransaction()
        return try {
            val abandoned = ContentValues().apply {
                put("ended_at", now)
                put("outcome", "process_stopped")
                put("detail", "Предыдущая сессия завершилась без финального события")
            }
            database.update("sessions", abandoned, "ended_at IS NULL", null)
            prune(database, now)
            val values = ContentValues().apply {
                put("started_at", now)
                put("profile_name", profile.name)
                put("endpoint", profile.endpoint)
                put("initial_network", network)
                put("outcome", "connecting")
            }
            database.insertOrThrow("sessions", null, values).also { database.setTransactionSuccessful() }
        } finally {
            database.endTransaction()
        }
    }

    fun connected(sessionId: Long, network: String, now: Long = System.currentTimeMillis()) {
        writableDatabase.update(
            "sessions",
            ContentValues().apply {
                put("connected_at", now)
                put("final_network", network)
                put("outcome", "connected")
            },
            "id = ?",
            arrayOf(sessionId.toString()),
        )
    }

    fun checkpoint(sessionId: Long, metrics: DiagnosticMetrics, network: String) {
        writableDatabase.update(
            "sessions",
            metrics.values().apply { put("final_network", network) },
            "id = ? AND ended_at IS NULL",
            arrayOf(sessionId.toString()),
        )
    }

    fun finish(
        sessionId: Long,
        outcome: String,
        detail: String?,
        metrics: DiagnosticMetrics,
        network: String,
        now: Long = System.currentTimeMillis(),
    ) {
        writableDatabase.update(
            "sessions",
            metrics.values().apply {
                put("ended_at", now)
                put("final_network", network)
                put("outcome", outcome)
                put("detail", detail?.take(MAX_DETAIL_LENGTH))
            },
            "id = ? AND ended_at IS NULL",
            arrayOf(sessionId.toString()),
        )
    }

    fun summary(limit: Int = 30): String {
        val rows = recent(limit)
        if (rows.length() == 0) return "Диагностических сессий пока нет."
        var reconnects = 0L
        var timeouts = 0L
        var failures = 0
        for (index in 0 until rows.length()) {
            val row = rows.getJSONObject(index)
            reconnects += row.optLong("reconnects")
            timeouts += row.optLong("sessionTimeouts")
            if (row.optString("outcome") !in setOf("user_disconnect", "connected")) failures++
        }
        val latest = rows.getJSONObject(0)
        return buildString {
            append("Последние сессии: ${rows.length()}\n")
            append("Аварийные завершения: $failures\n")
            append("Переподключения: $reconnects\n")
            append("Таймауты ответа сервера: $timeouts\n\n")
            append("Последняя сессия\n")
            append("Сервер: ${latest.optString("endpoint")}\n")
            append("Результат: ${latest.optString("outcome")}\n")
            append("Сеть: ${latest.optString("initialNetwork")} → ${latest.optString("finalNetwork")}\n")
            append("UDP недоступен: ${latest.optLong("peerUnreachable")}\n")
            append("Ошибки reconnect: ${latest.optLong("reconnectFailures")}\n")
            val unanswered = (latest.optLong("keepalivesSent") -
                latest.optLong("keepaliveResponses")).coerceAtLeast(0)
            append("Неотвеченные keepalive: $unanswered\n")
            append("Последний RTT keepalive: ${latest.optLong("lastKeepaliveRttMs")} мс\n")
            append("Максимальный RTT: ${latest.optLong("maxKeepaliveRttMs")} мс\n")
            latest.optString("detail").takeIf(String::isNotBlank)?.let { append("Детали: $it") }
        }
    }

    fun exportJson(limit: Int = MAX_ROWS): String = JSONObject().apply {
        put("format", "mousevpn-diagnostics-v1")
        put("generatedAt", System.currentTimeMillis())
        put("privacy", "No traffic contents, destinations or cryptographic keys are collected")
        put("sessions", recent(limit))
    }.toString(2)

    fun clear() {
        writableDatabase.delete("sessions", null, null)
    }

    private fun recent(limit: Int): JSONArray {
        val result = JSONArray()
        readableDatabase.query(
            "sessions",
            null,
            null,
            null,
            null,
            null,
            "started_at DESC",
            limit.coerceIn(1, MAX_ROWS).toString(),
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result.put(JSONObject().apply {
                    put("startedAt", cursor.long("started_at"))
                    put("connectedAt", cursor.nullableLong("connected_at"))
                    put("endedAt", cursor.nullableLong("ended_at"))
                    put("profile", cursor.string("profile_name"))
                    put("endpoint", cursor.string("endpoint"))
                    put("initialNetwork", cursor.string("initial_network"))
                    put("finalNetwork", cursor.string("final_network"))
                    put("outcome", cursor.string("outcome"))
                    put("detail", cursor.string("detail"))
                    METRIC_COLUMNS.forEach { (json, column) -> put(json, cursor.long(column)) }
                })
            }
        }
        return result
    }

    private fun prune(database: SQLiteDatabase, now: Long) {
        database.delete("sessions", "started_at < ?", arrayOf((now - RETENTION_MS).toString()))
        database.execSQL(
            "DELETE FROM sessions WHERE id NOT IN (SELECT id FROM sessions ORDER BY started_at DESC LIMIT $MAX_ROWS)",
        )
    }

    private fun DiagnosticMetrics.values() = ContentValues().apply {
        put("packets_sent", packetsSent)
        put("bytes_sent", bytesSent)
        put("packets_received", packetsReceived)
        put("bytes_received", bytesReceived)
        put("tun_drops", tunDrops)
        put("udp_send_drops", udpSendDrops)
        put("reconnects", reconnects)
        put("last_reconnect_ms", lastReconnectMs)
        put("network_changes", networkChanges)
        put("session_timeouts", sessionTimeouts)
        put("peer_unreachable", peerUnreachable)
        put("reconnect_failures", reconnectFailures)
        put("invalid_datagrams", invalidDatagrams)
        put("keepalives_sent", keepalivesSent)
        put("keepalive_responses", keepaliveResponses)
        put("last_keepalive_rtt_ms", lastKeepaliveRttMs)
        put("max_keepalive_rtt_ms", maxKeepaliveRttMs)
    }

    private fun android.database.Cursor.long(name: String) = getLong(getColumnIndexOrThrow(name))
    private fun android.database.Cursor.nullableLong(name: String): Long? =
        getColumnIndexOrThrow(name).let { if (isNull(it)) null else getLong(it) }
    private fun android.database.Cursor.string(name: String): String =
        getColumnIndexOrThrow(name).let { if (isNull(it)) "" else getString(it) }

    private companion object {
        const val DATABASE_NAME = "diagnostics.db"
        const val DATABASE_VERSION = 1
        const val MAX_ROWS = 100
        const val MAX_DETAIL_LENGTH = 500
        const val RETENTION_MS = 30L * 24 * 60 * 60 * 1_000
        val METRIC_COLUMNS = listOf(
            "packetsSent" to "packets_sent",
            "bytesSent" to "bytes_sent",
            "packetsReceived" to "packets_received",
            "bytesReceived" to "bytes_received",
            "tunDrops" to "tun_drops",
            "udpSendDrops" to "udp_send_drops",
            "reconnects" to "reconnects",
            "lastReconnectMs" to "last_reconnect_ms",
            "networkChanges" to "network_changes",
            "sessionTimeouts" to "session_timeouts",
            "peerUnreachable" to "peer_unreachable",
            "reconnectFailures" to "reconnect_failures",
            "invalidDatagrams" to "invalid_datagrams",
            "keepalivesSent" to "keepalives_sent",
            "keepaliveResponses" to "keepalive_responses",
            "lastKeepaliveRttMs" to "last_keepalive_rtt_ms",
            "maxKeepaliveRttMs" to "max_keepalive_rtt_ms",
        )
    }
}
