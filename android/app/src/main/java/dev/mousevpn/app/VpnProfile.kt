package dev.mousevpn.app

import android.util.Base64
import org.json.JSONObject
import java.util.UUID

data class VpnProfile(
    val id: String,
    val name: String,
    val endpoint: String,
    val serverPublicKey: String,
    val clientPrivateKey: String,
) {
    fun validate(): VpnProfile {
        require(isValidEndpoint(endpoint)) { "Неверный IPv4:port" }
        require(id.isNotBlank()) { "У профиля нет идентификатора" }
        require(name.isNotBlank()) { "Введите имя профиля" }
        require(decodeKey(serverPublicKey).size == KEY_SIZE) { "Неверный ключ сервера" }
        require(decodeKey(clientPrivateKey).size == KEY_SIZE) { "Неверный ключ клиента" }
        return this
    }

    fun toJson(): String = JSONObject()
        .put("version", 1)
        .put("id", id)
        .put("name", name)
        .put("endpoint", endpoint)
        .put("serverPublicKey", serverPublicKey)
        .put("clientPrivateKey", clientPrivateKey)
        .toString()

    companion object {
        private const val KEY_SIZE = 32

        fun fromJson(json: String): VpnProfile {
            val value = JSONObject(json)
            require(value.getInt("version") == 1) { "Неподдерживаемая версия профиля" }
            return VpnProfile(
                id = value.optString("id").ifBlank { UUID.randomUUID().toString() },
                name = value.optString("name").ifBlank { value.getString("endpoint") },
                endpoint = value.getString("endpoint"),
                serverPublicKey = value.getString("serverPublicKey"),
                clientPrivateKey = value.getString("clientPrivateKey"),
            ).validate()
        }

        private fun decodeKey(value: String): ByteArray =
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        private fun isValidEndpoint(value: String): Boolean {
            val separator = value.lastIndexOf(':')
            if (separator <= 0 || separator == value.lastIndex) return false
            val octets = value.substring(0, separator).split('.')
            val port = value.substring(separator + 1).toIntOrNull()
            return octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 } && port in 1..65535
        }
    }
}
