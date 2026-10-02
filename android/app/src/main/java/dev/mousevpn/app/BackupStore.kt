package dev.mousevpn.app

import android.content.Context
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/**
 * Password-protected portable backup.
 *
 * The backup deliberately does not depend on Android Keystore, because a
 * backup must remain importable after the app data and its Keystore entry
 * have been deleted.
 */
class BackupStore(private val context: Context) {
    fun export(password: CharArray): ByteArray {
        require(password.size >= MIN_PASSWORD_LENGTH) {
            "Пароль резервной копии должен содержать не менее $MIN_PASSWORD_LENGTH символов"
        }

        val snapshot = JSONObject()
            .put("format", FORMAT_VERSION)
            .put("app", "BatmanVPN")
            .put("profiles", ProfileStore(context).exportJson())
            .put("routing", ExcludedApps(context).exportJson())
            .toString()

        return encrypt(snapshot, password).toByteArray(StandardCharsets.UTF_8)
    }

    fun import(data: ByteArray, password: CharArray) {
        require(password.size >= MIN_PASSWORD_LENGTH) {
            "Пароль резервной копии должен содержать не менее $MIN_PASSWORD_LENGTH символов"
        }

        val root = decrypt(String(data, StandardCharsets.UTF_8), password)
        require(root.optInt("format", -1) == FORMAT_VERSION) {
            "Неподдерживаемый формат резервной копии"
        }

        val profiles = root.optJSONObject("profiles")
            ?: throw IllegalArgumentException("В резервной копии отсутствуют профили")
        val routing = root.optJSONObject("routing")
            ?: throw IllegalArgumentException("В резервной копии отсутствует маршрутизация")

        // Validate the complete payload before changing any local data.
        val profileStore = ProfileStore(context)
        val profileCount = profiles.getJSONArray("profiles").length()
        val selected = profiles.optString("selected")
        if (selected.isNotBlank() && selected != "null") {
            val ids = buildSet {
                val values = profiles.getJSONArray("profiles")
                for (index in 0 until values.length()) {
                    add(values.getJSONObject(index).getString("id"))
                }
            }
            require(ids.contains(selected)) {
                "Выбранный профиль отсутствует в резервной копии"
            }
        }
        require(profileCount >= 0) { "Повреждён список профилей" }

        // ProfileStore performs full profile validation before writing its
        // encrypted local representation. Routing data contains only package
        // names and a validated enum, so both stores can now be replaced.
        profileStore.importJson(profiles)
        ExcludedApps(context).importJson(routing)
    }

    private fun encrypt(plaintext: String, password: CharArray): String {
        val salt = ByteArray(SALT_SIZE).also(secureRandom::nextBytes)
        val iv = ByteArray(IV_SIZE).also(secureRandom::nextBytes)
        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(AAD)
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        return JSONObject()
            .put("format", FORMAT_VERSION)
            .put("kdf", "PBKDF2WithHmacSHA256")
            .put("iterations", KDF_ITERATIONS)
            .put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .toString()
    }

    private fun decrypt(encoded: String, password: CharArray): JSONObject {
        val envelope = try {
            JSONObject(encoded)
        } catch (_: Exception) {
            throw IllegalArgumentException("Файл не является резервной копией BatmanVPN")
        }

        require(envelope.optInt("format", -1) == FORMAT_VERSION) {
            "Неподдерживаемый формат резервной копии"
        }
        require(envelope.optString("kdf") == "PBKDF2WithHmacSHA256") {
            "Неподдерживаемый алгоритм защиты резервной копии"
        }
        val iterations = envelope.optInt("iterations", -1)
        require(iterations == KDF_ITERATIONS) {
            "Неподдерживаемые параметры защиты резервной копии"
        }

        val salt = decode(envelope, "salt")
        val iv = decode(envelope, "iv")
        val ciphertext = decode(envelope, "ciphertext")
        require(salt.size == SALT_SIZE && iv.size == IV_SIZE && ciphertext.size > TAG_SIZE) {
            "Резервная копия повреждена"
        }

        return try {
            val key = deriveKey(password, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(AAD)
            JSONObject(String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8))
        } catch (_: Exception) {
            throw IllegalArgumentException("Неверный пароль или повреждённая резервная копия")
        }
    }

    private fun decode(envelope: JSONObject, name: String): ByteArray = try {
        Base64.decode(envelope.getString(name), Base64.NO_WRAP)
    } catch (_: Exception) {
        throw IllegalArgumentException("Резервная копия повреждена")
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, KDF_ITERATIONS, KEY_BITS)
        return try {
            SecretKeySpec(
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .encoded,
                "AES",
            )
        } finally {
            spec.clearPassword()
        }
    }

    private companion object {
        const val FORMAT_VERSION = 1
        const val MIN_PASSWORD_LENGTH = 8
        const val KDF_ITERATIONS = 150_000
        const val KEY_BITS = 256
        const val TAG_BITS = 128
        const val TAG_SIZE = 16
        const val SALT_SIZE = 16
        const val IV_SIZE = 12
        val AAD = "BatmanVPN backup v1".toByteArray(StandardCharsets.UTF_8)
        val secureRandom = SecureRandom()
    }
}
