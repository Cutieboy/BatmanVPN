package dev.mousevpn.app

import android.util.Base64
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object ProfileCrypto {
    private const val PREFIX = "MV1."
    private const val ITERATIONS = 210_000
    private const val KEY_BITS = 256
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private val aad = "MouseVPN profile v1".toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    fun encrypt(profile: VpnProfile, password: CharArray): String {
        require(password.size >= 8) { "Пароль должен содержать минимум 8 символов" }
        val salt = ByteArray(SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
        val key = derive(password, salt)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            val encrypted = cipher.doFinal(profile.validate().toJson().toByteArray(Charsets.UTF_8))
            val packed = ByteBuffer.allocate(SALT_SIZE + NONCE_SIZE + encrypted.size)
                .put(salt)
                .put(nonce)
                .put(encrypted)
                .array()
            PREFIX + Base64.encodeToString(packed, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } finally {
            key.fill(0)
            password.fill('\u0000')
        }
    }

    fun decrypt(encoded: String, password: CharArray): VpnProfile {
        require(encoded.startsWith(PREFIX)) { "Это не профиль MouseVPN" }
        val packed = Base64.decode(
            encoded.removePrefix(PREFIX).trim(),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        require(packed.size > SALT_SIZE + NONCE_SIZE + 16) { "Профиль повреждён" }
        val salt = packed.copyOfRange(0, SALT_SIZE)
        val nonce = packed.copyOfRange(SALT_SIZE, SALT_SIZE + NONCE_SIZE)
        val ciphertext = packed.copyOfRange(SALT_SIZE + NONCE_SIZE, packed.size)
        val key = derive(password, salt)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            VpnProfile.fromJson(cipher.doFinal(ciphertext).toString(Charsets.UTF_8))
        } finally {
            key.fill(0)
            password.fill('\u0000')
            ciphertext.fill(0)
        }
    }

    private fun derive(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
