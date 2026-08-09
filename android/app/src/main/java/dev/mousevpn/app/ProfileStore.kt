package dev.mousevpn.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray

class ProfileStore(context: Context) {
    private val preferences = context.getSharedPreferences("mousevpn_secure", Context.MODE_PRIVATE)
    private val key: SecretKey by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { loadOrCreateKey() }
    private var cachedEncodedProfiles: String? = null
    private var cachedProfiles: List<VpnProfile>? = null

    @Synchronized
    fun save(profile: VpnProfile, select: Boolean = true) {
        val profiles = list().toMutableList()
        val index = profiles.indexOfFirst { it.id == profile.id }
        if (index >= 0) profiles[index] = profile.validate() else profiles.add(profile.validate())
        write(profiles)
        if (select) preferences.edit().putString(SELECTED, profile.id).apply()
    }

    @Synchronized
    fun list(): List<VpnProfile> {
        val encoded = preferences.getString(PROFILES, null)
        if (encoded == null) {
            cachedEncodedProfiles = null
            return emptyList<VpnProfile>().also { cachedProfiles = it }
        }
        if (encoded == cachedEncodedProfiles) cachedProfiles?.let { return it }
        val json = decrypt(encoded)
        val values = JSONArray(json)
        return (0 until values.length()).map { VpnProfile.fromJson(values.getString(it)) }.also {
            cachedEncodedProfiles = encoded
            cachedProfiles = it
        }
    }

    fun selected(): VpnProfile? {
        val profiles = list()
        val id = preferences.getString(SELECTED, null)
        return profiles.firstOrNull { it.id == id } ?: profiles.firstOrNull()
    }

    @Synchronized
    fun select(id: String) {
        require(list().any { it.id == id }) { "Профиль не найден" }
        preferences.edit().putString(SELECTED, id).apply()
    }

    @Synchronized
    fun delete(id: String) {
        val profiles = list().filterNot { it.id == id }
        write(profiles)
        preferences.edit().putString(SELECTED, profiles.firstOrNull()?.id).apply()
    }

    private fun write(profiles: List<VpnProfile>) {
        val values = JSONArray()
        profiles.forEach { values.put(it.toJson()) }
        val encoded = encrypt(values.toString())
        preferences.edit().putString(PROFILES, encoded).apply()
        cachedEncodedProfiles = encoded
        cachedProfiles = profiles.toList()
    }

    private fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(AAD)
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val packed = ByteBuffer.allocate(cipher.iv.size + ciphertext.size)
            .put(cipher.iv)
            .put(ciphertext)
            .array()
        return Base64.encodeToString(packed, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val packed = Base64.decode(encoded, Base64.NO_WRAP)
        require(packed.size > NONCE_SIZE + 16) { "Хранилище профиля повреждено" }
        val nonce = packed.copyOfRange(0, NONCE_SIZE)
        val ciphertext = packed.copyOfRange(NONCE_SIZE, packed.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(AAD)
        return cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
    }

    private fun loadOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            generateKey()
        }
    }

    private companion object {
        const val KEY_ALIAS = "mousevpn.profile.v1"
        const val PROFILES = "profiles"
        const val SELECTED = "selected"
        const val NONCE_SIZE = 12
        val AAD = "MouseVPN local profile v1".toByteArray(Charsets.UTF_8)
    }
}
