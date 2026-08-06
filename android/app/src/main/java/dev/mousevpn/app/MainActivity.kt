package dev.mousevpn.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ArrayAdapter
import android.widget.AdapterView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {
    private lateinit var endpoint: EditText
    private lateinit var profileName: EditText
    private lateinit var profileSpinner: Spinner
    private lateinit var password: EditText
    private lateinit var status: TextView
    private lateinit var store: ProfileStore
    private var profiles: List<VpnProfile> = emptyList()
    private var refreshing = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            status.text = intent?.getStringExtra(MouseVpnService.EXTRA_STATUS) ?: return
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        store = ProfileStore(this)
        profileName = findViewById(R.id.profileName)
        profileSpinner = findViewById(R.id.profileSpinner)
        endpoint = findViewById(R.id.serverEndpoint)
        password = findViewById(R.id.profilePassword)
        status = findViewById(R.id.statusText)
        profileSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                if (!refreshing && position in profiles.indices) {
                    store.select(profiles[position].id)
                    showProfile(profiles[position])
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
        refreshProfiles()

        findViewById<Button>(R.id.pasteProfile).setOnClickListener { pasteProfile() }
        findViewById<Button>(R.id.copyProfile).setOnClickListener { copyProfile() }
        findViewById<Button>(R.id.saveProfile).setOnClickListener { saveCurrent() }
        findViewById<Button>(R.id.deleteProfile).setOnClickListener { deleteCurrent() }
        findViewById<Button>(R.id.excludedApps).setOnClickListener {
            startActivity(Intent(this, AppListActivity::class.java))
        }
        findViewById<Button>(R.id.connectButton).setOnClickListener { requestConnection() }
        findViewById<Button>(R.id.disconnectButton).setOnClickListener {
            startService(Intent(this, MouseVpnService::class.java).setAction(MouseVpnService.ACTION_DISCONNECT))
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 42)
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(MouseVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION") registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    private fun pasteProfile() = reportErrors {
        val encoded = clipboard().primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()
        require(!encoded.isNullOrBlank()) { "Буфер обмена пуст" }
        val profile = ProfileCrypto.decrypt(encoded, passwordChars())
        store.save(profile)
        refreshProfiles(profile.id)
        password.text.clear()
        toast("Профиль расшифрован и сохранён")
    }

    private fun copyProfile() = reportErrors {
        val profile = editedProfile()
        store.save(profile)
        val encoded = ProfileCrypto.encrypt(profile, passwordChars())
        clipboard().setPrimaryClip(ClipData.newPlainText("MouseVPN encrypted profile", encoded))
        password.text.clear()
        toast("Зашифрованный профиль скопирован")
    }

    private fun requestConnection() = reportErrors {
        store.save(editedProfile())
        val permission = VpnService.prepare(this)
        if (permission == null) connect() else startActivityForResult(permission, VPN_REQUEST)
    }

    @Deprecated("The platform VPN consent screen still uses an activity result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) connect()
    }

    private fun connect() {
        val intent = Intent(this, MouseVpnService::class.java).setAction(MouseVpnService.ACTION_CONNECT)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    private fun saveCurrent() = reportErrors {
        val profile = editedProfile()
        store.save(profile)
        refreshProfiles(profile.id)
        toast("Профиль сохранён")
    }

    private fun deleteCurrent() = reportErrors {
        val profile = requireNotNull(store.selected()) { "Нет выбранного профиля" }
        store.delete(profile.id)
        refreshProfiles()
        toast("Профиль удалён")
    }

    private fun editedProfile(): VpnProfile {
        val saved = requireNotNull(store.selected()) { "Сначала вставьте профиль" }
        return saved.copy(
            name = profileName.text.toString().trim(),
            endpoint = endpoint.text.toString().trim(),
        ).validate()
    }

    private fun refreshProfiles(selectId: String? = null) {
        profiles = runCatching { store.list() }.getOrElse {
            toast("Не удалось открыть профили: ${it.message}")
            emptyList()
        }
        val selectedId = selectId ?: runCatching { store.selected()?.id }.getOrNull()
        refreshing = true
        profileSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            profiles.map { "${it.name} — ${it.endpoint}" },
        )
        val index = profiles.indexOfFirst { it.id == selectedId }.coerceAtLeast(0)
        if (profiles.isNotEmpty()) {
            profileSpinner.setSelection(index)
            store.select(profiles[index].id)
            showProfile(profiles[index])
        } else {
            profileName.text.clear()
            endpoint.text.clear()
        }
        refreshing = false
    }

    private fun showProfile(profile: VpnProfile) {
        profileName.setText(profile.name)
        endpoint.setText(profile.endpoint)
    }

    private fun passwordChars(): CharArray {
        val value = password.text.toString().toCharArray()
        require(value.size >= 8) { "Введите пароль профиля (минимум 8 символов)" }
        return value
    }

    private fun clipboard(): ClipboardManager = getSystemService(ClipboardManager::class.java)

    private inline fun reportErrors(action: () -> Unit) {
        try {
            action()
        } catch (error: Exception) {
            toast(error.message ?: "Неизвестная ошибка")
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    private companion object {
        const val VPN_REQUEST = 10
    }
}
