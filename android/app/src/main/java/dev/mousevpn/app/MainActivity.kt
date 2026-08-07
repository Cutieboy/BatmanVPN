package dev.mousevpn.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var profileName: TextView
    private lateinit var endpoint: TextView
    private lateinit var statusTitle: TextView
    private lateinit var statusText: TextView
    private lateinit var powerButton: ImageButton
    private lateinit var statServer: TextView
    private lateinit var statTime: TextView
    private val handler = Handler(Looper.getMainLooper())
    private var connected = false
    private var connecting = false

    private val clock = object : Runnable {
        override fun run() {
            val since = MouseVpnService.connectedSinceElapsedRealtime
            statTime.text = if (connected && since > 0L) {
                formatDuration(SystemClock.elapsedRealtime() - since)
            } else {
                "—"
            }
            handler.postDelayed(this, 1_000)
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            applyStatus(intent?.getStringExtra(MouseVpnService.EXTRA_STATUS) ?: return)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<View>(R.id.mainContent).applySystemBarPadding(20, 18, 20, 20)
        store = ProfileStore(this)
        profileName = findViewById(R.id.profileName)
        endpoint = findViewById(R.id.serverEndpoint)
        statusTitle = findViewById(R.id.statusTitle)
        statusText = findViewById(R.id.statusText)
        powerButton = findViewById(R.id.powerButton)
        statServer = findViewById(R.id.statServerValue)
        statTime = findViewById(R.id.statTimeValue)

        findViewById<View>(R.id.addProfile).setOnClickListener { openAddProfile() }
        findViewById<View>(R.id.profileChooser).setOnClickListener { showProfileChooser() }
        findViewById<View>(R.id.profileMenu).setOnClickListener { showProfileMenu() }
        findViewById<View>(R.id.excludedApps).setOnClickListener {
            startActivity(Intent(this, AppListActivity::class.java))
        }
        powerButton.setOnClickListener {
            if (connected) disconnect() else if (!connecting) requestConnection()
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
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
        refreshProfile()
        applyStatus(MouseVpnService.currentStatus)
        handler.post(clock)
    }

    override fun onStop() {
        handler.removeCallbacks(clock)
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    private fun openAddProfile() {
        startActivity(Intent(this, AddProfileActivity::class.java))
    }

    private fun refreshProfile() {
        val profile = runCatching { store.selected() }.getOrElse {
            toast(getString(R.string.profile_open_error, it.message ?: ""))
            null
        }
        if (profile == null) {
            profileName.setText(R.string.no_profiles)
            endpoint.setText(R.string.add_profile_hint)
            statServer.text = "—"
        } else {
            profileName.text = profile.name
            endpoint.text = profile.endpoint
            statServer.text = profile.name
        }
        updatePowerEnabled()
    }

    private fun showProfileChooser() {
        val profiles = runCatching { store.list() }.getOrElse {
            toast(it.message ?: getString(R.string.unknown_error))
            return
        }
        if (profiles.isEmpty()) {
            openAddProfile()
            return
        }
        val selectedId = store.selected()?.id
        val dialog = Dialog(this).apply {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
            setContentView(R.layout.dialog_profile_chooser)
            window?.setBackgroundDrawableResource(android.R.color.transparent)
        }
        val options = dialog.findViewById<android.widget.LinearLayout>(R.id.profileOptions)
        profiles.forEach { profile ->
            val row = layoutInflater.inflate(R.layout.item_profile_option, options, false)
            row.findViewById<TextView>(R.id.optionName).text = profile.name
            row.findViewById<TextView>(R.id.optionEndpoint).text = profile.endpoint
            row.findViewById<View>(R.id.selectedIndicator).visibility =
                if (profile.id == selectedId) View.VISIBLE else View.INVISIBLE
            row.setOnClickListener {
                store.select(profile.id)
                refreshProfile()
                dialog.dismiss()
            }
            options.addView(row)
        }
        dialog.findViewById<View>(R.id.dialogAddProfile).setOnClickListener {
            dialog.dismiss()
            openAddProfile()
        }
        dialog.show()
        dialog.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
    }

    private fun showProfileMenu() {
        val selected = store.selected()
        val dialog = createDialog(R.layout.dialog_profile_menu)
        dialog.findViewById<TextView>(R.id.currentProfileName).text =
            selected?.name ?: getString(R.string.no_profiles)
        dialog.findViewById<View>(R.id.menuAddProfile).setOnClickListener {
            dialog.dismiss()
            openAddProfile()
        }
        dialog.findViewById<View>(R.id.menuDeleteProfile).apply {
            isEnabled = selected != null
            alpha = if (isEnabled) 1f else 0.42f
            setOnClickListener {
                dialog.dismiss()
                selected?.let(::showDeleteConfirmation)
            }
        }
        showDialog(dialog)
    }

    private fun showDeleteConfirmation(profile: VpnProfile) {
        val dialog = createDialog(R.layout.dialog_delete_profile)
        dialog.findViewById<TextView>(R.id.deleteMessage).text =
            getString(R.string.delete_profile_confirm, profile.name)
        dialog.findViewById<View>(R.id.cancelDelete).setOnClickListener { dialog.dismiss() }
        dialog.findViewById<View>(R.id.confirmDelete).setOnClickListener {
                store.delete(profile.id)
                refreshProfile()
                dialog.dismiss()
        }
        showDialog(dialog)
    }

    private fun createDialog(layout: Int): Dialog = Dialog(this).apply {
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(layout)
        window?.setBackgroundDrawableResource(android.R.color.transparent)
    }

    private fun showDialog(dialog: Dialog) {
        dialog.show()
        dialog.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
    }

    private fun requestConnection() {
        if (store.selected() == null) {
            openAddProfile()
            return
        }
        val permission = VpnService.prepare(this)
        if (permission == null) connect() else startActivityForResult(permission, VPN_REQUEST)
    }

    @Deprecated("The platform VPN consent screen still uses an activity result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) connect()
    }

    private fun connect() {
        applyStatus(getString(R.string.status_connecting))
        val intent = Intent(this, MouseVpnService::class.java).setAction(MouseVpnService.ACTION_CONNECT)
        startForegroundService(intent)
    }

    private fun disconnect() {
        startService(Intent(this, MouseVpnService::class.java).setAction(MouseVpnService.ACTION_DISCONNECT))
    }

    private fun applyStatus(message: String) {
        connected = message.startsWith("Подключено")
        connecting = message.startsWith("Подключение")
        statusTitle.setText(
            when {
                connected -> R.string.status_on_title
                connecting -> R.string.status_connecting
                message.startsWith("Ошибка") || message == "Соединение потеряно" -> R.string.status_error_title
                else -> R.string.status_off_title
            },
        )
        statusText.text = when {
            connected -> message
            connecting -> getString(R.string.status_connecting_hint)
            message.startsWith("Ошибка") || message == "Соединение потеряно" -> message
            else -> getString(R.string.status_off_hint)
        }
        powerButton.setBackgroundResource(if (connected) R.drawable.bg_power_on else R.drawable.bg_power_off)
        if (!connected) statTime.text = "—"
        updatePowerEnabled()
    }

    private fun updatePowerEnabled() {
        powerButton.isEnabled = !connecting && store.selected() != null
        powerButton.alpha = if (powerButton.isEnabled) 1f else 0.48f
    }

    private fun formatDuration(milliseconds: Long): String {
        val seconds = (milliseconds / 1_000).coerceAtLeast(0)
        val hours = seconds / 3_600
        val minutes = seconds % 3_600 / 60
        val remainder = seconds % 60
        return if (hours > 0) "%d:%02d:%02d".format(hours, minutes, remainder)
        else "%02d:%02d".format(minutes, remainder)
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    private companion object {
        const val VPN_REQUEST = 10
    }
}
