package dev.mousevpn.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.graphics.Color
import android.content.Context
import android.content.Intent
import android.app.AlertDialog
import android.net.Uri
import android.text.InputType
import android.widget.EditText
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
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ImageButton
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var profileName: TextView
    private lateinit var endpoint: TextView
    private lateinit var statusTitle: TextView
    private lateinit var statusText: TextView
    private lateinit var powerButton: ImageButton
    private lateinit var statServer: TextView
    private lateinit var statTime: TextView
    private lateinit var statIp: TextView
    private lateinit var statCountry: TextView
    private lateinit var statPing: TextView
    private lateinit var statSpeed: TextView
    private lateinit var protocolMode: Spinner
    private lateinit var protocolHint: TextView
    private lateinit var networkTestButton: Button
    private lateinit var networkTestResult: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val networkTestExecutor = Executors.newSingleThreadExecutor()
    @Volatile private var connected = false
    private var connecting = false
    private var bindingProtocol = true
    @Volatile private var networkTestRunning = false
    private var pendingBackupBytes: ByteArray? = null
    private var publicInfoLoadedForSession = false
    private var lastMetricsBytes = 0L
    private var lastMetricsAt = 0L

    private val clock = object : Runnable {
        override fun run() {
            val now = SystemClock.elapsedRealtime()
            val since = MouseVpnService.connectedSinceElapsedRealtime
            statTime.text = if (connected && since > 0L) {
                formatDuration(now - since)
            } else {
                "—"
            }
            updateLiveMetrics(now)
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
        statIp = findViewById(R.id.statIpValue)
        statCountry = findViewById(R.id.statCountryValue)
        statPing = findViewById(R.id.statPingValue)
        statSpeed = findViewById(R.id.statSpeedValue)
        protocolMode = findViewById(R.id.protocolMode)
        protocolHint = findViewById(R.id.protocolHint)
        networkTestButton = findViewById(R.id.networkTest)
        networkTestResult = findViewById(R.id.networkTestResult)
        protocolMode.adapter = ArrayAdapter.createFromResource(
            this,
            R.array.protocol_mode_labels,
            R.layout.item_protocol_spinner,
        ).apply { setDropDownViewResource(R.layout.item_protocol_dropdown) }
        protocolMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (bindingProtocol) return
                val profile = store.selected() ?: return
                val protocol = VpnProtocol.entries.getOrNull(position) ?: VpnProtocol.LEGACY
                if (profile.protocol != protocol) store.save(profile.copy(protocol = protocol), select = false)
                updateProtocolUi()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }

        findViewById<View>(R.id.addProfile).setOnClickListener { openAddProfile() }
        findViewById<View>(R.id.profileChooser).setOnClickListener { showProfileChooser() }
        findViewById<View>(R.id.profileMenu).setOnClickListener { showProfileMenu() }
        findViewById<View>(R.id.excludedApps).setOnClickListener {
            startActivity(Intent(this, AppListActivity::class.java))
        }
        findViewById<View>(R.id.openDiagnostics).setOnClickListener {
            startActivity(Intent(this, DiagnosticsActivity::class.java))
        }
        networkTestButton.setOnClickListener { startNetworkTest() }
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

    override fun onDestroy() {
        networkTestExecutor.shutdownNow()
        super.onDestroy()
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
        bindingProtocol = true
        protocolMode.setSelection(profile?.protocol?.ordinal ?: VpnProtocol.LEGACY.ordinal, false)
        bindingProtocol = false
        updateProtocolUi()
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
        dialog.findViewById<View>(R.id.menuExportBackup).setOnClickListener {
            dialog.dismiss()
            promptBackupPassword(export = true)
        }
        dialog.findViewById<View>(R.id.menuImportBackup).setOnClickListener {
            dialog.dismiss()
            openBackupFile()
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

    private fun promptBackupPassword(export: Boolean, backupBytes: ByteArray? = null) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = getString(R.string.backup_password_hint)
            setSingleLine(true)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(if (export) R.string.backup_export_title else R.string.backup_import_title)
            .setMessage(R.string.backup_password_message)
            .setView(input)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(if (export) R.string.backup_export else R.string.backup_import, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val password = input.text.toString()
                if (password.length < 8) {
                    input.error = getString(R.string.backup_password_short)
                    return@setOnClickListener
                }
                dialog.dismiss()
                if (export) {
                    createBackup(password)
                } else {
                    importBackup(backupBytes ?: return@setOnClickListener, password)
                }
            }
        }
        dialog.show()
    }

    private fun createBackup(password: String) {
        val bytes = runCatching {
            BackupStore(this).export(password.toCharArray())
        }.getOrElse {
            toast(it.message ?: getString(R.string.backup_failed))
            return
        }
        pendingBackupBytes = bytes
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, "batmanvpn-backup.json")
        startActivityForResult(intent, BACKUP_CREATE_REQUEST)
    }

    private fun writeBackup(uri: Uri) {
        val bytes = pendingBackupBytes ?: return
        pendingBackupBytes = null
        val result = runCatching {
            contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                ?: error("Не удалось открыть файл для записи")
        }
        result.onSuccess {
            toast(getString(R.string.backup_exported))
        }.onFailure {
            toast(it.message ?: getString(R.string.backup_failed))
        }
    }

    private fun openBackupFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
        startActivityForResult(intent, BACKUP_OPEN_REQUEST)
    }

    private fun readBackup(uri: Uri) {
        val bytes = runCatching {
            contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("Не удалось открыть резервную копию")
        }.getOrElse {
            toast(it.message ?: getString(R.string.backup_failed))
            return
        }
        promptBackupPassword(export = false, backupBytes = bytes)
    }

    private fun importBackup(bytes: ByteArray, password: String) {
        val result = runCatching {
            BackupStore(this).import(bytes, password.toCharArray())
        }
        result.onSuccess {
            refreshProfile()
            toast(getString(R.string.backup_imported))
        }.onFailure {
            toast(it.message ?: getString(R.string.backup_failed))
        }
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
        when (requestCode) {
            VPN_REQUEST -> if (resultCode == RESULT_OK) connect()
            BACKUP_CREATE_REQUEST -> if (resultCode == RESULT_OK && data?.data != null) {
                writeBackup(data.data!!)
            }
            BACKUP_OPEN_REQUEST -> if (resultCode == RESULT_OK && data?.data != null) {
                readBackup(data.data!!)
            }
        }
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
            connecting && message == MouseVpnService.STATUS_CONNECTING ->
                getString(R.string.status_connecting_hint)
            connecting -> message
            message.startsWith("Ошибка") || message == "Соединение потеряно" -> message
            else -> getString(R.string.status_off_hint)
        }
        powerButton.setBackgroundColor(Color.TRANSPARENT)
        powerButton.setImageResource(if (connected) R.drawable.batman_logo_flying else R.drawable.batman_logo_sleeping)
        if (!connected) {
            statTime.text = "—"
            statIp.text = "—"
            statCountry.text = "—"
            statPing.text = "—"
            statSpeed.text = "—"
            publicInfoLoadedForSession = false
            lastMetricsBytes = 0L
            lastMetricsAt = 0L
        } else if (!publicInfoLoadedForSession) {
            publicInfoLoadedForSession = true
            fetchPublicNetworkInfo()
        }
        updatePowerEnabled()
        updateProtocolUi()
        updateNetworkTestButton()
    }

    private fun updateLiveMetrics(now: Long) {
        if (!connected) return
        val metrics = runCatching { JSONObject(MouseVpnService.currentMetricsJson) }.getOrNull() ?: return
        val received = metrics.optLong("bytesReceived")
        val sent = metrics.optLong("bytesSent")
        val total = received + sent
        val previousAt = lastMetricsAt
        val previousBytes = lastMetricsBytes
        if (previousAt > 0L && now > previousAt) {
            val bitsPerSecond = ((total - previousBytes).coerceAtLeast(0L) * 8_000L) /
                (now - previousAt).coerceAtLeast(1L)
            statSpeed.text = formatBitRate(bitsPerSecond)
        }
        lastMetricsBytes = total
        lastMetricsAt = now
        val rtt = metrics.optLong("lastKeepaliveRttMs")
        statPing.text = if (rtt > 0L) "$rtt мс" else "—"
    }

    private fun fetchPublicNetworkInfo() {
        networkTestExecutor.execute {
            val result = runCatching {
                val connection = URL("https://ipwho.is/").openConnection() as HttpURLConnection
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.requestMethod = "GET"
                connection.useCaches = false
                try {
                    if (connection.responseCode !in 200..299) error("HTTP " + connection.responseCode)
                    JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
                } finally {
                    connection.disconnect()
                }
            }
            val ip = result.getOrNull()?.optString("ip").orEmpty()
            val country = result.getOrNull()?.optString("country").orEmpty()
            runOnUiThread {
                if (!connected) return@runOnUiThread
                statIp.text = ip.ifBlank { "—" }
                statCountry.text = country.ifBlank { "—" }
            }
        }
    }

    private fun formatBitRate(bitsPerSecond: Long): String = when {
        bitsPerSecond >= 1_000_000_000L -> "%.1f Гбит/с".format(bitsPerSecond / 1_000_000_000.0)
        bitsPerSecond >= 1_000_000L -> "%.1f Мбит/с".format(bitsPerSecond / 1_000_000.0)
        bitsPerSecond >= 1_000L -> "%.0f Кбит/с".format(bitsPerSecond / 1_000.0)
        else -> "$bitsPerSecond бит/с"
    }

    private fun updateProtocolUi() {
        val profile = runCatching { store.selected() }.getOrNull()
        val protocol = profile?.protocol ?: VpnProtocol.LEGACY
        val hints = resources.getStringArray(R.array.protocol_mode_hints)
        protocolHint.text = hints.getOrElse(protocol.ordinal) { hints[0] }
        protocolMode.isEnabled = profile != null && !connected && !connecting
        protocolMode.alpha = if (protocolMode.isEnabled) 1f else 0.48f
    }

    private fun updatePowerEnabled() {
        powerButton.isEnabled = !connecting && store.selected() != null
        powerButton.alpha = if (powerButton.isEnabled) 1f else 0.48f
    }

    private fun startNetworkTest() {
        if (!connected || networkTestRunning) {
            if (!connected) networkTestResult.setText(R.string.network_test_requires_vpn)
            return
        }
        networkTestRunning = true
        networkTestButton.setText(R.string.network_test_running)
        networkTestResult.setText(R.string.network_test_starting)
        updateNetworkTestButton()
        networkTestExecutor.execute(::runNetworkTest)
    }

    private fun runNetworkTest() {
        val deadline = SystemClock.elapsedRealtime() + NETWORK_TEST_DURATION_MS
        var attempts = 0
        var successes = 0
        var totalLatencyMs = 0L
        var lastError = ""

        while (connected && !Thread.currentThread().isInterrupted &&
            SystemClock.elapsedRealtime() < deadline
        ) {
            val roundStarted = SystemClock.elapsedRealtime()
            val result = probeThroughVpn()
            attempts++
            if (result.success) {
                successes++
                totalLatencyMs += result.latencyMs
            } else {
                lastError = result.detail
            }
            val remainingSeconds =
                ((deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L) + 999L) / 1_000L
            val average = if (successes == 0) 0L else totalLatencyMs / successes
            runOnUiThread {
                if (!isDestroyed) {
                    networkTestResult.text = getString(
                        R.string.network_test_progress,
                        remainingSeconds,
                        successes,
                        attempts,
                        average,
                    )
                }
            }

            val delay = (NETWORK_TEST_INTERVAL_MS -
                (SystemClock.elapsedRealtime() - roundStarted)).coerceAtLeast(0L)
            val available = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
            try {
                Thread.sleep(delay.coerceAtMost(available))
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        val completedWhileConnected = connected && !Thread.currentThread().isInterrupted
        val average = if (successes == 0) 0L else totalLatencyMs / successes
        val failedPercent = if (attempts == 0) 100 else (attempts - successes) * 100 / attempts
        networkTestRunning = false
        runOnUiThread {
            if (isDestroyed) return@runOnUiThread
            networkTestButton.setText(R.string.network_test_start)
            updateNetworkTestButton()
            networkTestResult.text = when {
                !completedWhileConnected -> getString(R.string.network_test_interrupted)
                attempts == 0 -> getString(R.string.network_test_no_attempts)
                successes == 0 -> getString(R.string.network_test_failed, lastError)
                else -> getString(
                    R.string.network_test_finished,
                    successes,
                    attempts,
                    failedPercent,
                    average,
                )
            }
        }
    }

    private fun probeThroughVpn(): ProbeResult {
        var lastError = getString(R.string.unknown_error)
        for (target in NETWORK_TEST_TARGETS) {
            val started = SystemClock.elapsedRealtime()
            val address = try {
                InetAddress.getAllByName(target.host).firstOrNull { it is Inet4Address }
                    ?: error("IPv4 unavailable")
            } catch (exception: Exception) {
                lastError = "${target.name}: ${exception.javaClass.simpleName}"
                continue
            }
            try {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(address, target.port), NETWORK_TEST_TIMEOUT_MS)
                }
                return ProbeResult(
                    success = true,
                    latencyMs = SystemClock.elapsedRealtime() - started,
                    detail = target.name,
                )
            } catch (exception: Exception) {
                lastError = "${target.name}: ${exception.javaClass.simpleName}"
            }
        }
        return ProbeResult(success = false, latencyMs = 0L, detail = lastError)
    }

    private fun updateNetworkTestButton() {
        networkTestButton.isEnabled = connected && !networkTestRunning
        networkTestButton.alpha = if (networkTestButton.isEnabled) 1f else 0.48f
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
        const val BACKUP_CREATE_REQUEST = 11
        const val BACKUP_OPEN_REQUEST = 12
        const val NETWORK_TEST_DURATION_MS = 30_000L
        const val NETWORK_TEST_INTERVAL_MS = 1_000L
        const val NETWORK_TEST_TIMEOUT_MS = 2_000
        val NETWORK_TEST_TARGETS = listOf(
            ProbeTarget("Google", "www.google.com", 443),
            ProbeTarget("YouTube", "www.youtube.com", 443),
        )
    }
}

private data class ProbeTarget(val name: String, val host: String, val port: Int)

private data class ProbeResult(
    val success: Boolean,
    val latencyMs: Long,
    val detail: String,
)
