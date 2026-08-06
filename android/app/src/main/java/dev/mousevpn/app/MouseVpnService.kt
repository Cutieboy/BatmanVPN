package dev.mousevpn.app

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.Future

class MouseVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor()
    private var task: Future<*>? = null
    @Volatile private var handle = 0L
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = signalNetworkChange()

        override fun onLost(network: Network) = signalNetworkChange()
    }

    override fun onCreate() {
        super.onCreate()
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        getSystemService(ConnectivityManager::class.java)
            .registerNetworkCallback(request, networkCallback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        startForeground(VpnNotification.ID, VpnNotification.create(this, "Подключение…"))
        if (task?.isDone != false) task = executor.submit(::connect)
        return START_STICKY
    }

    private fun connect() {
        var descriptor: ParcelFileDescriptor? = null
        try {
            broadcast("Подключение…")
            val profile = requireNotNull(ProfileStore(this).selected()) { "Сначала вставьте профиль" }
            val prepared = JSONObject(
                NativeBridge.prepare(
                    this,
                    profile.endpoint,
                    profile.serverPublicKey,
                    profile.clientPrivateKey,
                ),
            )
            handle = prepared.getLong("handle")
            descriptor = Builder()
                .setSession("MouseVPN")
                .setMtu(prepared.getInt("mtu"))
                .addAddress(prepared.getString("address"), prepared.getInt("prefix"))
                .addRoute("0.0.0.0", 0)
                .addDnsServer(prepared.getString("dns"))
                .setBlocking(true)
                .establish()
            requireNotNull(descriptor) { "Android не создал VPN-интерфейс" }
            val fd = descriptor.detachFd()
            descriptor = null
            check(NativeBridge.start(handle, fd)) { "Rust-ядро не запустило туннель" }
            broadcast("Подключено: ${profile.endpoint}")
            val notification = VpnNotification.create(this, "Подключено: ${profile.endpoint}")
            getSystemService(android.app.NotificationManager::class.java)
                .notify(VpnNotification.ID, notification)
            monitor(handle)
        } catch (error: Exception) {
            if (handle != 0L) NativeBridge.stop(handle)
            handle = 0L
            broadcast("Ошибка: ${error.message ?: error.javaClass.simpleName}")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } finally {
            descriptor?.close()
        }
    }

    private fun monitor(currentHandle: Long) {
        while (!Thread.currentThread().isInterrupted && handle == currentHandle) {
            if (NativeBridge.status(currentHandle) != "running") {
                NativeBridge.stop(currentHandle)
                handle = 0L
                broadcast("Соединение потеряно")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            try {
                Thread.sleep(1_000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun disconnect() {
        val current = handle
        handle = 0L
        if (current != 0L) NativeBridge.stop(current)
        task?.cancel(true)
        task = null
        broadcast("Отключено")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcast(status: String) {
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS, status),
        )
    }

    private fun signalNetworkChange() {
        val current = handle
        if (current != 0L) NativeBridge.networkChanged(current)
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        val current = handle
        handle = 0L
        if (current != 0L) NativeBridge.stop(current)
        runCatching {
            getSystemService(ConnectivityManager::class.java)
                .unregisterNetworkCallback(networkCallback)
        }
        super.onDestroy()
    }

    companion object {
        const val ACTION_CONNECT = "dev.mousevpn.app.CONNECT"
        const val ACTION_DISCONNECT = "dev.mousevpn.app.DISCONNECT"
        const val ACTION_STATUS = "dev.mousevpn.app.STATUS"
        const val EXTRA_STATUS = "status"
    }
}
