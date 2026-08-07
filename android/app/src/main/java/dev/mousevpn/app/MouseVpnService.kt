package dev.mousevpn.app

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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
            val serverMtu = prepared.getInt("mtu")
            val mtu = tunnelMtu(serverMtu)
            val builder = Builder()
                .setSession("MouseVPN")
                .setMtu(mtu)
                .addAddress(prepared.getString("address"), prepared.getInt("prefix"))
                .addRoute("0.0.0.0", 0)
                .addDnsServer(prepared.getString("dns"))
                .setBlocking(true)
            val bypassing = excludeApps(builder)
            descriptor = builder.establish()
            requireNotNull(descriptor) { "Android не создал VPN-интерфейс" }
            val fd = descriptor.detachFd()
            descriptor = null
            check(NativeBridge.start(handle, fd)) { "Rust-ядро не запустило туннель" }
            connectedSinceElapsedRealtime = SystemClock.elapsedRealtime()
            val summary = buildString {
                append("Подключено: ${profile.endpoint}")
                if (bypassing > 0) append(" (в обход: $bypassing)")
                // Only worth showing when it differs from what the server asked
                // for, because then it is the answer to "why is this slow here".
                if (mtu != serverMtu) append(" (MTU $mtu)")
            }
            broadcast(summary)
            val notification = VpnNotification.create(this, summary)
            getSystemService(android.app.NotificationManager::class.java)
                .notify(VpnNotification.ID, notification)
            monitor(handle)
        } catch (error: Exception) {
            if (handle != 0L) NativeBridge.stop(handle)
            handle = 0L
            connectedSinceElapsedRealtime = 0L
            broadcast("Ошибка: ${error.message ?: error.javaClass.simpleName}")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } finally {
            descriptor?.close()
        }
    }

    /**
     * Lowers the tunnel MTU to what the current network can actually carry.
     *
     * The server picks one MTU for everybody, and it has to assume the usual
     * 1500-byte path. Mobile networks routinely carry less because of the
     * operator's own encapsulation, and a tunnel datagram that no longer fits
     * gets fragmented — often into fragments that carrier NAT then drops. The
     * result is not a clean failure: small requests succeed while anything
     * large stalls, so heavy apps break while light ones look fine.
     *
     * This can only reduce the value, never raise it above what the server
     * negotiated, and it is skipped entirely when Android does not report the
     * underlying MTU.
     */
    private fun tunnelMtu(serverMtu: Int): Int {
        val underlying = underlyingMtu() ?: return serverMtu
        val fits = underlying - OUTER_OVERHEAD
        return serverMtu.coerceAtMost(fits).coerceAtLeast(MINIMUM_MTU)
    }

    /**
     * MTU of the network carrying the tunnel, or null when it is unknown.
     *
     * Read before `establish`, so the active network is still the underlying
     * one rather than the VPN itself.
     *
     * Android only exposes the link MTU from API 29; on anything older the
     * tunnel keeps the value the server negotiated.
     */
    private fun underlyingMtu(): Int? {
        if (Build.VERSION.SDK_INT < 29) return null
        val manager = getSystemService(ConnectivityManager::class.java)
        val network = manager.activeNetwork ?: return null
        val mtu = manager.getLinkProperties(network)?.mtu ?: return null
        return mtu.takeIf { it >= MINIMUM_MTU }
    }

    /**
     * Routes the chosen apps around the tunnel and returns how many were applied.
     *
     * A package that has since been uninstalled must never prevent the tunnel
     * from coming up, so each entry is applied on its own and a failure only
     * drops that one app.
     *
     * Failed entries are deliberately left in the store. An app can be missing
     * for reasons that pass — an update in flight, a profile not yet unlocked —
     * and silently discarding a choice the user made is worse than carrying an
     * entry that costs one failed call per connection.
     */
    private fun excludeApps(builder: Builder): Int {
        var applied = 0
        ExcludedApps(this).packages().forEach { packageName ->
            runCatching { builder.addDisallowedApplication(packageName) }
                .onSuccess { applied++ }
        }
        return applied
    }

    private fun monitor(currentHandle: Long) {
        while (!Thread.currentThread().isInterrupted && handle == currentHandle) {
            if (NativeBridge.status(currentHandle) != "running") {
                NativeBridge.stop(currentHandle)
                handle = 0L
                connectedSinceElapsedRealtime = 0L
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
        connectedSinceElapsedRealtime = 0L
        if (current != 0L) NativeBridge.stop(current)
        task?.cancel(true)
        task = null
        broadcast("Отключено")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcast(status: String) {
        currentStatus = status
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
        connectedSinceElapsedRealtime = 0L
        if (current != 0L) NativeBridge.stop(current)
        runCatching {
            getSystemService(ConnectivityManager::class.java)
                .unregisterNetworkCallback(networkCallback)
        }
        super.onDestroy()
    }

    companion object {
        @Volatile
        var currentStatus: String = "Отключено"
            private set

        @Volatile
        var connectedSinceElapsedRealtime: Long = 0L
            private set

        /**
         * Bytes wrapped around every tunnelled packet: 20 outer IPv4, 8 UDP,
         * 20 protocol header, 1 inner packet kind and a 16-byte AEAD tag.
         */
        private const val OUTER_OVERHEAD = 65

        /** Floor for the tunnel MTU; every path is expected to carry this. */
        private const val MINIMUM_MTU = 1_280

        const val ACTION_CONNECT = "dev.mousevpn.app.CONNECT"
        const val ACTION_DISCONNECT = "dev.mousevpn.app.DISCONNECT"
        const val ACTION_STATUS = "dev.mousevpn.app.STATUS"
        const val EXTRA_STATUS = "status"
    }
}
