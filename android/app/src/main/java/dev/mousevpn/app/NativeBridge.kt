package dev.mousevpn.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager
import org.json.JSONObject

object NativeBridge {
    init {
        System.loadLibrary("mousevpn_android")
    }

    private var dozeService: MouseVpnService? = null
    private var dozeReceiver: BroadcastReceiver? = null
    private var dozeHandle = 0L

    fun prepare(
        service: MouseVpnService,
        endpoint: String,
        serverPublicKey: String,
        clientPrivateKey: String,
        protocol: String,
        generation: Long,
    ): String {
        unregisterDozeReceiver()
        val result = prepareNative(
            service,
            endpoint,
            serverPublicKey,
            clientPrivateKey,
            protocol,
            generation,
        )
        val handle = JSONObject(result).getLong("handle")
        dozeService = service
        dozeHandle = handle
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED) {
                    setDozing(dozeHandle, isDeviceIdleMode(context))
                }
            }
        }
        dozeReceiver = receiver
        val filter = IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) {
            service.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            service.registerReceiver(receiver, filter)
        }
        return result
    }

    fun start(handle: Long, tunFd: Int): Boolean {
        val started = startNative(handle, tunFd)
        if (started) {
            val service = dozeService
            if (service != null && handle == dozeHandle) {
                setDozing(handle, isDeviceIdleMode(service))
            }
        }
        return started
    }

    external fun networkChanged(handle: Long)

    fun stop(handle: Long) {
        try {
            stopNative(handle)
        } finally {
            if (handle == dozeHandle) unregisterDozeReceiver()
        }
    }

    external fun status(handle: Long): String
    external fun metrics(handle: Long): String

    private external fun prepareNative(
        service: MouseVpnService,
        endpoint: String,
        serverPublicKey: String,
        clientPrivateKey: String,
        protocol: String,
        generation: Long,
    ): String

    private external fun startNative(handle: Long, tunFd: Int): Boolean
    private external fun setDozing(handle: Long, dozing: Boolean)
    private external fun stopNative(handle: Long)

    private fun isDeviceIdleMode(context: Context): Boolean =
        (context.getSystemService(Context.POWER_SERVICE) as PowerManager).isDeviceIdleMode

    fun releaseDozeReceiver() {
        unregisterDozeReceiver()
    }

    private fun unregisterDozeReceiver() {
        val service = dozeService
        val receiver = dozeReceiver
        if (service != null && receiver != null) {
            runCatching { service.unregisterReceiver(receiver) }
        }
        dozeService = null
        dozeReceiver = null
        dozeHandle = 0L
    }
}
