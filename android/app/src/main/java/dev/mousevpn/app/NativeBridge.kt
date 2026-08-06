package dev.mousevpn.app

object NativeBridge {
    init {
        System.loadLibrary("mousevpn_android")
    }

    external fun prepare(
        service: MouseVpnService,
        endpoint: String,
        serverPublicKey: String,
        clientPrivateKey: String,
    ): String

    external fun start(handle: Long, tunFd: Int): Boolean
    external fun stop(handle: Long)
    external fun status(handle: Long): String
}
