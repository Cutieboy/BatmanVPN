package dev.mousevpn.app

import android.content.Context

/**
 * Packages that bypass the tunnel and use the normal network directly.
 *
 * Deliberately stored outside [ProfileStore]: that store is encrypted because
 * it holds private keys, while this is a list of package names in app-private
 * storage. It is also device-local by nature — profiles are copied between
 * phones, and the installed apps differ on each one.
 */
class ExcludedApps(context: Context) {
    private val preferences =
        context.getSharedPreferences("mousevpn_split_tunnel", Context.MODE_PRIVATE)

    fun packages(): Set<String> = preferences.getStringSet(PACKAGES, null)?.toSet() ?: emptySet()

    fun replace(packages: Set<String>) {
        preferences.edit().putStringSet(PACKAGES, packages).apply()
    }

    fun isExcluded(packageName: String): Boolean = packages().contains(packageName)

    private companion object {
        const val PACKAGES = "excluded_packages"
    }
}
