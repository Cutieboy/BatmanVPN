package dev.mousevpn.app

import android.content.Context

enum class AppRoutingMode {
    EXCLUDE,
    INCLUDE,
}

data class AppRoutingPolicy(
    val mode: AppRoutingMode,
    val packages: Set<String>,
)

/** Device-local per-application routing policy. */
class ExcludedApps(context: Context) {
    private val preferences =
        context.getSharedPreferences("mousevpn_split_tunnel", Context.MODE_PRIVATE)

    fun packages(): Set<String> = preferences.getStringSet(PACKAGES, null)?.toSet() ?: emptySet()

    fun policy(): AppRoutingPolicy = AppRoutingPolicy(
        mode = preferences.getString(MODE, null)
            ?.let { runCatching { AppRoutingMode.valueOf(it) }.getOrNull() }
            ?: AppRoutingMode.EXCLUDE,
        packages = packages(),
    )

    fun replace(mode: AppRoutingMode, packages: Set<String>) {
        preferences.edit()
            .putString(MODE, mode.name)
            .putStringSet(PACKAGES, packages)
            .apply()
    }

    fun isExcluded(packageName: String): Boolean = packages().contains(packageName)

    private companion object {
        const val PACKAGES = "excluded_packages"
        const val MODE = "routing_mode"
    }
}
