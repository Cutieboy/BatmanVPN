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

    fun exportJson(): org.json.JSONObject = org.json.JSONObject()
        .put("mode", policy().mode.name)
        .put("packages", org.json.JSONArray().apply {
            policy().packages.sorted().forEach(::put)
        })

    fun importJson(value: org.json.JSONObject) {
        val mode = runCatching {
            AppRoutingMode.valueOf(value.optString("mode", AppRoutingMode.EXCLUDE.name))
        }.getOrElse { AppRoutingMode.EXCLUDE }
        val packagesJson = value.optJSONArray("packages")
        val packages = buildSet {
            if (packagesJson != null) {
                for (index in 0 until packagesJson.length()) {
                    val packageName = packagesJson.optString(index).trim()
                    if (packageName.isNotEmpty()) add(packageName)
                }
            }
        }
        replace(mode, packages)
    }

    private companion object {
        const val PACKAGES = "excluded_packages"
        const val MODE = "routing_mode"
    }
}
