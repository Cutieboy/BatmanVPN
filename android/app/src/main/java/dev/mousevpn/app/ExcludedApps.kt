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

enum class DomainRoute {
    TUNNEL,
    DIRECT,
}

data class DomainRule(
    val domain: String,
    val route: DomainRoute,
)

/** Device-local per-application and domain-routing settings. */
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

    fun domainRules(): List<DomainRule> =
        preferences.getStringSet(DOMAIN_RULES, null).orEmpty()
            .mapNotNull { raw ->
                val parts = raw.split("|", limit = 2)
                if (parts.size != 2) return@mapNotNull null
                val domain = normalizeDomain(parts[0]) ?: return@mapNotNull null
                val route = runCatching { DomainRoute.valueOf(parts[1]) }.getOrNull()
                    ?: return@mapNotNull null
                DomainRule(domain, route)
            }
            .sortedBy { it.domain }

    fun replaceDomainRules(rules: List<DomainRule>) {
        val encoded = rules.mapNotNull { rule ->
            val domain = normalizeDomain(rule.domain) ?: return@mapNotNull null
            "${domain}|${rule.route.name}"
        }.toSet()
        preferences.edit().putStringSet(DOMAIN_RULES, encoded).apply()
    }

    fun addDomainRule(rawDomain: String, route: DomainRoute): List<DomainRule> {
        val domain = normalizeDomain(rawDomain)
            ?: throw IllegalArgumentException("Введите домен без схемы и пути, например chatgpt.com")
        val updated = domainRules().filterNot { it.domain == domain } + DomainRule(domain, route)
        replaceDomainRules(updated)
        return domainRules()
    }

    fun removeDomainRule(rawDomain: String): List<DomainRule> {
        val domain = normalizeDomain(rawDomain)
            ?: throw IllegalArgumentException("Некорректное доменное имя")
        val updated = domainRules().filterNot { it.domain == domain }
        replaceDomainRules(updated)
        return domainRules()
    }

    private fun normalizeDomain(raw: String): String? {
        val value = raw.trim().removePrefix("*.").trimEnd('.').lowercase()
        if (value.length !in 1..253 || value.contains('/') || value.contains(':') || value.contains(' ')) return null
        val labels = value.split('.')
        if (labels.size < 2 || labels.any { label ->
            label.isEmpty() || label.length > 63 || label.startsWith('-') || label.endsWith('-') ||
                label.any { !it.isLetterOrDigit() && it != '-' }
        }) return null
        return value
    }

    private companion object {
        const val PACKAGES = "excluded_packages"
        const val MODE = "routing_mode"
        const val DOMAIN_RULES = "domain_rules_v1"
    }
}
