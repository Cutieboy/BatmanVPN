package dev.mousevpn.app

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Bundle
import android.util.LruCache
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.ListView
import android.widget.RadioButton
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.Executors

private data class InstalledApp(
    val packageName: String,
    val label: String,
)

/** Lets the user choose which apps use or bypass the tunnel. */
class AppListActivity : Activity() {
    private lateinit var store: ExcludedApps
    private lateinit var adapter: AppAdapter
    private val selected = mutableSetOf<String>()
    private var mode = AppRoutingMode.EXCLUDE
    private var query = ""
    private var selectedOnly = false
    private val loader = Executors.newSingleThreadExecutor()
    private val icons = LruCache<String, android.graphics.drawable.Drawable>(64)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_list)
        findViewById<View>(R.id.appListRoot).applySystemBarPadding(16, 16, 16, 16)
        store = ExcludedApps(this)
        val policy = store.policy()
        mode = policy.mode
        selected.addAll(policy.packages)

        adapter = AppAdapter(emptyList())
        findViewById<ListView>(R.id.appList).adapter = adapter
        loader.execute {
            val apps = loadApps()
            runOnUiThread {
                if (!isDestroyed) adapter.replace(apps)
            }
        }
        findViewById<RadioButton>(R.id.modeExclude).apply {
            isChecked = mode == AppRoutingMode.EXCLUDE
            setOnClickListener { setMode(AppRoutingMode.EXCLUDE) }
        }
        findViewById<RadioButton>(R.id.modeInclude).apply {
            isChecked = mode == AppRoutingMode.INCLUDE
            setOnClickListener { setMode(AppRoutingMode.INCLUDE) }
        }
        setMode(mode)
        findViewById<EditText>(R.id.appSearch).addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(value: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(value: CharSequence?, start: Int, before: Int, count: Int) {
                    query = value?.toString().orEmpty()
                    adapter.applyFilter(query, selectedOnly)
                }
                override fun afterTextChanged(value: android.text.Editable?) = Unit
            },
        )
        findViewById<CheckBox>(R.id.showSelectedOnly).setOnCheckedChangeListener { _, checked ->
            selectedOnly = checked
            adapter.applyFilter(query, selectedOnly)
        }
        findViewById<Button>(R.id.clearExclusions).setOnClickListener {
            selected.clear()
            adapter.applyFilter(query, selectedOnly)
        }
        findViewById<Button>(R.id.saveExclusions).setOnClickListener { save() }
    }

    override fun onDestroy() {
        loader.shutdownNow()
        super.onDestroy()
    }

    private fun save() {
        store.replace(mode, selected.toSet())
        val message = if (selected.isEmpty()) {
            getString(
                if (mode == AppRoutingMode.EXCLUDE) R.string.exclusions_saved_empty
                else R.string.inclusions_saved_empty,
            )
        } else {
            resources.getQuantityString(
                if (mode == AppRoutingMode.EXCLUDE) R.plurals.exclusions_saved
                else R.plurals.inclusions_saved,
                selected.size,
                selected.size,
            )
        }
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    /**
     * Lists launchable apps, selected ones first so a long list stays reviewable.
     *
     * MouseVPN itself is left out: its own UDP socket is already kept off the
     * tunnel by `VpnService.protect`, so offering to exclude it would only
     * invite confusion.
     */
    private fun loadApps(): List<InstalledApp> {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val manager = packageManager
        return manager.queryIntentActivities(launcher, 0)
            .asSequence()
            .mapNotNull { it.toInstalledApp(manager) }
            .filter { it.packageName != packageName }
            .distinctBy { it.packageName }
            .sortedWith(
                compareByDescending<InstalledApp> { selected.contains(it.packageName) }
                    .thenBy { it.label.lowercase() },
            )
            .toList()
    }

    private fun ResolveInfo.toInstalledApp(manager: PackageManager): InstalledApp? {
        val info = activityInfo?.applicationInfo ?: return null
        return InstalledApp(
            packageName = info.packageName,
            label = manager.getApplicationLabel(info).toString(),
        )
    }

    private fun setMode(next: AppRoutingMode) {
        mode = next
        findViewById<TextView>(R.id.exclusionsHint).setText(
            if (mode == AppRoutingMode.EXCLUDE) R.string.exclusions_hint
            else R.string.inclusions_hint,
        )
    }

    private inner class AppAdapter(initialApps: List<InstalledApp>) : BaseAdapter() {
        private var allApps = initialApps
        private var apps = allApps

        fun replace(loaded: List<InstalledApp>) {
            allApps = loaded
            applyFilter(query, selectedOnly)
        }

        fun applyFilter(query: String, selectedOnly: Boolean) {
            val needle = query.trim().lowercase()
            apps = allApps.filter { app ->
                (!selectedOnly || selected.contains(app.packageName)) &&
                    (needle.isEmpty() || app.label.lowercase().contains(needle) ||
                        app.packageName.lowercase().contains(needle))
            }.sortedWith(
                compareByDescending<InstalledApp> { selected.contains(it.packageName) }
                    .thenBy { it.label.lowercase() },
            )
            notifyDataSetChanged()
        }

        override fun getCount(): Int = apps.size

        override fun getItem(position: Int): Any = apps[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val view = convertView
                ?: layoutInflater.inflate(R.layout.item_app, parent, false)
            val app = apps[position]
            val icon = view.findViewById<ImageView>(R.id.appIcon)
            icon.tag = app.packageName
            val cached = synchronized(icons) { icons.get(app.packageName) }
            icon.setImageDrawable(cached ?: packageManager.defaultActivityIcon)
            if (cached == null) {
                loader.execute {
                    val loaded = runCatching {
                        packageManager.getApplicationIcon(app.packageName)
                    }.getOrNull() ?: return@execute
                    synchronized(icons) { icons.put(app.packageName, loaded) }
                    runOnUiThread {
                        if (icon.tag == app.packageName) icon.setImageDrawable(loaded)
                    }
                }
            }
            view.findViewById<TextView>(R.id.appLabel).text = app.label
            view.findViewById<TextView>(R.id.appPackage).text = app.packageName
            val checkBox = view.findViewById<CheckBox>(R.id.appExcluded)
            // Detach the listener first: recycled rows would otherwise fire it
            // for the previous app while its state is being restored.
            checkBox.setOnCheckedChangeListener(null)
            checkBox.isChecked = selected.contains(app.packageName)
            checkBox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) selected.add(app.packageName) else selected.remove(app.packageName)
                if (selectedOnly && !isChecked) applyFilter(query, true)
            }
            view.setOnClickListener { checkBox.toggle() }
            return view
        }
    }
}
