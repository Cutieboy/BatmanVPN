package dev.mousevpn.app

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast

private data class InstalledApp(
    val packageName: String,
    val label: String,
    val icon: Drawable,
)

/** Lets the user pick which apps skip the tunnel. */
class AppListActivity : Activity() {
    private lateinit var store: ExcludedApps
    private lateinit var adapter: AppAdapter
    private val excluded = mutableSetOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_list)
        findViewById<View>(R.id.appListRoot).applySystemBarPadding(16, 16, 16, 16)
        store = ExcludedApps(this)
        excluded.addAll(store.packages())

        adapter = AppAdapter(loadApps())
        findViewById<ListView>(R.id.appList).adapter = adapter
        findViewById<Button>(R.id.clearExclusions).setOnClickListener {
            excluded.clear()
            adapter.notifyDataSetChanged()
        }
        findViewById<Button>(R.id.saveExclusions).setOnClickListener { save() }
    }

    private fun save() {
        store.replace(excluded.toSet())
        val message = if (excluded.isEmpty()) {
            getString(R.string.exclusions_saved_empty)
        } else {
            resources.getQuantityString(R.plurals.exclusions_saved, excluded.size, excluded.size)
        }
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    /**
     * Lists launchable apps, excluded ones first so a long list stays reviewable.
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
                compareByDescending<InstalledApp> { excluded.contains(it.packageName) }
                    .thenBy { it.label.lowercase() },
            )
            .toList()
    }

    private fun ResolveInfo.toInstalledApp(manager: PackageManager): InstalledApp? {
        val info = activityInfo?.applicationInfo ?: return null
        return InstalledApp(
            packageName = info.packageName,
            label = manager.getApplicationLabel(info).toString(),
            icon = manager.getApplicationIcon(info),
        )
    }

    private inner class AppAdapter(private val apps: List<InstalledApp>) : BaseAdapter() {
        override fun getCount(): Int = apps.size

        override fun getItem(position: Int): Any = apps[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val view = convertView
                ?: layoutInflater.inflate(R.layout.item_app, parent, false)
            val app = apps[position]
            view.findViewById<ImageView>(R.id.appIcon).setImageDrawable(app.icon)
            view.findViewById<TextView>(R.id.appLabel).text = app.label
            view.findViewById<TextView>(R.id.appPackage).text = app.packageName
            val checkBox = view.findViewById<CheckBox>(R.id.appExcluded)
            // Detach the listener first: recycled rows would otherwise fire it
            // for the previous app while its state is being restored.
            checkBox.setOnCheckedChangeListener(null)
            checkBox.isChecked = excluded.contains(app.packageName)
            checkBox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) excluded.add(app.packageName) else excluded.remove(app.packageName)
            }
            view.setOnClickListener { checkBox.toggle() }
            return view
        }
    }
}
