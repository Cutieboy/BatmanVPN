package dev.mousevpn.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast

class DiagnosticsActivity : Activity() {
    private lateinit var store: DiagnosticStore
    private lateinit var summary: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_diagnostics)
        findViewById<View>(R.id.diagnosticsContent).applySystemBarPadding(20, 14, 20, 20)
        store = DiagnosticStore(this)
        summary = findViewById(R.id.diagnosticsSummary)
        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.shareDiagnostics).setOnClickListener { share() }
        findViewById<View>(R.id.clearDiagnostics).setOnClickListener {
            store.clear()
            refresh()
            Toast.makeText(this, R.string.diagnostics_cleared, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onStart() {
        super.onStart()
        refresh()
    }

    private fun refresh() {
        summary.text = store.summary()
    }

    private fun share() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_SUBJECT, "MouseVPN diagnostics")
            putExtra(Intent.EXTRA_TEXT, store.exportJson())
        }
        startActivity(Intent.createChooser(intent, getString(R.string.diagnostics_export)))
    }
}
