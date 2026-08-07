package dev.mousevpn.app

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.text.method.HideReturnsTransformationMethod
import android.text.method.PasswordTransformationMethod
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast

class AddProfileActivity : Activity() {
    private lateinit var profileKey: EditText
    private lateinit var password: EditText
    private lateinit var save: Button
    private lateinit var progress: ProgressBar
    private lateinit var error: TextView
    private var passwordVisible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_profile)
        findViewById<View>(R.id.addProfileContent).applySystemBarPadding(20, 14, 20, 24)
        profileKey = findViewById(R.id.profileKey)
        password = findViewById(R.id.profilePassword)
        save = findViewById(R.id.saveProfile)
        progress = findViewById(R.id.saveProgress)
        error = findViewById(R.id.formError)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<ImageButton>(R.id.togglePassword).setOnClickListener { togglePassword() }
        profileKey.addTextChangedListener(validationWatcher)
        password.addTextChangedListener(validationWatcher)
        save.setOnClickListener { saveProfile() }
        updateValidation()
    }

    private val validationWatcher = object : TextWatcher {
        override fun beforeTextChanged(value: CharSequence?, start: Int, count: Int, after: Int) = Unit
        override fun onTextChanged(value: CharSequence?, start: Int, before: Int, count: Int) = updateValidation()
        override fun afterTextChanged(value: Editable?) = Unit
    }

    private fun updateValidation() {
        val keyReady = profileKey.text?.toString()?.trim()?.startsWith("MV1.") == true
        val passwordReady = (password.text?.length ?: 0) >= 8
        save.isEnabled = keyReady && passwordReady
        save.alpha = if (save.isEnabled) 1f else 0.45f
        if (error.visibility == View.VISIBLE) error.visibility = View.GONE
    }

    private fun togglePassword() {
        passwordVisible = !passwordVisible
        password.transformationMethod = if (passwordVisible) {
            HideReturnsTransformationMethod.getInstance()
        } else {
            PasswordTransformationMethod.getInstance()
        }
        password.setSelection(password.text?.length ?: 0)
    }

    private fun saveProfile() {
        hideKeyboard()
        setBusy(true)
        val chars = password.text.toString().toCharArray()
        try {
            val profile = ProfileCrypto.decrypt(profileKey.text.toString().trim(), chars)
            ProfileStore(this).save(profile)
            Toast.makeText(this, getString(R.string.profile_added, profile.name), Toast.LENGTH_LONG).show()
            finish()
        } catch (exception: Exception) {
            showError(exception.message ?: getString(R.string.profile_decode_error))
        } finally {
            chars.fill('\u0000')
            setBusy(false)
        }
    }

    private fun setBusy(busy: Boolean) {
        profileKey.isEnabled = !busy
        password.isEnabled = !busy
        save.isEnabled = !busy && profileKey.text.toString().trim().startsWith("MV1.") && password.length() >= 8
        progress.visibility = if (busy) View.VISIBLE else View.GONE
    }

    private fun showError(message: String) {
        error.text = message
        error.visibility = View.VISIBLE
    }

    private fun hideKeyboard() {
        getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(currentFocus?.windowToken, 0)
    }
}
