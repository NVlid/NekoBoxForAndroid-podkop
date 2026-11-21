package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.AutoUrlTester
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher

class AutoUrlTestPreferenceFragment : PreferenceFragmentCompat() {

    private lateinit var autoUrlTestEnabled: SwitchPreference
    private lateinit var autoUrlTestInterval: EditTextPreference
    private lateinit var autoSelectBestProfile: SwitchPreference

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        listView.layoutManager = FixedLinearLayoutManager(listView)
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        preferenceManager.preferenceDataStore = DataStore.configurationStore
        addPreferencesFromResource(R.xml.auto_url_test_preferences)

        autoUrlTestEnabled = findPreference(Key.AUTO_URL_TEST_ENABLED)!!
        autoUrlTestInterval = findPreference(Key.AUTO_URL_TEST_INTERVAL)!!
        autoSelectBestProfile = findPreference(Key.AUTO_SELECT_BEST_PROFILE)!!

        autoUrlTestInterval.setOnBindEditTextListener {
            it.inputType = EditorInfo.TYPE_CLASS_NUMBER
        }

        autoUrlTestEnabled.setOnPreferenceChangeListener { _, newValue ->
            updatePreferenceStates(newValue as Boolean)
            scheduleReconfigure()
            true
        }
        autoUrlTestInterval.setOnPreferenceChangeListener { _, newValue ->
            val interval = newValue.toString().toIntOrNull()
            if (interval == null || interval !in 15..1440) {
                MaterialAlertDialogBuilder(requireContext())
                    .setMessage(R.string.auto_url_test_interval_invalid)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
                false
            } else {
                scheduleReconfigure()
                true
            }
        }
        autoSelectBestProfile.setOnPreferenceChangeListener { _, _ -> true }

        updatePreferenceStates(autoUrlTestEnabled.isChecked)
    }

    override fun onResume() {
        super.onResume()
        updatePreferenceStates(autoUrlTestEnabled.isChecked)
    }

    private fun updatePreferenceStates(enabled: Boolean) {
        autoUrlTestInterval.isEnabled = enabled
        autoSelectBestProfile.isEnabled = enabled
    }

    private fun scheduleReconfigure() {
        view?.post {
            runOnDefaultDispatcher { AutoUrlTester.reconfigureUpdater() }
        }
    }

}
