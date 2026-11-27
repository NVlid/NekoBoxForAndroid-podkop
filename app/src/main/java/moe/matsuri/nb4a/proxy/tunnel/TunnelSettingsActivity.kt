package moe.matsuri.nb4a.proxy.tunnel

import android.os.Bundle
import android.widget.Toast
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ui.profile.ProfileSettingsActivity
import moe.matsuri.nb4a.proxy.PreferenceBinding
import moe.matsuri.nb4a.proxy.PreferenceBindingManager
import moe.matsuri.nb4a.proxy.Type

class TunnelSettingsActivity : ProfileSettingsActivity<TunnelBean>() {
    private val bindings = PreferenceBindingManager().apply {
        listOf("name", "serverAddress", "domain", "secret", "recordTypes", "username",
            "password", "privateKey", "privateKeyPassphrase", "hostKey", "python").forEach {
            add(PreferenceBinding(Type.Text, it))
        }
        add(PreferenceBinding(Type.TextToInt, "serverPort"))
        add(PreferenceBinding(Type.TextToInt, "delay"))
    }

    override fun createEntity() = TunnelBean().apply {
        kind = intent.getIntExtra("tunnelKind", TunnelBean.DNSCAT2)
        initializeDefaultValues()
    }

    override fun TunnelBean.init() {
        DataStore.profileCacheStore.putInt("tunnelKind", kind)
        bindings.writeToCacheAll(this)
    }

    override fun TunnelBean.serialize() {
        kind = DataStore.profileCacheStore.getInt("tunnelKind", TunnelBean.DNSCAT2)
        bindings.fromCacheAll(this)
    }

    override suspend fun saveAndExit() {
        try {
            val candidate = createEntity().apply { serialize() }
            buildTunnelOutbound(candidate) // Validate before touching an existing profile.
        } catch (e: IllegalArgumentException) {
            onMainDispatcher {
                Toast.makeText(this@TunnelSettingsActivity, e.message, Toast.LENGTH_LONG).show()
            }
            return
        }
        super.saveAndExit()
    }

    override fun PreferenceFragmentCompat.createPreferences(savedInstanceState: Bundle?, rootKey: String?) {
        addPreferencesFromResource(R.xml.tunnel_preferences)
        val sshuttle = DataStore.profileCacheStore.getInt("tunnelKind", 0) == TunnelBean.SSHUTTLE
        findPreference<Preference>("dnsCategory")!!.isVisible = !sshuttle
        findPreference<Preference>("sshCategory")!!.isVisible = sshuttle
        findPreference<Preference>("tunnelInfo")!!.setSummary(
            if (sshuttle) R.string.sshuttle_info else R.string.dnscat2_info
        )
        findPreference<EditTextPreference>("serverPort")!!
            .setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        findPreference<EditTextPreference>("delay")!!
            .setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        listOf("secret", "password", "privateKeyPassphrase").forEach {
            findPreference<EditTextPreference>(it)!!.summaryProvider = PasswordSummaryProvider
        }
    }
}
