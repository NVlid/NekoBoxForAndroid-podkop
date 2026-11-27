package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.bg.ServiceNotification
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.runBlocking
import moe.matsuri.nb4a.utils.JavaUtil
import org.json.JSONObject
import org.json.JSONArray

class ProxyInstance(profile: ProxyEntity, var service: BaseService.Interface? = null) :
    BoxInstance(profile) {

    var notTmp = true

    var lastSelectorGroupId = -1L
    var displayProfileName = ServiceNotification.genTitle(profile)

    // for TrafficLooper
    var looper: TrafficLooper? = null

    override fun buildConfig() {
        super.buildConfig()
        lastSelectorGroupId = super.config.selectorGroupId
        //
        if (notTmp) Logs.d(configForLog(config.config))
        if (notTmp && BuildConfig.DEBUG) Logs.d(JavaUtil.gson.toJson(config.trafficMap))
    }

    private fun configForLog(raw: String): String = runCatching {
        val sensitive = setOf("secret", "password", "private_key", "private_key_passphrase")
        fun redact(value: Any?) {
            when (value) {
                is JSONObject -> value.keys().asSequence().toList().forEach { key ->
                    if (key in sensitive) value.put(key, "<redacted>") else redact(value.opt(key))
                }
                is JSONArray -> (0 until value.length()).forEach { redact(value.opt(it)) }
            }
        }
        JSONObject(raw).apply { redact(this) }.toString(2)
    }.getOrDefault("<configuration omitted>")

    // only use this in temporary instance
    fun buildConfigTmp() {
        notTmp = false
        buildConfig()
    }

    override suspend fun init() {
        super.init()
        pluginConfigs.forEach { (_, plugin) ->
            val (_, content) = plugin
            Logs.d(content)
        }
    }

    override suspend fun loadConfig() {
        super.loadConfig()
    }

    override fun launch() {
        box.setAsMain()
        super.launch() // start box
        runOnDefaultDispatcher {
            looper = service?.let { TrafficLooper(it.data, this) }
            looper?.start()
        }
    }

    override fun close() {
        super.close()
        runBlocking {
            looper?.stop()
            looper = null
        }
    }
}
