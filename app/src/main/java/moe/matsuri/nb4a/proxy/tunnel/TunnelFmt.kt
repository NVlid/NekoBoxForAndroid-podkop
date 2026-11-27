package moe.matsuri.nb4a.proxy.tunnel

import moe.matsuri.nb4a.SingBoxOptions
import moe.matsuri.nb4a.utils.JavaUtil.gson
import java.util.Locale

fun buildTunnelOutbound(bean: TunnelBean): SingBoxOptions.SingBoxOption {
    require(bean.serverAddress.isNotBlank()) { "Tunnel server is required" }
    require(bean.serverPort in 1..65535) { "Invalid tunnel server port" }
    val options = linkedMapOf<String, Any>(
        "server" to bean.serverAddress,
        "server_port" to bean.serverPort,
    )
    when (bean.kind) {
        TunnelBean.DNSCAT2 -> {
            require(bean.secret.isNotBlank()) { "DNScat2 requires a pre-shared secret" }
            require(bean.delay in 50..60000) { "DNScat2 delay must be 50–60000 ms" }
            val domain = bean.domain.trim().trimEnd('.')
            require(domain.length <= 46 && (domain.isEmpty() || domain.split('.').all {
                it.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"))
            })) { "DNScat2 domain must be a valid ASCII domain of at most 46 characters" }
            val records = bean.recordTypes.split(',').map { it.trim().uppercase(Locale.ROOT) }
            require(records.isNotEmpty() && records.all { it in setOf("TXT", "CNAME", "MX", "A", "AAAA") }) {
                "DNScat2 records must be TXT, CNAME, MX, A or AAAA"
            }
            options["type"] = "dnscat2"
            options["domain"] = domain
            options["secret"] = bean.secret
            options["record_types"] = records.distinct().joinToString(",")
            options["delay"] = bean.delay
        }
        TunnelBean.SSHUTTLE -> {
            require(bean.username.isNotBlank()) { "sshuttle requires a username" }
            require(bean.hostKey.isNotBlank()) { "sshuttle requires the SSH server host key" }
            require(bean.password.isNotEmpty() || bean.privateKey.isNotBlank()) { "sshuttle requires a password or private key" }
            require(bean.python.matches(Regex("[A-Za-z0-9_./-]+"))) { "Specify a Python executable path, not a shell command" }
            options["type"] = "sshuttle"
            options["user"] = bean.username
            options["host_key"] = bean.hostKey
            options["password"] = bean.password
            options["private_key"] = bean.privateKey
            options["private_key_passphrase"] = bean.privateKeyPassphrase
            options["python"] = bean.python
        }
        else -> error("Unknown embedded tunnel")
    }
    return SingBoxOptions.CustomSingBoxOption(gson.toJson(options))
}
