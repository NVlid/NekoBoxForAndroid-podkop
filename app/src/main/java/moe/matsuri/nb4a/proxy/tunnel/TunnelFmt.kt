package moe.matsuri.nb4a.proxy.tunnel

import moe.matsuri.nb4a.SingBoxOptions
import moe.matsuri.nb4a.utils.JavaUtil.gson

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
            options["type"] = "dnscat2"
            options["domain"] = bean.domain.trim()
            options["secret"] = bean.secret
            options["record_types"] = bean.recordTypes
            options["delay"] = bean.delay
        }
        TunnelBean.SSHUTTLE -> {
            require(bean.username.isNotBlank()) { "sshuttle requires a username" }
            require(bean.hostKey.isNotBlank()) { "sshuttle requires the SSH server host key" }
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
