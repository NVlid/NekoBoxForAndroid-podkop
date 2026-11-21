package io.nekohasekai.sagernet.fmt.wireguard

import moe.matsuri.nb4a.SingBoxOptions
import moe.matsuri.nb4a.utils.Util
import moe.matsuri.nb4a.utils.listByLineOrComma

fun parseReserved(anyStr: String): List<Int>? {
    val items = anyStr.listByLineOrComma().map {
        it.replace("[", "")
            .replace("]", "")
            .trim()
    }.filter { it.isNotEmpty() }
    val numbers = items.map { it.toIntOrNull() }
    if (numbers.size == 3 && numbers.all { it != null }) {
        return numbers.map { it!!.and(0xff) }
    }

    // Profiles created for older cores may already contain base64-encoded bytes.
    return runCatching { Util.b64Decode(anyStr) }.getOrNull()
        ?.takeIf { it.size == 3 }
        ?.map { it.toInt().and(0xff) }
}

fun buildSingBoxEndpointWireguardBean(bean: WireGuardBean): SingBoxOptions.Endpoint_WireGuardOptions {
    return SingBoxOptions.Endpoint_WireGuardOptions().apply {
        type = "wireguard"
        address = bean.localAddress.listByLineOrComma()
        private_key = bean.privateKey
        mtu = bean.mtu
        peers = listOf(SingBoxOptions.WireGuardEndpointPeer().apply {
            address = bean.serverAddress
            port = bean.serverPort
            public_key = bean.peerPublicKey
            pre_shared_key = bean.peerPreSharedKey
            allowed_ips = listOf("0.0.0.0/0", "::/0")
            if (bean.reserved.isNotBlank()) reserved = parseReserved(bean.reserved)
        })
    }
}
