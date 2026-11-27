package moe.matsuri.nb4a.proxy.tunnel

import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.fmt.KryoConverters
import org.junit.Assert.*
import org.junit.Test

class TunnelProfileTest {
    private fun dns() = TunnelBean().apply {
        kind = TunnelBean.DNSCAT2
        initializeDefaultValues()
        name = "DNS test"
        serverAddress = "192.0.2.1"
        secret = "public-test-secret"
        domain = "t.example.test"
    }

    @Test fun roundTripBeanAndDatabaseType() {
        listOf(TunnelBean.DNSCAT2, TunnelBean.SSHUTTLE).forEach { kind ->
            val bean = dns().apply {
                this.kind = kind
                username = "user"
                password = "test"
                privateKey = "key\nline"
                hostKey = "ssh-ed25519 test"
            }
            val entity = ProxyEntity().putBean(bean)
            val expected = if (kind == TunnelBean.DNSCAT2) ProxyEntity.TYPE_DNSCAT2 else ProxyEntity.TYPE_SSHUTTLE
            assertEquals(expected, entity.type)
            val decoded = ProxyEntity(type = expected).apply {
                putByteArray(KryoConverters.serialize(bean))
            }.requireBean() as TunnelBean
            assertEquals(bean, decoded)
            assertEquals(bean.privateKey, decoded.privateKey)
            assertEquals(bean.secret, decoded.secret)
            assertEquals(kind, decoded.kind)
            assertFalse(entity.needExternal())
            assertFalse(entity.haveStandardLink())
        }
    }

    @Test fun buildsRegisteredOutboundNotSocks() {
        val map = buildTunnelOutbound(dns()).asMap()
        assertEquals("dnscat2", map["type"])
        assertEquals("public-test-secret", map["secret"])
        assertEquals("t.example.test", map["domain"])
        assertFalse(map.containsKey("listen"))
        assertFalse(map.containsKey("domain_strategy"))
    }

    @Test fun sameResolverCanHaveDifferentTunnelProfiles() {
        val first = dns()
        val second = dns().apply { domain = "other.example.test" }
        assertNotEquals(
            moe.matsuri.nb4a.Protocols.Deduplication(first, "DNScat2"),
            moe.matsuri.nb4a.Protocols.Deduplication(second, "DNScat2")
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMissingSecret() { buildTunnelOutbound(dns().apply { secret = "" }) }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnsupportedRecord() { buildTunnelOutbound(dns().apply { recordTypes = "TXT,ANY" }) }

    @Test fun credentialsAreNotInBeanLog() {
        assertFalse(dns().toString().contains("public-test-secret"))
    }
}
