package io.nekohasekai.sagernet.bg

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy.UPDATE
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteWorkManager
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.bg.proto.UrlTest
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.plugin.PluginManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit

object AutoUrlTester {

    private const val WORK_NAME = "AutoUrlTester"
    private val runMutex = Mutex()

    suspend fun reconfigureUpdater() {
        RemoteWorkManager.getInstance(app).cancelUniqueWork(WORK_NAME)
        if (!DataStore.autoUrlTestEnabled) return

        val interval = DataStore.autoUrlTestInterval.toLong().coerceIn(15L, 1440L)
        RemoteWorkManager.getInstance(app).enqueueUniquePeriodicWork(
            WORK_NAME,
            UPDATE,
            PeriodicWorkRequest.Builder(UpdateTask::class.java, interval, TimeUnit.MINUTES)
                .build()
        )
    }

    private suspend fun runTests() {
        if (!runMutex.tryLock()) return
        try {
            if (!DataStore.autoUrlTestEnabled) return
            val profiles = SagerDatabase.proxyDao.getAll()
            if (profiles.isEmpty()) return

            val queue = ConcurrentLinkedQueue(profiles)
            val results = ConcurrentLinkedQueue<ProxyEntity>()
            coroutineScope {
                repeat(DataStore.connectionTestConcurrent.coerceIn(1, 32)) {
                    launch(Dispatchers.IO) {
                        val urlTest = UrlTest()
                        while (isActive) {
                            val profile = queue.poll() ?: break
                            try {
                                profile.ping = urlTest.doTest(profile)
                                profile.status = 1
                                profile.error = null
                            } catch (e: PluginManager.PluginNotFoundException) {
                                profile.status = 2
                                profile.error = e.readableMessage
                            } catch (e: Exception) {
                                profile.status = 3
                                profile.error = e.readableMessage
                            }
                            results.add(profile)
                        }
                    }
                }
            }

            val tested = results.toList()
            if (tested.isEmpty()) return
            ProfileManager.updateProfile(tested)
            tested.map { it.groupId }.distinct().forEach { GroupManager.postReload(it) }

            if (DataStore.autoUrlTestEnabled && DataStore.autoSelectBestProfile) {
                selectBestProfile(tested)
            }
        } finally {
            runMutex.unlock()
        }
    }

    private suspend fun selectBestProfile(tested: List<ProxyEntity>) {
        val best = tested.filter { it.status == 1 && it.ping > 0 }
            .minByOrNull { it.ping } ?: return
        val previousId = DataStore.selectedProxy
        if (best.id == previousId) return

        val previous = tested.find { it.id == previousId }
        if (previous != null && previous.status == 1 && previous.ping > 0 && previous.ping <= best.ping) {
            return
        }

        DataStore.selectedProxy = best.id
        DataStore.selectedGroup = best.groupId
        ProfileManager.postUpdate(previousId, true)
        ProfileManager.postUpdate(best.id, true)
        Logs.d("Auto URL test: selected ${best.displayName()} (${best.ping} ms)")
        if (DataStore.serviceState.canStop) SagerNet.reloadService()
    }

    class UpdateTask(
        appContext: Context,
        params: WorkerParameters,
    ) : CoroutineWorker(appContext, params) {
        override suspend fun doWork(): Result {
            runCatching { runTests() }.onFailure { Logs.w(it) }
            return Result.success()
        }
    }

}
