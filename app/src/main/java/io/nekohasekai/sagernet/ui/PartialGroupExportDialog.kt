package io.nekohasekai.sagernet.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import androidx.core.widget.addTextChangedListener
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.databinding.LayoutGroupExportBinding
import io.nekohasekai.sagernet.ktx.FixedLinearLayoutManager
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher

class PartialGroupExportDialog(
    private val fragment: GroupFragment,
    private val group: ProxyGroup,
) {

    private lateinit var binding: LayoutGroupExportBinding
    private lateinit var profileAdapter: ProfileAdapter
    private var profiles = listOf<ProxyEntity>()
    private val selectedIds = mutableSetOf<Long>()
    private var onlyAvailable = false
    private var nameFilter = ""

    fun show() {
        runOnDefaultDispatcher {
            val groupProfiles = SagerDatabase.proxyDao.getByGroup(group.id)
            onMainDispatcher {
                if (fragment.isAdded) showProfiles(groupProfiles)
            }
        }
    }

    private fun showProfiles(groupProfiles: List<ProxyEntity>) {
        profiles = groupProfiles
        selectedIds.clear()
        selectedIds.addAll(profiles.map { it.id })
        binding = LayoutGroupExportBinding.inflate(fragment.layoutInflater)
        profileAdapter = ProfileAdapter()
        binding.exportProfiles.layoutManager = FixedLinearLayoutManager(binding.exportProfiles)
        binding.exportProfiles.adapter = profileAdapter

        binding.exportNameFilter.addTextChangedListener {
            nameFilter = it?.toString().orEmpty()
            profileAdapter.refresh()
        }
        binding.exportOnlyAvailable.setOnCheckedChangeListener { _, checked ->
            onlyAvailable = checked
            profileAdapter.refresh()
        }
        binding.exportSelectVisible.setOnClickListener {
            profileAdapter.setVisibleSelected(true)
        }
        binding.exportClearVisible.setOnClickListener {
            profileAdapter.setVisibleSelected(false)
        }
        profileAdapter.refresh()

        val dialog = MaterialAlertDialogBuilder(fragment.requireContext())
            .setTitle(R.string.partial_group_export)
            .setView(binding.root)
            .setPositiveButton(R.string.action_export_file, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                exportSelected(dialog)
            }
        }
        dialog.show()
    }

    private fun exportSelected(dialog: AlertDialog) {
        val selected = profiles.filter {
            it.id in selectedIds && (!onlyAvailable || it.isAvailable())
        }
        if (selected.isEmpty()) {
            Toast.makeText(
                fragment.requireContext(),
                R.string.partial_export_none_selected,
                Toast.LENGTH_SHORT,
            ).show()
            return
        }
        fragment.startPartialExport(selected)
        dialog.dismiss()
    }

    private fun updateSummary() {
        val eligible = profiles.filter { !onlyAvailable || it.isAvailable() }
        val selected = eligible.count { it.id in selectedIds }
        binding.exportSelectedCount.text = fragment.getString(
            R.string.partial_export_selected_count,
            selected,
            eligible.size,
        )
        binding.exportEmpty.isVisible = profileAdapter.visibleProfiles.isEmpty()
    }

    private fun ProxyEntity.isAvailable() = status == 1 && ping > 0

    private inner class ProfileAdapter : RecyclerView.Adapter<ProfileHolder>() {
        var visibleProfiles = listOf<ProxyEntity>()
            private set

        fun refresh() {
            visibleProfiles = profiles.filter {
                (!onlyAvailable || it.isAvailable()) &&
                    (nameFilter.isBlank() || it.displayName().contains(nameFilter, ignoreCase = true))
            }
            notifyDataSetChanged()
            updateSummary()
        }

        fun setVisibleSelected(selected: Boolean) {
            visibleProfiles.forEach {
                if (selected) selectedIds.add(it.id) else selectedIds.remove(it.id)
            }
            notifyDataSetChanged()
            updateSummary()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ProfileHolder {
            val checkBox = LayoutInflater.from(parent.context).inflate(
                R.layout.layout_group_export_item,
                parent,
                false,
            ) as CheckBox
            return ProfileHolder(checkBox)
        }

        override fun onBindViewHolder(holder: ProfileHolder, position: Int) {
            val profile = visibleProfiles[position]
            holder.checkBox.setOnCheckedChangeListener(null)
            holder.checkBox.isChecked = profile.id in selectedIds
            holder.checkBox.text = buildString {
                append(profile.displayName())
                append('\n')
                append(profile.displayType())
                if (profile.isAvailable()) append(" • ${profile.ping} ms")
            }
            holder.checkBox.setOnCheckedChangeListener { _, checked ->
                if (checked) selectedIds.add(profile.id) else selectedIds.remove(profile.id)
                updateSummary()
            }
        }

        override fun getItemCount() = visibleProfiles.size
    }

    private inner class ProfileHolder(val checkBox: CheckBox) : RecyclerView.ViewHolder(checkBox)

}
