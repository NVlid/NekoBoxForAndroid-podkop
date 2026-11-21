package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.View
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.databinding.LayoutToolsBinding
import io.nekohasekai.sagernet.widget.ListListener

class SettingsFragment : ToolbarFragment(R.layout.layout_tools) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        ViewCompat.setOnApplyWindowInsetsListener(view, ListListener)
        toolbar.setTitle(R.string.settings)

        val pages = listOf<Fragment>(
            SettingsPreferenceFragment(),
            AutoUrlTestPreferenceFragment(),
        )
        val titles = listOf(
            getString(R.string.general_settings),
            getString(R.string.auto_url_test_settings),
        )
        val binding = LayoutToolsBinding.bind(view)
        binding.toolsPager.adapter = SettingsAdapter(pages)
        TabLayoutMediator(binding.toolsTab, binding.toolsPager) { tab, position ->
            tab.text = titles[position]
            tab.view.setOnLongClickListener { true }
        }.attach()
    }

    inner class SettingsAdapter(private val pages: List<Fragment>) : FragmentStateAdapter(this) {
        override fun getItemCount() = pages.size
        override fun createFragment(position: Int) = pages[position]
    }

}
