package com.example.app

import android.app.Application
import com.luciq.library.Luciq
import com.luciq.library.LuciqInvocationEvent
import com.luciq.library.BugReporting
import com.luciq.library.CrashReporting
import com.luciq.library.SessionReplay
import com.luciq.library.Feature
import com.luciq.library.networkinterception.LuciqOkhttpInterceptor

class MyApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        initLuciq()
    }

    private fun initLuciq() {
        Luciq.Builder(this, "android-app-token-12345")
            .setInvocationEvents(
                LuciqInvocationEvent.SHAKE,
                LuciqInvocationEvent.SCREENSHOT
            )
            .build()

        // Module configuration
        BugReporting.setState(Feature.State.ENABLED)
        BugReporting.setReportTypes(BugReporting.ReportType.BUG, BugReporting.ReportType.FEEDBACK)

        CrashReporting.setState(Feature.State.ENABLED)
        CrashReporting.setAnrState(Feature.State.ENABLED)
        CrashReporting.setNDKCrashesState(Feature.State.ENABLED)

        SessionReplay.setEnabled(true)
        SessionReplay.setNetworkLogsEnabled(true)
        SessionReplay.setUserStepsEnabled(true)
        SessionReplay.setLuciqLogsEnabled(true)

        // User identification
        Luciq.identifyUser("user@example.com", "John Doe", "user-123")

        // Custom logging
        Luciq.log("Application started")
        Luciq.setCustomData("app_tier", "premium")
        Luciq.setUserAttribute("subscription", "annual")

        // Feature flags
        Luciq.addFeatureFlag("NewOnboarding", "variant_a")
        Luciq.addFeatureFlag("DarkMode", "enabled")
    }

    fun logout() {
        Luciq.removeAllFeatureFlags()
        Luciq.logOut()
    }
}
