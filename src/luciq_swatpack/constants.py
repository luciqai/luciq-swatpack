"""
Luciq SDK API patterns and constants.

This module contains all the patterns used to detect Luciq SDK usage,
module states, and configuration in customer codebases.

Reference: https://docs.luciq.ai (redirects from docs.instabug.com)

Last verified against SDK source:
- iOS SDK: v19.1.1+ (Headers in Instabug/InstabugI/)
- Android SDK: luciq-core, luciq-bug, luciq-crash, luciq-apm, luciq-survey
"""
from __future__ import annotations

import re

# =============================================================================
# INVOCATION EVENTS
# =============================================================================
# All supported invocation events from Luciq SDK
# Reference: SDK headers LCQTypes.h (iOS), LuciqInvocationEvent.java (Android)
INVOCATION_EVENT_PATTERN = re.compile(
    r"\.(shake|screenshot|floatingButton|twoFingersSwipeLeft|twoFingersSwipe|rightEdgePan|none)"
)

# =============================================================================
# FEATURE FLAGS API
# =============================================================================
# Feature flag API patterns - supports both Swift and ObjC syntax
# Swift: Luciq.add(featureFlag: FeatureFlag(...))
# ObjC: [Luciq addFeatureFlag:...]
FEATURE_API_PATTERNS = {
    "Luciq.addFeatureFlag": "add_feature_flag",
    "Luciq.addFeatureFlags": "add_feature_flags",
    "Luciq.add(featureFlag": "add_feature_flag",  # Swift syntax
    "Luciq.removeFeatureFlag": "remove_feature_flag",
    "Luciq.removeFeatureFlags": "remove_feature_flags",
    "Luciq.removeAllFeatureFlags": "remove_all_feature_flags",
    "Luciq.clearAllFeatureFlags": "remove_all_feature_flags",  # Flutter/Dart variant
    "Luciq.checkFeatures": "check_features",
}

# =============================================================================
# MODULE DEFAULT STATES
# =============================================================================
# Modules enabled by default when SDK is initialized
# Reference: https://docs.luciq.ai/docs/ios-*
MODULE_DEFAULT_TRUE = {
    "bug_reporting_enabled",
    "crash_reporting_enabled",
    "anr_monitor_enabled",        # App hang detection (CrashReporting.appHangEnabled)
    "session_replay_enabled",
    "apm_enabled",
    "network_logs_enabled",
    "user_steps_enabled",
    "surveys_enabled",
    "feature_requests_enabled",
    "in_app_replies_enabled",
    "in_app_chat_enabled",
    "oom_monitor_enabled",        # Out of memory crash detection
    "force_restart_enabled",      # Force restart detection (CrashReporting.forceRestartEnabled)
    "network_auto_masking_enabled",  # Auto-mask sensitive headers (SDK 14.2+)
}

MODULE_DEFAULT_FALSE = {
    "sdk_globally_disabled",
    "debug_logs_enabled",
}

# =============================================================================
# NETWORK PRIVACY
# =============================================================================
# Sensitive headers that should be masked in network logging
NETWORK_SENSITIVE_HEADERS = [
    "Authorization",
    "Cookie",
    "X-API-Key",
    "Set-Cookie",
]

# Sensitive body fields that should be masked
NETWORK_SENSITIVE_BODY_FIELDS = [
    "password",
    "token",
    "access_token",
    "refresh_token",
    "ssn",
    "email",
]

# =============================================================================
# iOS PERMISSIONS
# =============================================================================
# Info.plist usage description keys
IOS_USAGE_DESCRIPTION_KEYS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSPhotoLibraryUsageDescription": "photo_library",
    "NSPhotoLibraryAddUsageDescription": "photo_library_add",
}

# =============================================================================
# ANDROID PERMISSIONS
# =============================================================================
ANDROID_PERMISSION_KEYS = {
    "android.permission.INTERNET": "internet",
    "android.permission.ACCESS_NETWORK_STATE": "network_state",
    "android.permission.RECORD_AUDIO": "record_audio",
    "android.permission.READ_EXTERNAL_STORAGE": "read_storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "write_storage",
    "android.permission.POST_NOTIFICATIONS": "post_notifications",
}

# =============================================================================
# ATTACHMENTS
# =============================================================================
# Map attachment types to required permissions
ATTACHMENT_PERMISSION_MAP = {
    "gallery_image": "photo_library",
    "voice_note": "microphone",
}

# Attachment type labels in code
ATTACHMENT_LABELS = {
    "screenshot": ["screenshot", "screenShot"],
    "extra_screenshot": ["extraScreenshot", "extraScreenShot"],
    "gallery_image": ["galleryImage", "gallery"],
    "voice_note": ["voiceNote"],
    "screen_recording": ["screenRecording"],
}

# =============================================================================
# PROGRAMMATIC INVOCATION
# =============================================================================
# Patterns for programmatic SDK invocation (not gesture-based)
PROGRAMMATIC_INVOCATION_PATTERNS = [
    "Luciq.show(",
    "Luciq.invoke(",
    "BugReporting.show(",
    "BugReporting.invoke(",
]

# =============================================================================
# LOGGING API
# =============================================================================
# Logging API patterns - supports both namespaces
# Old: Luciq.log*, New: LCQLog.log*
# Also includes user event logging
CUSTOM_LOG_PATTERNS = [
    "Luciq.log(",
    "Luciq.logVerbose(",
    "Luciq.logInfo(",
    "Luciq.logWarn(",
    "Luciq.logError(",
    "Luciq.logDebug(",
    "LCQLog.log(",           # Current Swift API
    "LCQLog.logVerbose(",
    "LCQLog.logInfo(",
    "LCQLog.logWarn(",
    "LCQLog.logError(",
    "LCQLog.logDebug(",
    "Luciq.logUserEvent(",   # User event logging
    "LCQLogVerbose(",        # ObjC macros
    "LCQLogInfo(",
    "LCQLogWarn(",
    "LCQLogError(",
    "LCQLogDebug(",
]

# =============================================================================
# USER DATA API
# =============================================================================
# User data and attribute patterns
# Reference: https://docs.luciq.ai/docs/user-data
CUSTOM_DATA_PATTERNS = [
    "Luciq.setCustomData",
    "Luciq.addUserAttribute",
    "Luciq.setUserAttribute",
    "Luciq.userData",          # Swift property syntax
    "Luciq.setUserData(",      # Method syntax (Android/RN/Flutter)
    "Luciq.trackUserSteps",    # User steps tracking toggle
]

# =============================================================================
# MODULE TOGGLE PATTERNS (iOS)
# =============================================================================
# Module toggle patterns - supports both property and method syntax
# Reference: SDK headers LCQBugReporting.h, LCQCrashReporting.h, LCQAPM.h, etc.
MODULE_TOGGLE_PATTERNS = {
    "bug_reporting_enabled": [
        "Luciq.setBugReportingEnabled",
        "BugReporting.enabled",
        "BugReporting.setState",
        "LCQBugReporting.enabled",  # ObjC
        "BugReporting.promptOptionsEnabledReportTypes",  # Report types control
    ],
    "crash_reporting_enabled": [
        "Luciq.setCrashReportingEnabled",
        "CrashReporting.enabled",
        "CrashReporting.setState",
        "LCQCrashReporting.enabled",  # ObjC
        "CrashReporting.unhandledEnabled",  # Unhandled crash toggle
    ],
    "session_replay_enabled": [
        "Luciq.setSessionReplayEnabled",
        "SessionReplay.enabled",
        "LCQSessionReplay.enabled",  # ObjC
    ],
    "surveys_enabled": [
        "Luciq.setSurveysEnabled",
        "Surveys.enabled",
        "Surveys.setState",         # Android
        "LCQSurveys.enabled",       # ObjC
        "LCQSurveys.setEnabled",
        "Surveys.autoShowingEnabled",
    ],
    "feature_requests_enabled": [
        "Luciq.setFeatureRequestsEnabled",
        "FeatureRequests.enabled",
        "FeatureRequests.setState",  # Android
        "LCQFeatureRequests.enabled",  # ObjC
    ],
    "in_app_replies_enabled": [
        "Luciq.setRepliesEnabled",
        "Replies.enabled",
        "Replies.setState",         # Android
        "Luciq.setChatsEnabled",
        "LCQReplies.enabled",       # ObjC
    ],
    "in_app_chat_enabled": [
        "Luciq.setChatsEnabled",
        "Chats.enabled",
        "LCQChats.enabled",  # ObjC
    ],
    "apm_enabled": [
        "Luciq.setAPMEnabled",
        "APM.enabled",
        "APM.setEnabled",           # Android
        "LCQAPM.enabled",           # ObjC
    ],
    "network_logs_enabled": [
        "SessionReplay.setNetworkLogsEnabled",
        "SessionReplay.networkLogsEnabled",
        "LCQSessionReplay.networkLogsEnabled",  # ObjC
        "NetworkLogger.enabled",
        "LCQNetworkLogger.enabled",  # ObjC
    ],
    "user_steps_enabled": [
        "SessionReplay.setUserStepsEnabled",
        "SessionReplay.userStepsEnabled",
        "LCQSessionReplay.userStepsEnabled",  # ObjC
        "Luciq.setTrackingUserStepsState",    # Android
        "Luciq.trackUserSteps",               # iOS property
    ],
    "oom_monitor_enabled": [
        "CrashReporting.oomEnabled",
        "CrashReporting.OOMEnabled",  # Correct case
        "LCQCrashReporting.OOMEnabled",  # ObjC
    ],
    "anr_monitor_enabled": [
        "CrashReporting.setAnrState",
        "CrashReporting.appHangEnabled",  # Modern API name (iOS)
        "LCQCrashReporting.appHangEnabled",  # ObjC
    ],
    "force_restart_enabled": [
        "CrashReporting.forceRestartEnabled",
        "LCQCrashReporting.forceRestartEnabled",  # ObjC
    ],
    "network_auto_masking_enabled": [
        "NetworkLogger.autoMaskingEnabled",
        "LCQNetworkLogger.autoMaskingEnabled",  # ObjC
        "Luciq.setNetworkAutoMaskingState",    # Android
    ],
    # Session Replay sub-features
    "session_replay_logs_enabled": [
        "SessionReplay.LCQLogsEnabled",         # iOS
        "LCQSessionReplay.LCQLogsEnabled",      # ObjC
        "SessionReplay.setLuciqLogsEnabled",    # Android
    ],
}

# =============================================================================
# PRIVATE VIEW PATTERNS
# =============================================================================
# Private view detection patterns
# Reference: Luciq.h (iOS), Luciq.java (Android)
# iOS Swift: view.luciq_privateView = true
# iOS ObjC: view.luciq_setPrivateView = YES
# Android: Luciq.addPrivateViews(view1, view2)
# Compose: .luciqPrivate modifier
PRIVATE_VIEW_PATTERNS = [
    # iOS patterns
    ".luciq_privateView",          # Swift/ObjC property
    "luciq_setPrivateView",        # Alternative ObjC pattern
    ".luciqPrivate",               # Legacy/Compose pattern
    "Luciq.setPrivateView",        # Method style
    # Android patterns
    "Luciq.addPrivateViews(",      # Add private views
    "Luciq.removePrivateViews(",   # Remove private views
    "Luciq.removeAllPrivateViews(", # Clear all private views
]

# =============================================================================
# SYMBOL UPLOAD / API ENDPOINTS
# =============================================================================
# API endpoint patterns - both Instabug (legacy/current API) and Luciq domains
# Note: API endpoint is still api.instabug.com as of docs
ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"']*(instabug\.com|luciq\.ai)[^\s\"']*")

# Token patterns in environment files and scripts
TOKEN_ENV_PATTERN = re.compile(r"(INSTABUG|LUCIQ)_APP_TOKEN\s*=?\s*['\"]?([A-Za-z0-9_\-]+)")
APP_TOKEN_PATTERN = re.compile(r"appToken\s*=\s*['\"]([^\"']+)['\"]")

# Token extraction from Swift code
TOKEN_LITERAL_PATTERN = re.compile(r'withToken:\s*"([^"]+)"')
TOKEN_IDENTIFIER_PATTERN = re.compile(
    r"withToken:\s*([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)
TOKEN_DECL_PATTERN = re.compile(
    r"(?:static\s+)?(?:private\s+|fileprivate\s+|public\s+|internal\s+)?(?:let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String)?\s*=\s*\"([^\"]+)\""
)

# =============================================================================
# dSYM UPLOAD SCRIPT PATTERNS
# =============================================================================
# Keywords to detect dSYM upload scripts in Xcode projects
DSYM_SCRIPT_KEYWORDS = [
    "upload_symbols", "upload-symbols",
    "Luciq_dsym_upload.sh",  # New Luciq script name
    "instabug", "luciq"
]

# Keywords to detect dSYM upload in shell scripts
SHELL_SCRIPT_KEYWORDS = [
    "upload", "dsym", "symbols",
    "instabug", "luciq"
]

# =============================================================================
# ANDROID-SPECIFIC PATTERNS
# =============================================================================
# Android SDK initialization patterns
# Kotlin: Luciq.Builder(this, "APP_TOKEN").build()
# Java: new Luciq.Builder(this, "APP_TOKEN").build()
ANDROID_INIT_PATTERNS = [
    "Luciq.Builder(",
    "new Luciq.Builder(",
    "LuciqInvocationEvent.",
]

# Android module toggle patterns - uses setState/setEnabled methods
# Reference: SDK source files BugReporting.java, CrashReporting.java, APM.java, etc.
ANDROID_MODULE_TOGGLE_PATTERNS = {
    "bug_reporting_enabled": [
        "BugReporting.setState(",
        "BugReporting.setReportTypes(",
        "BugReporting.setOptions(",
    ],
    "crash_reporting_enabled": [
        "CrashReporting.setState(",
        "CrashReporting.setUserIdentificationState(",
    ],
    "session_replay_enabled": [
        "SessionReplay.setEnabled(",
    ],
    "anr_monitor_enabled": [
        "CrashReporting.setAnrState(",
    ],
    "ndk_crashes_enabled": [
        "CrashReporting.setNDKCrashesState(",
    ],
    "network_logs_enabled": [
        "SessionReplay.setNetworkLogsEnabled(",
    ],
    "user_steps_enabled": [
        "SessionReplay.setUserStepsEnabled(",
    ],
    "luciq_logs_enabled": [
        "SessionReplay.setLuciqLogsEnabled(",
    ],
    # APM Module controls
    "apm_enabled": [
        "APM.setEnabled(",
    ],
    "apm_cold_launch_enabled": [
        "APM.setColdAppLaunchEnabled(",
    ],
    "apm_hot_launch_enabled": [
        "APM.setHotAppLaunchEnabled(",
    ],
    "apm_warm_launch_enabled": [
        "APM.setWarmAppLaunchEnabled(",
    ],
    "apm_auto_ui_trace_enabled": [
        "APM.setAutoUITraceEnabled(",
    ],
    "apm_ui_hang_enabled": [
        "APM.setUIHangEnabled(",
    ],
    "apm_screen_loading_enabled": [
        "APM.setScreenLoadingEnabled(",
    ],
    "apm_fragment_spans_enabled": [
        "APM.setFragmentSpansEnabled(",
    ],
    "apm_compose_spans_enabled": [
        "APM.setComposeSpansEnabled(",
    ],
    "apm_webview_tracking_enabled": [
        "APM.setWebViewsTrackingEnabled(",
    ],
    # Surveys Module
    "surveys_enabled": [
        "Surveys.setState(",
        "Surveys.setAutoShowingEnabled(",
    ],
    # Replies Module
    "in_app_replies_enabled": [
        "Replies.setState(",
        "Replies.setPushNotificationState(",
        "Replies.setInAppNotificationEnabled(",
    ],
    # Feature Requests Module
    "feature_requests_enabled": [
        "FeatureRequests.setState(",
    ],
    # View Hierarchy capture
    "view_hierarchy_enabled": [
        "BugReporting.setViewHierarchyState(",
    ],
    # User identification in reports
    "user_identification_enabled": [
        "BugReporting.setUserIdentificationState(",
        "CrashReporting.setUserIdentificationState(",
        "FeatureRequests.setUserIdentificationState(",
    ],
}

# Android invocation events
ANDROID_INVOCATION_EVENTS = [
    "LuciqInvocationEvent.SHAKE",
    "LuciqInvocationEvent.FLOATING_BUTTON",
    "LuciqInvocationEvent.SCREENSHOT",
    "LuciqInvocationEvent.TWO_FINGER_SWIPE_LEFT",
    "LuciqInvocationEvent.NONE",
]

# Android network logging patterns
# Reference: SDK source LuciqAPMOkhttpInterceptor.java, NetworkLogListener.java
ANDROID_NETWORK_PATTERNS = [
    "LuciqNetworkLog",
    "LuciqOkhttpInterceptor",
    "LuciqAPMOkhttpInterceptor",   # APM-enabled interceptor
    "LuciqAPMGrpcInterceptor",     # gRPC interceptor
    "NetworkLogListener",
    "registerNetworkLogsListener(",
    "removeNetworkLogsListener(",
    "addOnNetworkTraceListener(",  # APM network trace listener
    "removeOnNetworkTraceListener(",
    ".addNetworkInterceptor(",     # OkHttp integration pattern
    ".addInterceptor(LuciqOkhttpInterceptor",
    ".addInterceptor(LuciqAPMOkhttpInterceptor",
]

# =============================================================================
# ANDROID APM EXTENDED PATTERNS
# =============================================================================
# Additional APM patterns for screen loading, fragments, compose spans
# Reference: APM.java, APM.kt in luciq-apm module
ANDROID_APM_EXTENDED_PATTERNS = [
    # Screen Loading
    "APM.startScreenLoading(",
    "APM.endScreenLoading(",
    "APM.setScreenLoadingEnabled(",
    # Fragment Spans
    "APM.setFragmentSpansEnabled(",
    # Compose Spans
    "APM.setComposeSpansEnabled(",
    # WebView Tracking
    "APM.setWebViewsTrackingEnabled(",
    # UI Hang Detection
    "APM.setUIHangEnabled(",
    # Auto UI Trace
    "APM.setAutoUITraceEnabled(",
    # Network Latency
    "LuciqApmOkHttpEventListener",
    "InstabugApmOkHttpEventListener",  # Legacy name
]

# =============================================================================
# ANDROID BUG REPORTING EXTENDED PATTERNS
# =============================================================================
# Additional Bug Reporting patterns
# Reference: BugReporting.java, BugReporting.kt
ANDROID_BUG_REPORTING_PATTERNS = [
    # Screen Recording
    "BugReporting.setAutoScreenRecordingEnabled(",
    "BugReporting.setScreenshotByMediaProjectionEnabled(",
    # Shaking threshold
    "BugReporting.setShakingThreshold(",
    # Extended Bug Report
    "BugReporting.setExtendedBugReportState(",
    "ExtendedBugReport.State.",
    # Report Types
    "BugReporting.setReportTypes(",
    "BugReporting.ReportType.",
    # Proactive Reporting
    "BugReporting.setProactiveReportingConfigurations(",
    # Callbacks
    "BugReporting.setOnInvokeCallback(",
    "BugReporting.setOnDismissCallback(",
    # View Hierarchy
    "BugReporting.setViewHierarchyState(",
]

# =============================================================================
# ANDROID SESSION REPLAY PATTERNS
# =============================================================================
# Session Replay configuration
# Reference: SessionReplay.java, SessionReplay.kt
ANDROID_SESSION_REPLAY_PATTERNS = [
    "SessionReplay.setState(",
    "SessionReplay.setNetworkLogsEnabled(",
    "SessionReplay.setSyncCallback(",
    "SessionReplay.setSyncCallback {",   # Kotlin lambda syntax
    "SessionReplay.setLuciqLogsEnabled(",
    "SessionReplay.setUserStepsEnabled(",
]

# =============================================================================
# ANDROID CRASH REPORTING EXTENDED PATTERNS
# =============================================================================
# Additional Crash Reporting patterns
# Reference: CrashReporting.java
ANDROID_CRASH_REPORTING_PATTERNS = [
    # Callbacks
    "CrashReporting.setOnCrashSentCallback(",
    # Non-fatal reporting
    "CrashReporting.report(",
    "LuciqNonFatalException.Builder(",
    "LuciqNonFatalException(",
    # User Identification
    "CrashReporting.setUserIdentificationState(",
]

# =============================================================================
# ANDROID MASKING PATTERNS
# =============================================================================
# Android auto-masking patterns
# Reference: MaskingType.java, Luciq.java
ANDROID_MASKING_PATTERNS = [
    "MaskingType.MEDIA",
    "MaskingType.LABELS",
    "MaskingType.INPUT_FIELDS",
    "MaskingType.NONE",
    "Luciq.setAutoMaskScreenshotsTypes(",
    "Luciq.setNetworkAutoMaskingState(",
]

# =============================================================================
# APM (Application Performance Monitoring) PATTERNS
# =============================================================================
# APM API patterns for flows, traces, and performance monitoring
# Reference: LCQAPM.h (iOS), APM.java (Android)
APM_FLOW_PATTERNS = [
    # iOS Flow APIs
    "APM.startFlowWithName:",
    "APM.endFlowWithName:",
    "APM.setAttributeForFlowWithName:",
    "LCQAPM.startFlowWithName:",       # ObjC
    "LCQAPM.endFlowWithName:",         # ObjC
    # Android Flow APIs
    "APM.startFlow(",
    "APM.endFlow(",
    "APM.setFlowAttribute(",
]

APM_TRACE_PATTERNS = [
    # iOS Trace APIs
    "APM.startUITraceWithName:",
    "APM.endUITrace",
    "APM.startExecutionTraceWithName:",  # Deprecated
    "LCQAPM.startUITraceWithName:",      # ObjC
    "LCQAPM.endUITrace",                 # ObjC
    # Android Trace APIs
    "APM.startUITrace(",
    "APM.endUITrace(",
]

APM_LIFECYCLE_PATTERNS = [
    # iOS App Launch/Screen Load
    "APM.endAppLaunch",
    "APM.endScreenLoadingForViewController:",
    "LCQAPM.endAppLaunch",               # ObjC
    "LCQAPM.endScreenLoadingForViewController:",  # ObjC
    # Android App Launch/Screen Load
    "APM.endAppLaunch(",
    "APM.endScreenLoading(",
]

# =============================================================================
# NON-FATAL CRASH/EXCEPTION REPORTING PATTERNS
# =============================================================================
# Patterns for reporting handled exceptions and errors
# Reference: LCQCrashReporting.h (iOS), CrashReporting.java (Android)
NON_FATAL_PATTERNS = [
    # iOS Non-Fatal APIs
    "CrashReporting.exception:",         # Report NSException
    "CrashReporting.error:",             # Report NSError
    "LCQCrashReporting.exception:",      # ObjC
    "LCQCrashReporting.error:",          # ObjC
    # Android Non-Fatal APIs
    "CrashReporting.report(",            # Report LuciqNonFatalException
    "LuciqNonFatalException.Builder(",   # Exception builder
    "LuciqNonFatalException(",
]

# =============================================================================
# NETWORK OBFUSCATION/MASKING PATTERNS
# =============================================================================
# Network request/response modification for privacy
# Reference: LCQNetworkLogger.h (iOS), NetworkLogListener.java (Android)
NETWORK_OBFUSCATION_PATTERNS = [
    # iOS Network Obfuscation
    "NetworkLogger.setRequestObfuscationHandler:",
    "NetworkLogger.setResponseObfuscationHandler:",
    "NetworkLogger.setNetworkLoggingRequestFilterPredicate:",
    "LCQNetworkLogger.setRequestObfuscationHandler:",    # ObjC
    "LCQNetworkLogger.setResponseObfuscationHandler:",   # ObjC
    # Network body logging control
    "NetworkLogger.logBodyEnabled",
    "LCQNetworkLogger.logBodyEnabled",   # ObjC
    "Luciq.setNetworkLogBodyEnabled(",   # Android
    # Disable automatic capture
    "NetworkLogger.disableAutomaticCapturingOfNetworkLogs",
]

# =============================================================================
# USER CONSENT PATTERNS
# =============================================================================
# User consent checkboxes in bug reports
# Reference: LCQBugReporting.h (iOS), BugReporting.java (Android)
USER_CONSENT_PATTERNS = [
    # iOS
    "BugReporting.addUserConsentWithKey:",
    "LCQBugReporting.addUserConsentWithKey:",  # ObjC
    # Android
    "BugReporting.addUserConsent(",
]

# =============================================================================
# SDK STATE CONTROL PATTERNS
# =============================================================================
# Patterns for globally enabling/disabling/pausing SDK
# Reference: Luciq.h (iOS), Luciq.java (Android)
SDK_STATE_PATTERNS = [
    # iOS
    "Luciq.enabled",               # Property
    "Luciq.setEnabled:",           # Setter
    # Android
    "Luciq.enable(",
    "Luciq.disable(",
    "Luciq.pauseSdk(",
    "Luciq.resumeSdk(",
    "Luciq.isEnabled(",
]

# =============================================================================
# WELCOME MESSAGE PATTERNS
# =============================================================================
# Welcome message configuration
# Reference: Luciq.h (iOS), Luciq.java (Android)
WELCOME_MESSAGE_PATTERNS = [
    # iOS
    "Luciq.welcomeMessageMode",
    "Luciq.showWelcomeMessageWithMode:",
    # Android
    "Luciq.setWelcomeMessageState(",
    "Luciq.showWelcomeMessage(",
]

# =============================================================================
# SCREENSHOT CAPTURE PATTERNS
# =============================================================================
# Manual screenshot capture and masking
# Reference: Luciq.h (iOS), Luciq.java (Android)
SCREENSHOT_PATTERNS = [
    # Manual capture
    "Luciq.captureScreenshot",
    # Auto-masking configuration
    "Luciq.setAutoMaskScreenshots:",         # iOS
    "Luciq.autoMaskAllSwiftUIViews",         # iOS SwiftUI
    "Luciq.setAutoMaskScreenshotsTypes(",    # Android
    # Screenshot provider (Android)
    "Luciq.setScreenshotProvider(",
]

# =============================================================================
# WEBVIEW TRACKING PATTERNS
# =============================================================================
# WebView monitoring and tracking APIs (iOS SDK v19.2.0+)
# Reference: Luciq.h, LCQAPM.h headers
# Docs: https://docs.luciq.ai/docs/ios-webviews
WEBVIEW_PATTERNS = [
    # iOS Master switch (default: true)
    "Luciq.webViewMonitoringEnabled",
    "LCQ.webViewMonitoringEnabled",          # ObjC
    # User interactions tracking in WebViews (default: false)
    "Luciq.webViewUserInteractionsTrackingEnabled",
    "LCQ.webViewUserInteractionsTrackingEnabled",  # ObjC
    # Network tracking in WebViews (default: false)
    "Luciq.webViewNetworkTrackingEnabled",
    "LCQ.webViewNetworkTrackingEnabled",     # ObjC
    # APM WebView tracking toggle
    "APM.webViewsTrackingEnabled",
    "LCQAPM.webViewsTrackingEnabled",        # ObjC
]

# Auto-masking options that include WebViews
WEBVIEW_MASKING_PATTERNS = [
    ".webViews",                             # Auto-masking option
    "LCQAutoMaskScreenshotsOptionWebViews",  # ObjC enum
]

# =============================================================================
# REACT NATIVE-SPECIFIC PATTERNS
# =============================================================================
# React Native SDK initialization patterns
# import Luciq, { InvocationEvent } from '@luciq/react-native';
# Luciq.init({ token: 'APP_TOKEN', invocationEvents: [...] })
REACT_NATIVE_INIT_PATTERNS = [
    "Luciq.init(",
    "@luciq/react-native",
    "luciq-react-native",
    "instabug-reactnative",  # Legacy package name
    "InvocationEvent.shake",
    "InvocationEvent.screenshot",
    "InvocationEvent.floatingButton",
    "InvocationEvent.twoFingersSwipeLeft",
    "InvocationEvent.none",
]

# React Native APM patterns
# Reference: luciq-reactnative-sdk/src/modules/APM.ts
REACT_NATIVE_APM_PATTERNS = [
    # Flow APIs
    "APM.startFlow(",
    "APM.setFlowAttribute(",
    "APM.endFlow(",
    # Trace APIs
    "APM.startUITrace(",
    "APM.endUITrace(",
    # App Launch
    "APM.endAppLaunch(",
    # Screen Loading
    "APM.startScreenLoading(",
    "APM.endScreenLoading(",
    # Module control
    "APM.setEnabled(",
    "APM.isEnabled(",
    # Cold launch
    "APM.setColdAppLaunchEnabled(",
    "APM.isAppLaunchEnabled(",
    # Screen loading control
    "APM.setScreenLoadingEnabled(",
    "APM.isScreenLoadingEnabled(",
]

# React Native Bug Reporting patterns
# Reference: luciq-reactnative-sdk/src/modules/BugReporting.ts
REACT_NATIVE_BUG_REPORTING_PATTERNS = [
    "BugReporting.setEnabled(",
    "BugReporting.setInvocationEvents(",
    "BugReporting.setInvocationOptions(",
    "BugReporting.setReportTypes(",
    "BugReporting.setExtendedBugReportMode(",
    "BugReporting.setOptions(",
    "BugReporting.show(",
    "BugReporting.setOnInvokeHandler(",
    "BugReporting.setOnDismissHandler(",
    "BugReporting.setOnSDKDismissedHandler(",
    "BugReporting.setShakingThresholdForiPhone(",
    "BugReporting.setShakingThresholdForiPad(",
    "BugReporting.setShakingThresholdForAndroid(",
    "BugReporting.setEnabledAttachmentTypes(",
    "BugReporting.setAutoScreenRecordingEnabled(",
    "BugReporting.setAutoScreenRecordingMaxDuration(",
    "BugReporting.setViewHierarchyEnabled(",
    "BugReporting.setFloatingButtonEdge(",
    "BugReporting.setVideoRecordingFloatingButtonPosition(",
    "BugReporting.setDisclaimerText(",
    "BugReporting.setCommentMinimumCharacterCount(",
    # Proactive reporting
    "BugReporting.setProactiveReportingEnabled(",
    "BugReporting.setProactiveReportingConfigurations(",
    "BugReporting.addUserConsent(",
]

# React Native Crash Reporting patterns
# Reference: luciq-reactnative-sdk/src/modules/CrashReporting.ts
REACT_NATIVE_CRASH_REPORTING_PATTERNS = [
    "CrashReporting.setEnabled(",
    "CrashReporting.reportError(",
    "CrashReporting.reportHandledError(",
    "CrashReporting.setNonFatalErrorLevel(",
    "CrashReporting.setNDKCrashesEnabled(",
    # User identification
    "CrashReporting.setErrorIdentificationState(",
]

# React Native Session Replay patterns
# Reference: luciq-reactnative-sdk/src/modules/SessionReplay.ts
REACT_NATIVE_SESSION_REPLAY_PATTERNS = [
    "SessionReplay.setEnabled(",
    "SessionReplay.setNetworkLogsEnabled(",
    "SessionReplay.setInstabugLogsEnabled(",
    "SessionReplay.setLuciqLogsEnabled(",
    "SessionReplay.setUserStepsEnabled(",
    "SessionReplay.getSessionReplayLink(",
    "SessionReplay.maskViewComponentsWithTag(",
    "SessionReplay.setOnSyncCallbackHandler(",
]

# React Native Network Logger patterns
# Reference: luciq-reactnative-sdk/src/modules/NetworkLogger.ts
REACT_NATIVE_NETWORK_PATTERNS = [
    "NetworkLogger.setEnabled(",
    "NetworkLogger.setNetworkDataObfuscationHandler(",
    "NetworkLogger.setRequestFilterExpression(",
    "NetworkLogger.setProgressHandlerForRequest(",
    "NetworkLogger.registerNetworkLogsListener(",
    "NetworkLogger.removeNetworkLogsListener(",
]

# React Native Surveys patterns
REACT_NATIVE_SURVEYS_PATTERNS = [
    "Surveys.setEnabled(",
    "Surveys.showSurveyIfAvailable(",
    "Surveys.showSurvey(",
    "Surveys.setAutoShowingEnabled(",
    "Surveys.setOnShowHandler(",
    "Surveys.setOnDismissHandler(",
    "Surveys.getAvailableSurveys(",
    "Surveys.hasRespondedToSurvey(",
    "Surveys.setShouldShowWelcomeScreen(",
]

# React Native Replies patterns
REACT_NATIVE_REPLIES_PATTERNS = [
    "Replies.setEnabled(",
    "Replies.setOnNewReplyReceivedHandler(",
    "Replies.hasChats(",
    "Replies.show(",
    "Replies.setPushNotificationsEnabled(",
    "Replies.setInAppNotificationEnabled(",
    "Replies.setInAppNotificationSound(",
]

# React Native Feature Requests patterns
REACT_NATIVE_FEATURE_REQUESTS_PATTERNS = [
    "FeatureRequests.setEnabled(",
    "FeatureRequests.show(",
]

# React Native module toggle patterns
REACT_NATIVE_MODULE_TOGGLE_PATTERNS = {
    "bug_reporting_enabled": [
        "BugReporting.setEnabled(",
    ],
    "crash_reporting_enabled": [
        "CrashReporting.setEnabled(",
    ],
    "session_replay_enabled": [
        "SessionReplay.setEnabled(",
    ],
    "apm_enabled": [
        "APM.setEnabled(",
    ],
    "network_logs_enabled": [
        "SessionReplay.setNetworkLogsEnabled(",
        "NetworkLogger.setEnabled(",
    ],
    "user_steps_enabled": [
        "SessionReplay.setUserStepsEnabled(",
    ],
    "surveys_enabled": [
        "Surveys.setEnabled(",
    ],
    "in_app_replies_enabled": [
        "Replies.setEnabled(",
    ],
    "feature_requests_enabled": [
        "FeatureRequests.setEnabled(",
    ],
    "ndk_crashes_enabled": [
        "CrashReporting.setNDKCrashesEnabled(",
    ],
}

# =============================================================================
# FLUTTER-SPECIFIC PATTERNS
# =============================================================================
# Flutter SDK initialization patterns
# import 'package:luciq_flutter/luciq_flutter.dart';
# Luciq.init(token: 'APP_TOKEN', invocationEvents: [...])
FLUTTER_INIT_PATTERNS = [
    "luciq_flutter",
    "package:luciq_flutter",
    "instabug_flutter",  # Legacy package name
    "package:instabug_flutter",
    "Luciq.init(",
    "InvocationEvent.shake",
    "InvocationEvent.screenshot",
    "InvocationEvent.floatingButton",
    "InvocationEvent.twoFingersSwipeLeft",
    "InvocationEvent.none",
]

# Flutter APM patterns
# Reference: luciq-flutter-sdk/packages/luciq_flutter/lib/src/modules/apm.dart
FLUTTER_APM_PATTERNS = [
    # Module control
    "APM.setEnabled(",
    "APM.isEnabled(",
    # Flow APIs
    "APM.startFlow(",
    "APM.setFlowAttribute(",
    "APM.endFlow(",
    # Trace APIs
    "APM.startUITrace(",
    "APM.endUITrace(",
    "APM.setAutoUITraceEnabled(",
    # Screen Loading
    "APM.setScreenLoadingEnabled(",
    "APM.isScreenLoadingEnabled(",
    "APM.endScreenLoading(",
    "APM.wrapRoutes(",  # Flutter-specific route wrapper
    # App Launch
    "APM.endAppLaunch(",
    "APM.setColdAppLaunchEnabled(",
    # Network logging (Android)
    "APM.networkLogAndroid(",
]

# Flutter Bug Reporting patterns
# Reference: luciq-flutter-sdk/packages/luciq_flutter/lib/src/modules/bug_reporting.dart
FLUTTER_BUG_REPORTING_PATTERNS = [
    "BugReporting.setEnabled(",
    "BugReporting.setInvocationEvents(",
    "BugReporting.setInvocationOptions(",
    "BugReporting.setReportTypes(",
    "BugReporting.setExtendedBugReportMode(",
    "BugReporting.show(",
    "BugReporting.setOnInvokeCallback(",
    "BugReporting.setOnDismissCallback(",
    "BugReporting.setShakingThresholdForiPhone(",
    "BugReporting.setShakingThresholdForiPad(",
    "BugReporting.setShakingThresholdForAndroid(",
    "BugReporting.setEnabledAttachmentTypes(",
    "BugReporting.setFloatingButtonEdge(",
    "BugReporting.setVideoRecordingFloatingButtonPosition(",
    "BugReporting.setDisclaimerText(",
    "BugReporting.setCommentMinimumCharacterCount(",
    # User consent
    "BugReporting.addUserConsents(",
    # Proactive reporting
    "BugReporting.setProactiveReportingConfigurations(",
]

# Flutter Crash Reporting patterns
# Reference: luciq-flutter-sdk/packages/luciq_flutter/lib/src/modules/crash_reporting.dart
FLUTTER_CRASH_REPORTING_PATTERNS = [
    "CrashReporting.setEnabled(",
    "CrashReporting.reportCrash(",
    "CrashReporting.reportHandledCrash(",
    "CrashReporting.setNDKEnabled(",
    # Enums
    "NonFatalExceptionLevel.error",
    "NonFatalExceptionLevel.critical",
    "NonFatalExceptionLevel.info",
    "NonFatalExceptionLevel.warning",
]

# Flutter Session Replay patterns
# Reference: luciq-flutter-sdk/packages/luciq_flutter/lib/src/modules/session_replay.dart
FLUTTER_SESSION_REPLAY_PATTERNS = [
    "SessionReplay.setEnabled(",
    "SessionReplay.setNetworkLogsEnabled(",
    "SessionReplay.setLuciqLogsEnabled(",
    "SessionReplay.setUserStepsEnabled(",
    "SessionReplay.getSessionReplayLink(",
]

# Flutter Surveys patterns
FLUTTER_SURVEYS_PATTERNS = [
    "Surveys.setEnabled(",
    "Surveys.showSurveyIfAvailable(",
    "Surveys.showSurvey(",
    "Surveys.setAutoShowingEnabled(",
    "Surveys.setOnShowCallback(",
    "Surveys.setOnDismissCallback(",
    "Surveys.getAvailableSurveys(",
    "Surveys.hasRespondedToSurvey(",
    "Surveys.setShouldShowWelcomeScreen(",
]

# Flutter Replies patterns
FLUTTER_REPLIES_PATTERNS = [
    "Replies.setEnabled(",
    "Replies.setOnNewReplyReceivedCallback(",
    "Replies.hasChats(",
    "Replies.show(",
    "Replies.setPushNotificationsEnabled(",
    "Replies.setInAppNotificationEnabled(",
    "Replies.setInAppNotificationSound(",
]

# Flutter Feature Requests patterns
FLUTTER_FEATURE_REQUESTS_PATTERNS = [
    "FeatureRequests.setEnabled(",
    "FeatureRequests.show(",
]

# Flutter feature flag methods (use different syntax)
FLUTTER_FEATURE_FLAG_PATTERNS = [
    "Luciq.addFeatureFlags(",
    "Luciq.removeFeatureFlags(",
    "Luciq.clearAllFeatureFlags(",
]

# Flutter module toggle patterns
FLUTTER_MODULE_TOGGLE_PATTERNS = {
    "bug_reporting_enabled": [
        "BugReporting.setEnabled(",
    ],
    "crash_reporting_enabled": [
        "CrashReporting.setEnabled(",
    ],
    "session_replay_enabled": [
        "SessionReplay.setEnabled(",
    ],
    "apm_enabled": [
        "APM.setEnabled(",
    ],
    "network_logs_enabled": [
        "SessionReplay.setNetworkLogsEnabled(",
    ],
    "user_steps_enabled": [
        "SessionReplay.setUserStepsEnabled(",
    ],
    "luciq_logs_enabled": [
        "SessionReplay.setLuciqLogsEnabled(",
    ],
    "surveys_enabled": [
        "Surveys.setEnabled(",
    ],
    "in_app_replies_enabled": [
        "Replies.setEnabled(",
    ],
    "feature_requests_enabled": [
        "FeatureRequests.setEnabled(",
    ],
    "ndk_crashes_enabled": [
        "CrashReporting.setNDKEnabled(",
    ],
}
