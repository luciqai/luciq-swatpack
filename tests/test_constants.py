"""
Tests for constants.py - Pattern validation and completeness checks.

These tests verify that all patterns are correctly defined and match
the expected SDK API patterns from docs.luciq.ai
"""

import re
from luciq_swatpack.constants import (
    # Regex patterns
    INVOCATION_EVENT_PATTERN,
    ENDPOINT_PATTERN,
    TOKEN_ENV_PATTERN,
    APP_TOKEN_PATTERN,
    TOKEN_LITERAL_PATTERN,
    TOKEN_IDENTIFIER_PATTERN,
    TOKEN_DECL_PATTERN,
    # iOS patterns
    FEATURE_API_PATTERNS,
    MODULE_DEFAULT_TRUE,
    MODULE_DEFAULT_FALSE,
    MODULE_TOGGLE_PATTERNS,
    CUSTOM_LOG_PATTERNS,
    CUSTOM_DATA_PATTERNS,
    PROGRAMMATIC_INVOCATION_PATTERNS,
    PRIVATE_VIEW_PATTERNS,
    ATTACHMENT_LABELS,
    ATTACHMENT_PERMISSION_MAP,
    IOS_USAGE_DESCRIPTION_KEYS,
    NETWORK_SENSITIVE_HEADERS,
    NETWORK_SENSITIVE_BODY_FIELDS,
    DSYM_SCRIPT_KEYWORDS,
    SHELL_SCRIPT_KEYWORDS,
    # Android patterns
    ANDROID_PERMISSION_KEYS,
    ANDROID_INIT_PATTERNS,
    ANDROID_MODULE_TOGGLE_PATTERNS,
    ANDROID_INVOCATION_EVENTS,
    ANDROID_NETWORK_PATTERNS,
    # React Native patterns
    REACT_NATIVE_INIT_PATTERNS,
    # Flutter patterns
    FLUTTER_INIT_PATTERNS,
    FLUTTER_FEATURE_FLAG_PATTERNS,
)


class TestInvocationEventPattern:
    """Tests for INVOCATION_EVENT_PATTERN regex."""

    def test_matches_shake(self):
        assert INVOCATION_EVENT_PATTERN.search(".shake")

    def test_matches_screenshot(self):
        assert INVOCATION_EVENT_PATTERN.search(".screenshot")

    def test_matches_floating_button(self):
        assert INVOCATION_EVENT_PATTERN.search(".floatingButton")

    def test_matches_two_fingers_swipe_left(self):
        assert INVOCATION_EVENT_PATTERN.search(".twoFingersSwipeLeft")

    def test_matches_two_fingers_swipe(self):
        assert INVOCATION_EVENT_PATTERN.search(".twoFingersSwipe")

    def test_matches_right_edge_pan(self):
        assert INVOCATION_EVENT_PATTERN.search(".rightEdgePan")

    def test_matches_none(self):
        assert INVOCATION_EVENT_PATTERN.search(".none")

    def test_does_not_match_invalid(self):
        assert not INVOCATION_EVENT_PATTERN.search(".invalid")
        assert not INVOCATION_EVENT_PATTERN.search("shake")  # missing dot

    def test_extracts_event_name(self):
        match = INVOCATION_EVENT_PATTERN.search("invocationEvents: [.shake, .screenshot]")
        assert match is not None
        assert match.group(1) == "shake"


class TestEndpointPattern:
    """Tests for ENDPOINT_PATTERN regex - matches Instabug/Luciq API URLs."""

    def test_matches_instabug_api(self):
        assert ENDPOINT_PATTERN.search("https://api.instabug.com/upload")

    def test_matches_luciq_api(self):
        assert ENDPOINT_PATTERN.search("https://api.luciq.ai/upload")

    def test_matches_http(self):
        assert ENDPOINT_PATTERN.search("http://api.instabug.com/test")

    def test_does_not_match_other_domains(self):
        assert not ENDPOINT_PATTERN.search("https://api.google.com/test")


class TestTokenPatterns:
    """Tests for token extraction patterns."""

    def test_token_env_pattern_instabug(self):
        match = TOKEN_ENV_PATTERN.search("INSTABUG_APP_TOKEN=abc123")
        assert match is not None
        assert match.group(2) == "abc123"

    def test_token_env_pattern_luciq(self):
        match = TOKEN_ENV_PATTERN.search("LUCIQ_APP_TOKEN = 'mytoken'")
        assert match is not None
        assert match.group(2) == "mytoken"

    def test_app_token_pattern(self):
        match = APP_TOKEN_PATTERN.search('appToken = "abc123"')
        assert match is not None
        assert match.group(1) == "abc123"

    def test_token_literal_pattern(self):
        match = TOKEN_LITERAL_PATTERN.search('withToken: "my-app-token"')
        assert match is not None
        assert match.group(1) == "my-app-token"

    def test_token_identifier_pattern(self):
        match = TOKEN_IDENTIFIER_PATTERN.search("withToken: AppConstants.token")
        assert match is not None
        assert match.group(1) == "AppConstants"

    def test_token_decl_pattern(self):
        match = TOKEN_DECL_PATTERN.search('let instabugToken = "abc123"')
        assert match is not None
        assert match.group(1) == "instabugToken"
        assert match.group(2) == "abc123"


class TestFeatureApiPatterns:
    """Tests for FEATURE_API_PATTERNS dictionary."""

    def test_contains_add_feature_flag(self):
        assert "Luciq.addFeatureFlag" in FEATURE_API_PATTERNS
        assert FEATURE_API_PATTERNS["Luciq.addFeatureFlag"] == "add_feature_flag"

    def test_contains_swift_syntax(self):
        # Swift uses Luciq.add(featureFlag: ...)
        assert "Luciq.add(featureFlag" in FEATURE_API_PATTERNS

    def test_contains_remove_operations(self):
        assert "Luciq.removeFeatureFlag" in FEATURE_API_PATTERNS
        assert "Luciq.removeFeatureFlags" in FEATURE_API_PATTERNS
        assert "Luciq.removeAllFeatureFlags" in FEATURE_API_PATTERNS

    def test_contains_flutter_clear_variant(self):
        # Flutter uses clearAllFeatureFlags
        assert "Luciq.clearAllFeatureFlags" in FEATURE_API_PATTERNS


class TestModuleDefaults:
    """Tests for MODULE_DEFAULT_TRUE and MODULE_DEFAULT_FALSE sets."""

    def test_bug_reporting_default_true(self):
        assert "bug_reporting_enabled" in MODULE_DEFAULT_TRUE

    def test_crash_reporting_default_true(self):
        assert "crash_reporting_enabled" in MODULE_DEFAULT_TRUE

    def test_session_replay_default_true(self):
        assert "session_replay_enabled" in MODULE_DEFAULT_TRUE

    def test_debug_logs_default_false(self):
        assert "debug_logs_enabled" in MODULE_DEFAULT_FALSE

    def test_sdk_globally_disabled_default_false(self):
        assert "sdk_globally_disabled" in MODULE_DEFAULT_FALSE

    def test_no_overlap_between_defaults(self):
        overlap = MODULE_DEFAULT_TRUE & MODULE_DEFAULT_FALSE
        assert len(overlap) == 0, f"Overlapping modules: {overlap}"


class TestModuleTogglePatterns:
    """Tests for MODULE_TOGGLE_PATTERNS dictionary."""

    def test_has_all_modules(self):
        expected_modules = [
            "bug_reporting_enabled",
            "crash_reporting_enabled",
            "session_replay_enabled",
            "surveys_enabled",
            "feature_requests_enabled",
            "in_app_replies_enabled",
            "in_app_chat_enabled",
            "apm_enabled",
            "network_logs_enabled",
            "user_steps_enabled",
            "oom_monitor_enabled",
            "anr_monitor_enabled",
            "force_restart_enabled",
            "network_auto_masking_enabled",
        ]
        for module in expected_modules:
            assert module in MODULE_TOGGLE_PATTERNS, f"Missing module: {module}"

    def test_bug_reporting_patterns(self):
        patterns = MODULE_TOGGLE_PATTERNS["bug_reporting_enabled"]
        assert any("BugReporting.enabled" in p for p in patterns)
        assert any("LCQBugReporting.enabled" in p for p in patterns)  # ObjC

    def test_crash_reporting_patterns(self):
        patterns = MODULE_TOGGLE_PATTERNS["crash_reporting_enabled"]
        assert any("CrashReporting.enabled" in p for p in patterns)

    def test_anr_monitor_has_app_hang_pattern(self):
        # Modern API uses appHangEnabled
        patterns = MODULE_TOGGLE_PATTERNS["anr_monitor_enabled"]
        assert any("appHangEnabled" in p for p in patterns)


class TestCustomLogPatterns:
    """Tests for CUSTOM_LOG_PATTERNS list."""

    def test_contains_luciq_log(self):
        assert any("Luciq.log(" in p for p in CUSTOM_LOG_PATTERNS)

    def test_contains_lcqlog_patterns(self):
        # Modern Swift API uses LCQLog namespace
        assert any("LCQLog.log(" in p for p in CUSTOM_LOG_PATTERNS)
        assert any("LCQLog.logVerbose(" in p for p in CUSTOM_LOG_PATTERNS)
        assert any("LCQLog.logInfo(" in p for p in CUSTOM_LOG_PATTERNS)
        assert any("LCQLog.logWarn(" in p for p in CUSTOM_LOG_PATTERNS)
        assert any("LCQLog.logError(" in p for p in CUSTOM_LOG_PATTERNS)

    def test_contains_objc_macros(self):
        assert any("LCQLogVerbose(" in p for p in CUSTOM_LOG_PATTERNS)
        assert any("LCQLogInfo(" in p for p in CUSTOM_LOG_PATTERNS)

    def test_contains_user_event_logging(self):
        assert any("logUserEvent" in p for p in CUSTOM_LOG_PATTERNS)


class TestCustomDataPatterns:
    """Tests for CUSTOM_DATA_PATTERNS list."""

    def test_contains_set_custom_data(self):
        assert any("setCustomData" in p for p in CUSTOM_DATA_PATTERNS)

    def test_contains_user_attribute_patterns(self):
        assert any("addUserAttribute" in p for p in CUSTOM_DATA_PATTERNS)
        assert any("setUserAttribute" in p for p in CUSTOM_DATA_PATTERNS)

    def test_contains_user_data_property(self):
        # Swift property syntax: Luciq.userData
        assert any("Luciq.userData" in p for p in CUSTOM_DATA_PATTERNS)


class TestPrivateViewPatterns:
    """Tests for PRIVATE_VIEW_PATTERNS list."""

    def test_contains_correct_swift_pattern(self):
        # Correct pattern is luciq_privateView (with underscore)
        assert any("luciq_privateView" in p for p in PRIVATE_VIEW_PATTERNS)

    def test_contains_objc_pattern(self):
        assert any("luciq_setPrivateView" in p for p in PRIVATE_VIEW_PATTERNS)


class TestProgrammaticInvocationPatterns:
    """Tests for PROGRAMMATIC_INVOCATION_PATTERNS list."""

    def test_contains_luciq_show(self):
        assert any("Luciq.show(" in p for p in PROGRAMMATIC_INVOCATION_PATTERNS)

    def test_contains_luciq_invoke(self):
        assert any("Luciq.invoke(" in p for p in PROGRAMMATIC_INVOCATION_PATTERNS)

    def test_contains_bug_reporting_show(self):
        assert any("BugReporting.show(" in p for p in PROGRAMMATIC_INVOCATION_PATTERNS)


class TestIOSPermissions:
    """Tests for iOS permission constants."""

    def test_usage_description_keys(self):
        assert "NSCameraUsageDescription" in IOS_USAGE_DESCRIPTION_KEYS
        assert "NSMicrophoneUsageDescription" in IOS_USAGE_DESCRIPTION_KEYS
        assert "NSPhotoLibraryUsageDescription" in IOS_USAGE_DESCRIPTION_KEYS

    def test_attachment_labels(self):
        assert "screenshot" in ATTACHMENT_LABELS
        assert "gallery_image" in ATTACHMENT_LABELS
        assert "voice_note" in ATTACHMENT_LABELS

    def test_attachment_permission_map(self):
        assert ATTACHMENT_PERMISSION_MAP["gallery_image"] == "photo_library"
        assert ATTACHMENT_PERMISSION_MAP["voice_note"] == "microphone"


class TestNetworkSensitiveFields:
    """Tests for network privacy constants."""

    def test_sensitive_headers(self):
        assert "Authorization" in NETWORK_SENSITIVE_HEADERS
        assert "Cookie" in NETWORK_SENSITIVE_HEADERS
        assert "X-API-Key" in NETWORK_SENSITIVE_HEADERS

    def test_sensitive_body_fields(self):
        assert "password" in NETWORK_SENSITIVE_BODY_FIELDS
        assert "token" in NETWORK_SENSITIVE_BODY_FIELDS
        assert "email" in NETWORK_SENSITIVE_BODY_FIELDS


class TestDsymScriptKeywords:
    """Tests for dSYM upload detection keywords."""

    def test_contains_upload_symbols(self):
        assert "upload_symbols" in DSYM_SCRIPT_KEYWORDS
        assert "upload-symbols" in DSYM_SCRIPT_KEYWORDS

    def test_contains_luciq_script(self):
        assert "Luciq_dsym_upload.sh" in DSYM_SCRIPT_KEYWORDS

    def test_shell_script_keywords(self):
        assert "dsym" in SHELL_SCRIPT_KEYWORDS
        assert "upload" in SHELL_SCRIPT_KEYWORDS


# =============================================================================
# ANDROID PATTERN TESTS
# =============================================================================


class TestAndroidPatterns:
    """Tests for Android-specific patterns."""

    def test_permission_keys(self):
        assert "android.permission.INTERNET" in ANDROID_PERMISSION_KEYS
        assert "android.permission.RECORD_AUDIO" in ANDROID_PERMISSION_KEYS
        assert "android.permission.POST_NOTIFICATIONS" in ANDROID_PERMISSION_KEYS

    def test_init_patterns(self):
        assert any("Luciq.Builder(" in p for p in ANDROID_INIT_PATTERNS)
        assert any("new Luciq.Builder(" in p for p in ANDROID_INIT_PATTERNS)

    def test_invocation_events(self):
        assert "LuciqInvocationEvent.SHAKE" in ANDROID_INVOCATION_EVENTS
        assert "LuciqInvocationEvent.FLOATING_BUTTON" in ANDROID_INVOCATION_EVENTS
        assert "LuciqInvocationEvent.SCREENSHOT" in ANDROID_INVOCATION_EVENTS
        assert "LuciqInvocationEvent.NONE" in ANDROID_INVOCATION_EVENTS

    def test_module_toggle_patterns(self):
        assert "bug_reporting_enabled" in ANDROID_MODULE_TOGGLE_PATTERNS
        assert "crash_reporting_enabled" in ANDROID_MODULE_TOGGLE_PATTERNS
        assert "session_replay_enabled" in ANDROID_MODULE_TOGGLE_PATTERNS
        assert "ndk_crashes_enabled" in ANDROID_MODULE_TOGGLE_PATTERNS

    def test_network_patterns(self):
        assert any("LuciqNetworkLog" in p for p in ANDROID_NETWORK_PATTERNS)
        assert any("LuciqOkhttpInterceptor" in p for p in ANDROID_NETWORK_PATTERNS)


# =============================================================================
# REACT NATIVE PATTERN TESTS
# =============================================================================


class TestReactNativePatterns:
    """Tests for React Native-specific patterns."""

    def test_init_patterns(self):
        assert any("Luciq.init(" in p for p in REACT_NATIVE_INIT_PATTERNS)
        assert any("@luciq/react-native" in p for p in REACT_NATIVE_INIT_PATTERNS)

    def test_invocation_events(self):
        assert any("InvocationEvent.shake" in p for p in REACT_NATIVE_INIT_PATTERNS)
        assert any("InvocationEvent.screenshot" in p for p in REACT_NATIVE_INIT_PATTERNS)


# =============================================================================
# FLUTTER PATTERN TESTS
# =============================================================================


class TestFlutterPatterns:
    """Tests for Flutter-specific patterns."""

    def test_init_patterns(self):
        assert any("luciq_flutter" in p for p in FLUTTER_INIT_PATTERNS)
        assert any("package:luciq_flutter" in p for p in FLUTTER_INIT_PATTERNS)
        assert any("Luciq.init(" in p for p in FLUTTER_INIT_PATTERNS)

    def test_feature_flag_patterns(self):
        assert any("addFeatureFlags(" in p for p in FLUTTER_FEATURE_FLAG_PATTERNS)
        assert any("removeFeatureFlags(" in p for p in FLUTTER_FEATURE_FLAG_PATTERNS)
        assert any("clearAllFeatureFlags(" in p for p in FLUTTER_FEATURE_FLAG_PATTERNS)


# =============================================================================
# CROSS-PLATFORM COMPLETENESS TESTS
# =============================================================================


class TestCrossPlatformCompleteness:
    """Tests to verify pattern completeness across platforms."""

    def test_all_ios_modules_have_toggle_patterns(self):
        """Every module in defaults should have toggle patterns."""
        all_modules = MODULE_DEFAULT_TRUE | MODULE_DEFAULT_FALSE
        # Exclude sdk_globally_disabled and debug_logs as they're meta-settings
        modules_needing_toggles = all_modules - {"sdk_globally_disabled", "debug_logs_enabled"}
        for module in modules_needing_toggles:
            assert module in MODULE_TOGGLE_PATTERNS, f"Module {module} has no toggle patterns"

    def test_android_has_core_modules(self):
        """Android should have patterns for core modules."""
        core_modules = [
            "bug_reporting_enabled",
            "crash_reporting_enabled",
            "session_replay_enabled",
        ]
        for module in core_modules:
            assert module in ANDROID_MODULE_TOGGLE_PATTERNS, f"Android missing {module}"

    def test_no_duplicate_patterns_in_lists(self):
        """Pattern lists should not have duplicates."""
        for name, patterns in [
            ("CUSTOM_LOG_PATTERNS", CUSTOM_LOG_PATTERNS),
            ("CUSTOM_DATA_PATTERNS", CUSTOM_DATA_PATTERNS),
            ("PRIVATE_VIEW_PATTERNS", PRIVATE_VIEW_PATTERNS),
            ("PROGRAMMATIC_INVOCATION_PATTERNS", PROGRAMMATIC_INVOCATION_PATTERNS),
            ("ANDROID_INIT_PATTERNS", ANDROID_INIT_PATTERNS),
            ("ANDROID_INVOCATION_EVENTS", ANDROID_INVOCATION_EVENTS),
            ("REACT_NATIVE_INIT_PATTERNS", REACT_NATIVE_INIT_PATTERNS),
            ("FLUTTER_INIT_PATTERNS", FLUTTER_INIT_PATTERNS),
        ]:
            assert len(patterns) == len(set(patterns)), f"Duplicates in {name}"
