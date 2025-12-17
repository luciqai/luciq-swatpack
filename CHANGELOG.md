# Changelog

All notable changes to luciq-swatpack will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-17

### Added

#### Android Support (Kotlin/Java)
- Full Android project scanning with Gradle dependency detection
- SDK initialization detection (`Luciq.Builder`, invocation events)
- Network logging patterns:
  - OkHttp interceptors (`LuciqOkhttpInterceptor`, `LuciqAPMOkhttpInterceptor`)
  - gRPC interceptor (`LuciqAPMGrpcInterceptor`)
  - Network log listeners and callbacks
- APM (Application Performance Monitoring):
  - Flow tracking (`APM.startFlow`, `APM.endFlow`, `APM.setFlowAttribute`)
  - Screen loading (`APM.startScreenLoading`, `APM.endScreenLoading`)
  - UI traces, Fragment spans, Compose spans
  - WebView tracking (`APM.setWebViewsTrackingEnabled`)
  - UI hang detection, auto UI trace
- Bug Reporting patterns:
  - Screen recording, shaking threshold
  - Extended bug reports, report types
  - Proactive reporting, view hierarchy
- Session Replay detection:
  - State control, network logs, sync callbacks
  - Kotlin lambda syntax support
- Crash Reporting:
  - Non-fatal exception reporting (`LuciqNonFatalException`)
  - User identification state
- Masking patterns:
  - Screenshot auto-masking (`MaskingType.MEDIA`, `MaskingType.LABELS`, etc.)
  - Network auto-masking (`Luciq.setNetworkAutoMaskingState`)

#### React Native Support (JavaScript/TypeScript)
- Full JS/TS file scanning (`.js`, `.jsx`, `.ts`, `.tsx`)
- SDK detection via `@luciq/react-native` package
- All module support:
  - APM (flows, traces, screen loading, app launch)
  - BugReporting (invocation events, report types, attachments, proactive reporting)
  - CrashReporting (error reporting, NDK crashes)
  - SessionReplay (masking, network logs, user steps)
  - NetworkLogger (obfuscation handlers, request filters)
  - Surveys, Replies, FeatureRequests
- Module toggle state detection
- Token extraction and validation

#### Flutter Support (Dart)
- Full Dart file scanning (`.dart`)
- SDK detection via `luciq_flutter` in pubspec.yaml
- All module support:
  - APM (flows, traces, screen loading, route wrapping)
  - BugReporting (invocation events, report types, user consents)
  - CrashReporting (handled crashes, NDK support, non-fatal levels)
  - SessionReplay (network logs, user steps, Luciq logs)
  - Surveys, Replies, FeatureRequests
- Feature flags detection (`addFeatureFlags`, `removeFeatureFlags`, `clearAllFeatureFlags`)
- Module toggle state detection

#### Enhanced iOS Support
- WebView tracking patterns (`WKWebViewConfiguration` extensions)
- WebView masking detection
- APM lifecycle patterns (cold/hot/warm launch)
- Non-fatal crash reporting patterns
- User consent patterns
- Welcome message customization
- Network obfuscation handler detection
- Screenshot capture patterns

#### Testing & Quality
- Expanded test suite from ~50 to 210 tests
- Comprehensive schema compliance tests for all platforms
- Platform-specific test fixtures

### Changed
- Platform detection now prioritizes cross-platform frameworks (React Native, Flutter) over native
- Improved pattern matching for Kotlin lambda syntax
- Enhanced module state inference with platform-specific defaults

### Fixed
- Session Replay sync callback detection for Kotlin lambda syntax
- Schema validation for new APM module states

## [0.1.3] - 2025-12-05

### Changed
- Improved SDK detection and usage documentation
- Version bump for PyPI release

## [0.1.2] - 2025-11-26

### Fixed
- Fixed `tool_version` metadata in reports

## [0.1.1] - 2025-11-24

### Added
- Initial release
- iOS platform support (Swift/Objective-C)
- Build system detection: SPM, CocoaPods, Carthage, manual embed
- SDK version extraction from lockfiles
- Usage pattern detection (init, invocation events, module toggles)
- Privacy-first design: no source code capture, only metadata
- JSON output with schema validation
- Markdown report generation
- CLI with dry-run and manifest-only modes
