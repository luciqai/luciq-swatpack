# Luciq SWAT Pack Report

## Run Metadata
- Timestamp (UTC): 2025-11-24T15:37:12+00:00
- Run ID: 683b1d2b-35cc-4442-afd0-ee0fb25ca61f
- Tool version: 0.1.0
- Schema version: 0.1
- Scan root: /Users/<redacted>/faresdev/swat-ios/SwatSampleApp
- Typer version: 0.20.0
- CLI arguments:
  - path: /Users/faresnabil/faresdev/swat-ios/SwatSampleApp
  - platform: ios
  - dry_run: False
  - explain: False
  - include_ci_hints: True
  - output_dir: examples/swat_sample_output
  - files_allowlist: []

## Project Identity
- App name: $(PRODUCT_NAME)
- Bundle ID: $(PRODUCT_BUNDLE_IDENTIFIER)
- Build systems detected: manual
- Xcode projects:
  - SwatSampleApp.xcodeproj
- Xcode workspaces:
  - SwatSampleApp.xcodeproj/project.xcworkspace
- Deployment targets: 16.0
- Swift versions: 5.0

## Luciq SDK
- Luciq installed: True
- Integration method: manual
- Versions detected: unknown
- Sources: manual_detection

## Luciq Usage
- Luciq.start found: True
  - init locations:
    - SwatSampleApp/SwatSampleAppApp.swift:12
    - SwatSampleApp/SwatSampleAppApp.swift:23
- Invocation events: floatingButton, screenshot, shake
- Network logging: True
- Network masking: True
- Screenshot masking: True
- Repro steps configured: True
- identify hooks: True
- logout hooks: True

## Module States
- Bug Reporting Enabled: unknown
- Crash Reporting Enabled: unknown
- Anr Monitor Enabled: unknown
- Session Replay Enabled: unknown
- Apm Enabled: unknown
- Network Logs Enabled: unknown
- User Steps Enabled: unknown
- Sdk Globally Disabled: unknown
- Debug Logs Enabled: unknown
- Ndk Module Present: unknown
- React Native Integration Detected: unknown
- Flutter Integration Detected: unknown

## Privacy & Masking
- Auto-masking calls: none
- Private view tags found: False
- Compose masking modifiers: False
- Network masking rules: True

## Token Analysis
- Tokens observed: none
- Multiple tokens detected: False
- Placeholder token detected: False

## Symbolication
- dSYM upload detected: True
- dSYM locations:
  - SwatSampleApp/Vendor/LuciqSDK.xcframework/ios-arm64/dSYMs/LuciqSDK.framework.dSYM
  - SwatSampleApp/Vendor/LuciqSDK.xcframework/ios-arm64_x86_64-simulator/dSYMs/LuciqSDK.framework.dSYM
  - SwatSampleApp/Vendor/LuciqSDK.xcframework/tvos-arm64/dSYMs/LuciqSDK.framework.dSYM
  - SwatSampleApp/Vendor/LuciqSDK.xcframework/tvos-arm64_x86_64-simulator/dSYMs/LuciqSDK.framework.dSYM
- Mapping/sourcemap detected: False

## CI Hints
- CI systems detected: none

## Environment
- macos version: 15.6.1
- xcode version: Xcode 26.1.1
Build version 17B100
- swift version: Apple Swift version 6.2.1 (swiftlang-6.2.1.4.8 clang-1700.4.4.1)
Target: arm64-apple-macosx15.0
- cocoapods version: unavailable
- carthage version: unavailable

## Symbol Pipeline
- iOS:
  - Scripts: none
  - Endpoints: none
  - Tokens: none
  - Issues:
    - No Luciq/Instabug dSYM upload script detected in Xcode project.
- Android:
  - Mapping tasks: none
  - Endpoints: none
  - Tokens: none
- React Native:
  - Dependencies: none
  - Env flags: none
  - Sourcemap paths: none

## Privacy Disclosure
- Files read:
  - SwatSampleApp.xcodeproj/project.pbxproj
  - SwatSampleApp/DetailsView.swift
  - SwatSampleApp/DiagnosticsHubView.swift
  - SwatSampleApp/DiagnosticsService.swift
  - SwatSampleApp/HomeView.swift
  - SwatSampleApp/Info.plist
  - SwatSampleApp/InputDemoView.swift
  - SwatSampleApp/LoginView.swift
  - SwatSampleApp/MediaShowcaseView.swift
  - SwatSampleApp/NetworkService.swift
  - SwatSampleApp/ScenarioPlaygroundView.swift
  - SwatSampleApp/SessionStore.swift
  - SwatSampleApp/SwatSampleAppApp.swift
- Fields captured:
  - Run metadata (versions, timestamps, UUID run id)
  - Project identity (app/bundle names, project/workspace paths)
  - Build systems & dependency metadata (lockfiles + xcframework references)
  - Luciq SDK presence, versions, and usage file+line numbers
  - Symbolication + CI hints (paths only)
  - Environment toolchain versions (macOS/Xcode/Swift/CocoaPods/Carthage)
  - Privacy disclosure metadata (files read, fields captured/excluded)
- Fields NOT captured:
  - Source code contents
  - UI strings, screenshots, or assets
  - Secrets/tokens/API keys
  - Email addresses, user IDs, or other PII
  - Network traffic or uploads of any kind
