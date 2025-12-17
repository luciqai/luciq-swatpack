# luciq-swatpack

`luciq-swatpack` is a deterministic, privacy-conscious CLI that generates SWAT Pack diagnostics snapshots for Luciq Support/SE workflows. It runs entirely on the customer's machine, never uploads data, and only records approved metadata (paths, versions, line numbers) so customers can confidently share the outputs with Luciq.

## Supported Platforms

| Platform | Languages | Status |
|----------|-----------|--------|
| iOS | Swift, Objective-C | ✅ Full Support |
| Android | Kotlin, Java | ✅ Full Support |
| React Native | JavaScript, TypeScript | ✅ Full Support |
| Flutter | Dart | ✅ Full Support |

## Quick Start

```bash
# Install from PyPI
pip install luciq-swatpack

# Scan any project (auto-detects platform)
luciq-swatpack scan /path/to/your/app

# View results
cat luciq_swatpack_out/luciq_swatpack_report.md
```

## Installation

### From PyPI (Recommended)

```bash
python3 -m pip install luciq-swatpack
luciq-swatpack --version
```

### From Source

```bash
git clone https://github.com/luciqai/luciq-swatpack.git
cd luciq-swatpack
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Basic scan (auto-detects platform)
luciq-swatpack scan /path/to/repo

# Scan current directory
luciq-swatpack scan

# Preview what will be scanned (no files written)
luciq-swatpack scan --dry-run

# Include CI/CD configuration files
luciq-swatpack scan --include-ci-hints

# Custom output directory
luciq-swatpack scan --output-dir ./my_output

# Restrict to specific files
luciq-swatpack scan --files-allowlist "**/*.swift"

# Show extractor documentation
luciq-swatpack scan --explain
```

## Output Files

The tool generates three files in the output directory (default: `./luciq_swatpack_out/`):

1. **`luciq_swatpack.json`** – Machine-readable snapshot validated against schema v0.1
2. **`luciq_swatpack_report.md`** – Human-friendly summary with recommendations
3. **`luciq_swatpack.log`** – Timestamped runtime log for auditing

## Privacy Guarantees

- **Privacy first**: No source code, UI text, screenshots, tokens, or PII are ever persisted
- **Transparency**: Every run prints a capture manifest showing exactly which files will be read
- **Deterministic**: Outputs are stable for the same repo (only `run_id` changes)
- **Local only**: Zero network requests—customers decide when/if to share artifacts

## What Gets Detected

### All Platforms
- SDK installation and version detection
- Module states (Bug Reporting, Crash Reporting, APM, Session Replay, etc.)
- Invocation events (shake, screenshot, floating button)
- User identification and logout hooks
- Feature flags usage
- Custom logging and user attributes
- Token analysis (masked, never raw)

### iOS Specific
- Build systems: SPM, CocoaPods, Carthage, manual embed
- dSYM upload configuration
- Privacy view modifiers (SwiftUI/UIKit)
- Network obfuscation handlers
- WebView tracking configuration

### Android Specific
- Gradle dependency detection
- OkHttp/gRPC interceptors
- APM: flows, traces, screen loading, UI hang detection
- Masking: screenshot types, network auto-masking
- NDK crash reporting
- ProGuard/R8 mapping configuration

### React Native Specific
- Package.json dependency detection
- NetworkLogger configuration
- Source map upload hints
- CodePush/Expo detection

### Flutter Specific
- pubspec.yaml dependency detection
- Route wrapping for APM
- NDK plugin detection

## Example Report Sections

The markdown report includes:

- **SDK Status**: Installation method, version, integration health
- **Module States**: Which features are enabled/disabled
- **Privacy Posture**: Masking configuration, network obfuscation
- **Usage Locations**: File:line references for key API calls
- **Extra Findings**: Warnings and recommendations
- **Next Steps**: Actionable items for optimization

## Development

```bash
# Run tests
pytest

# Run with verbose output
pytest -v

# Test specific platform
pytest tests/test_analysis.py -k "Android"
pytest tests/test_analysis.py -k "ReactNative"
pytest tests/test_analysis.py -k "Flutter"
```

### Test Coverage

- 210 tests covering all platforms
- Schema compliance validation
- Deterministic output verification
- Guard-rail messaging

## Fixtures

The `fixtures/` directory contains test projects:
- `spm_only/` - iOS with Swift Package Manager
- `pods_only/` - iOS with CocoaPods
- `mixed_spm_pods/` - iOS with multiple package managers
- `android_kotlin/` - Android Kotlin project
- `react_native/` - React Native project
- `flutter_app/` - Flutter project

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No Info.plist found" | Check the scan path or use `--files-allowlist` |
| "No Swift/Kotlin sources" | Verify project structure or adjust allowlist |
| Platform misdetected | Check for conflicting dependency files |
| Large scan time | Use `--files-allowlist` to restrict scope |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Links

- [PyPI Package](https://pypi.org/project/luciq-swatpack/)
- [GitHub Repository](https://github.com/luciqai/luciq-swatpack)
- [Changelog](CHANGELOG.md)
