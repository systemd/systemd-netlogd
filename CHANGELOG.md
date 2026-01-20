# Changelog

All notable changes to systemd-netlogd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test suite with cmocka framework (7 unit tests)
- GitHub Actions CI for automated testing
- Documentation improvements (CONTRIBUTING.md, ARCHITECTURE.md, TESTING.md, FAQ.md)
- Example configurations in examples/ directory
- Enhanced man page with detailed protocol and configuration examples

### Changed
- Refactored TLS/DTLS code to eliminate ~220 lines of duplication
- Split netlog-manager.c into focused modules (journal, state, manager)
- Broke down long functions (>50 lines) into focused helpers
- Updated RPM spec file with proper systemd integration

### Fixed
- Improved error handling in journal processing
- Fixed state file permissions and ownership

## [1.4.0] - 2020-01-15

### Added
- Support for RFC 5425 (TLS transport for syslog)
- DTLS support for secure datagram transport
- Configurable syslog facility and level filtering
- State persistence for journal cursor

### Changed
- Improved network connectivity monitoring
- Enhanced SSL certificate verification

## [1.3.0] - 2019-06-20

### Added
- Support for journal namespaces
- Structured data support (RFC 5424)
- Configurable message ID

### Changed
- Improved configuration file parsing
- Better error messages and logging

## [1.2.0] - 2018-11-10

### Added
- TLS support for encrypted log transmission
- Certificate authentication modes (deny/warn/allow)

### Changed
- Improved network reconnection logic
- Enhanced rate limiting

## [1.1.0] - 2018-05-15

### Added
- Support for RFC 5424 syslog format
- TCP transport support
- Configuration file support

### Changed
- Improved memory management
- Better journal integration

## [1.0.0] - 2017-12-01

### Added
- Initial release
- UDP transport for syslog messages
- RFC 3339 timestamp format
- systemd journal integration
- Multicast support

[Unreleased]: https://github.com/systemd/systemd-netlogd/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/systemd/systemd-netlogd/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/systemd/systemd-netlogd/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/systemd/systemd-netlogd/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/systemd/systemd-netlogd/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/systemd/systemd-netlogd/releases/tag/v1.0.0
