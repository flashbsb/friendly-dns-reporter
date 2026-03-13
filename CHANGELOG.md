# Changelog

All notable changes to this project will be documented in this file.

## [2.3.0] - 2026-03-13
### Added
- **Full Feature Parity**: Restored logic for `SLEEP` (rate-limiting) and diagnostic toggles from the original Bash version.
- **Configurable Connectivity**: `PING_COUNT` and various `ENABLE_*_CHECK` flags now fully control the diagnostic engine.
- **Improved Reliability**: Better protection against firewall rate-limiting and redundant query filtering.

## [2.2.1] - 2026-03-13
### Fixed
- **Sync Logic**: Resolved issue where synchronization was reported as [OK] even when all queries failed.

## [2.2.0] - 2026-03-13
### Added
- **Architectural Refinement**: Decoupled script into specialized modules (`core/ui.py`, `core/config_loader.py`).
- **Professional Logging**: Integrated structured logging infrastructure.
- **Clean Code Improvements**: Improved modularity and typed settings access.
