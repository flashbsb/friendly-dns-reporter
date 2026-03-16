# Changelog

All notable changes to this project will be documented in this file.

## [6.9.2] - 2026-03-16
### Added
- **Plain Text Report Export**: Added generation of a `.txt` report alongside the existing outputs for copy/paste, ticketing, and offline sharing.
- **Terminal Executive Takeaways**: Added a final action-oriented summary block to highlight public recursion, zone desynchronization, semantic findings, wildcard behavior, and score applicability.
- **Phase Snapshots in Terminal**: Added compact pre-table summaries for Infrastructure, Zones, and Records to improve live execution readability.
- **Progress Activity Context**: Added inline progress context so long-running phases can expose active targets without switching away from single-line progress behavior.
- **Report Coverage Audit Helper**: Added `tools/report_coverage_check.py` to verify key fields in generated JSON reports.

### Changed
- **Version Milestone**: Incremented version to 6.9.2.
- **Measurement Semantics Hardening**:
  - Reworked open-recursion detection to use a recursive third-party request instead of a non-recursive probe.
  - Distinguished `DNSSEC data serving` from `DNSSEC validation` in code, UI, and dashboard help.
  - Limited QNAME minimization scoring to recursive-capable profiles and marked it as heuristic.
  - Propagated RD intent into downstream checks such as chain resolution, wildcard detection, and CAA validation.
- **Consistency and Sync Logic**:
  - Tightened record consistency comparison so relaxed mode no longer hides real IP-set changes.
  - Replaced Phase 2 sync health with a domain-level synchronization metric based on actual zone sync state.
  - Moved wildcard persistence to zone/server semantics instead of attaching it to only the first record row.
- **Terminal UX Refresh**:
  - Added export-safe behavior when stdout is redirected.
  - Reworked summaries to separate phase snapshots, detailed rows, interpretations, and final summary blocks.
  - Simplified progress rendering to keep interactive bars on a single line while preserving plain-text progress when redirected.
- **Dashboard and Help Alignment**:
  - Updated HTML explanations so heuristic signals and direct observations are clearly distinguished.
  - Expanded presentation of zone audit, wildcard, and richer infrastructure context.
- **README Refresh**:
  - Updated CLI usage examples and removed unsupported flags from documentation.
  - Reworked the logic-flow diagram to better match the current pipeline and outputs.
  - Cleaned up encoding issues and aligned version references with the current release.

### Fixed
- **CAA Reporting Contract**: Standardized on `caa_records` across collection, scoring, and reporting.
- **Config/Runtime Drift**: Reconnected settings such as `ONLY_TEST_ACTIVE_GROUPS`, `PING_TIMEOUT`, and `ENABLE_WEB_RISK_CHECK` to active runtime behavior.
- **Zone and Record Output Gaps**: Persisted wildcard results and additional zone audit details into reporting outputs.
- **Dashboard Stability**: Guarded charts and summary cards against empty history and division-by-zero scenarios.
- **Terminal Progress Rendering**: Fixed progress bar artifacts caused by stale inline status text and ensured phase completion clears lingering activity suffixes.

## [6.9.1] - 2026-03-15
### Changed
- **Terminal UI Consolidation**: Eliminated redundant phase headers and legends in terminal output for a cleaner diagnostic flow.
- **Version Polish**: Incremented to 6.9.1 reflecting terminal presentation refinements.

## [6.9.0] - 2026-03-15
### Added
- **Forensic Analysis Console**: Completely redesigned `dashboard.html` with a premium dark-mode UI for technical auditors.
- **Global Forensic Search**: Real-time filtering across all diagnostic phases with keyword highlighting in tables.
- **Incident Radar Strip**: New high-visibility tracker for critical anomalies (Open Resolvers, Lame Delegations, DIV!, Desync).
- **Interactive SVG Trend Charts**: Replaced static charts with lightweight, high-performance SVG line charts for historical tracking.
- **Forensic Table Highlights**: Automatic red highlighting for anomalous rows and integrated finding density displays.
- **Execution Performance Tracking**: Real-time script execution duration now exported to all reporting formats (Terminal, JSON, HTML).

### Changed
- **Version Milestone**: Incremented to 6.9.0 reflecting the UI/UX transformation.
- **Architecture Refinement**: Modularized dashboard JavaScript for improved maintenance and dual-mode data loading.

## [6.8.0] - 2026-03-15
### Added
- **Professional JSON Execution Metadata**: Integrated `metadata` section in `report.json` containing script version, CLI arguments, system information (OS/Python), and runtime configuration.
- **Hierarchical JSON Layout**: Reorganized report structure into `metadata`, `summary`, `analytics`, and `detailed_results` for better automation compatibility.
- **UTF-8 Support in JSON**: Forced `ensure_ascii=False` in the reporting engine to preserve decorative symbols (like ⚠️) in programmatic outputs.

### Changed
- **Version Milestone**: Incremented to 6.8.0 reflecting the reporting engine overhaul.

## [6.7.0] - 2026-03-15
### Added
- **Sarcastic Legal Disclaimer**: Introduced a professional-yet-humorous disclaimer in the terminal, help message, and README to clarify liability and diagnostic limitations.

### Changed
- **Version Milestone**: Incremented to 6.7.0 reflecting the addition of legal and policy documentation.

## [6.6.0] - 2026-03-15
### Added
- **Multi-CSV Analytical Export**:
  - Split the single CSV report into up to 7 specialized files for massive data analysis.
  - New detail files: `details_phase1_infrastructure.csv`, `details_phase2_zones.csv`, `details_phase3_records.csv`.
  - New summary files: `summary_phase1.csv`, `summary_phase2.csv`, `summary_phase3.csv`, `summary_final.csv`.
- **Integrated Technical Glossary**: Added a comprehensive status meaning section to the README for easier auditing.

### Changed
- **Reporting Engine UI**: Updated terminal summary to reflect the new specialized CSV output paths.
- **Data Model Expansion**: Phase functions now return specialized analytical insights for granular reporting.

## [6.5.0] - 2026-03-14
### Added
- **Extended Forensic Legends**:
  - Comprehensive definitions for all technical statuses (SERVFAIL, DIV!, P_ONLY, etc.).
  - Detailed explanation of PING formatting `[R/S % ms]`.
  - Transparent disclosure of scoring weights for Infrastructure and Zone compliance.
  - New Grading System (A+) legend in the final summary.

### Added
- **Triple Double Legend System**:
  - Split technical legends (tables) from analytical legends (summaries) in all phases.
  - Legends are now displayed sequentially: Table -> Technical Legend -> Summary -> Analytics Legend.
  - Improved clarity on forensic scoring criteria and SLA health indices.

### Added
- **Analytical Legends**:
  - Detailed context for Phase Summaries (Infrastructure Health, Zone Compliance, Stability Index).
  - Repositioned legends to appear immediately after analytical summaries for better readability.
  - Explanation of "Finding Density" and "Network Health SLA" criteria.

### Added
- **Granular Forensic Scoring**:
  - **Individual Server Scores (Phase 1)**: Each server now has a 0-100 health score directly in the table.
  - **Individual Zone Scores (Phase 2)**: Each zone-per-server record now displays a compliance score.
  - **Infrastructure Health Index**: Aggregated average of all server health metrics in Phase 1 footer.
  - **Zone Compliance Index**: Aggregated average of all zone integrity metrics in Phase 2 footer.
- **UI Layout Optimization**: Streamlined headers (`U53`, `T53`) to fit new forensic data on standard terminals.

### Added
- **Auditor Intelligence (Advanced Analytics)**:
  - **Protocol Adoption Rate (Phase 1)**: Insights into modern protocol deployment (% DoT, DoH, DNSSEC).
  - **Network Health SLA (Phase 1)**: Statistical comparison of latencies against configured SLAs.
  - **Synchronization Health (Phase 2)**: Percentage-based global consistency tracking per zone.
  - **Stability Index (Phase 3)**: Quantitative measure of result stability (% of non-flapping queries).
  - **Finding Density (Phase 3)**: Average counts of semantic issues per query/domain.
- **Global Executive Grade**: Automated A-F letter grade in the final summary for quick management assessment.
- **Enhanced UI Footers**: Redesigned phase summaries with nested analytical insights.

### Added
- **Privacy & Security Scores**: Integrated a sophisticated scoring engine that evaluates DNS health based on multiple forensic metrics (0-100 score).
- **Advanced Diagnostic "Caps"**: Introduced detection for:
  - **DNS Cookies (RFC 7873)**: Protection against amplification.
  - **QNAME Minimization (RFC 7816)**: Privacy protection.
  - **EDNS Client Subnet (ECS)**: Network performance vs privacy tracking.
- **CAA (Certificate Authority Authorization)**: Automatic check for domain certificate issuance policies in Phase 2.
- **Final Summary Legend**: New descriptive legend explaining the Security/Privacy scoring criteria and consistency metrics.
- **Improved UI Layout**: Compact "Capabilities" column in Phase 1 and updated legend systems.
- **Return-based Architecture**: Data engine now returns structural results, enabling complex post-processing and scoring.

### Changed
- **Major Release**: Project elevated to "Professional Suite" status with advanced forensic depth.
- **Global Table Layout**: Optimized Phase 1 table to fit more technical markers in standard terminal widths.

### Added
- **Forensic Execution Logging**: Introduced a high-detail logging system that records every diagnostic action (probes, queries, findings) for technical forensic analysis.
- **Conditional Logging Trigger**: Added `ENABLE_EXECUTION_LOG` in `settings.ini` to toggle detailed execution logging (Default: `true`).
- **IPv6 Chain Resolution**: Updated the "Dangling DNS" check in the diagnostic engine to support both IPv4 (`A`) and IPv6 (`AAAA`) record verification.
- **Truncated Response Detection**: Added terminal and log warnings for DNS responses with the `TC` (Truncated) bit set, identifying potential MTU/Packet size issues.

### Fixed
- **Empty Log File Issue**: Resolved the bug where an empty log file was created even when no logging occurred.
- **SOA Search Robustness**: Hardened the SOA record extraction logic to handle varied authoritative response formats.
- **Config Type Consistency**: Standardized the `Settings` class to use type-safe helper methods for all `.ini` parameters.
- **Web-Risk Description**: Clarified the Phase 2 legend to accurately describe the "Web-Risk" check as a port exposure scan.

## [5.2.0] - 2026-03-14
### Added
- **UI Legends integration**: Added descriptive legends after Phase 1 (Infrastructure), Phase 2 (Zones), and Phase 3 (Records) to clarify column meanings, values, and color coding.
- **Legend Configuration Toggle**: Introduced `ENABLE_UI_LEGENDS` in `settings.ini` and `Settings` class to allow users to toggle the visibility of terminal legends (Default: `true`).
- **Branding Simplification**: Removed "PYTHON EDITION" from terminal banners and documentation for a cleaner user experience.

### Changed
- **Version Milestone**: Incremented version to 5.2.0 reflecting the addition of interactive terminal documentation features.

## [5.1.0] - 2026-03-14
### Added
- **Colorized Sync Status**: The Phase 3 'Sync' column now displays `OK` in green for immediate visual confirmation of synchronized records.
- **Diagnostics UI Transparency**: Phase 2 now displays the specific DNS error code (e.g., `TIMEOUT`, `REFUSED`, `SERVFAIL`) directly in the SOA Serial column when a query fails, eliminating generic placeholder outputs.
- **Smart Recursion Fallback**: If a Phase 2 query fails with the configured recursion setting (RD bit), the engine automatically falls back to the opposite setting (e.g., iterative fallback for strict authoritative servers).
- **Optional Filename Timestamps**: Added `ENABLE_REPORT_TIMESTAMPS` in `settings.ini` to control whether logs and reports include execution timestamps.

### Fixed
- **Settings Initialization Crashes**: Fixed `AttributeError` tracebacks in Phase 2 by correctly defining the `enable_soa_timer_audit` and `enable_zone_dnssec_check` properties in the `Settings` class (`core/config_loader.py`) and exposing them in `settings.ini`.
- **Phase 2 Column Geometry**: Reordered Phase 2 terminal output layout to `Domain | Group | Server` for a more logical reading flow, aligning with Phase 3 design.
- **Group Context Consistency**: Hardened the Phase 2 worker iterator to ensure that proper group names remain associated with failing servers, resolving instances where errors were labeled as `UNCATEGORIZED`.


## [5.0.0] - 2026-03-14
### Added
- **Deep Service Validation**: Phase 1 now distinguishes between a port being "open" (socket) and the service being "functional" (responding to real DNS queries).
- **Hybrid Status Notation**: New UI indicators: `OK` (Port+Service up), `P_ONLY` (Port up, Service down), `CLOSE` (Port closed).
- **CLI Phase Selection**: Added `-p` / `--phases` argument (e.g., `-p 1,3`) to run specific diagnostic stages.
- **Architecture Circuit Breaker**: Phase 1 results now act as an intelligent gatekeeper for Phase 2 and 3, preventing timeouts on dead services.

### Fixed
- **Phase 2 & 3 Data Stability**: Resolved critical variable scoping and silent error suppression issues that caused missing output in parallel workers.
- **SOA Robust Extraction**: Enhanced DNS engine to extract SOA records from the Authority section for authoritative servers and referrals.
- **UI Cleanliness**: Hidden the "Reports Generated" footer when no reports are actually created, as requested.
- **CSV Robustness**: Further refined field stripping and normalization to prevent key mismatches between diagnostic phases.
- **Infrastructure Context**: Fixed group name mapping in Phase 2 diagnostics by improving `infra_cache` lookup stability.

### Changed
- **Phase 1 UI Reordering**: Reordered columns to `Group | IP Address` for better readability as requested.
- **DNS Engine Expansion**: Added protocol-specific deep probing for UDP, TCP, DoT, and DoH.
- **Settings Sanitization**: Renamed `[DIG_OPTIONS]` to `[DNS_ENGINE]` and variables to `DNS_TIMEOUT`/`DNS_RETRIES` to align with the Python-native architecture.
- **Smart CSV Loader**: Implemented automatic delimiter detection (`;` vs `,`) for custom datasets.
- **Data Consolidation**: Simplified `domains.csv` by removing redundant `STRATEGY` column; logic now uses `TYPE` from `groups.csv`.

## [4.1.0] - 2026-03-14
### Added
- **Phase 3 Performance Visualization**: Latency column is now colorized (Green/Yellow/Red) based on thresholds.
- **Configurable Thresholds**: Added `REC_LATENCY_WARN` and `REC_LATENCY_CRIT` to `settings.ini`.

## [4.0.1] - 2026-03-14
### Fixed
- **SPF/DMARC Grouping**: Corrected logic to detect multiple mail records per domain.

## [4.0.0] - 2026-03-14
### Added
- **Major Milestone: Semantic DNS Audit**: Phase 3 now performs intelligent analysis (SPF/DMARC, Dangling DNS, Port 25, Wildcards, TTL).

## [3.1.2] - 2026-03-14
### Added
- **Project Footer**: Added contribution invitation and repository link.

## [3.1.1] - 2026-03-14
### Changed
- **Phase 3 Layout Refined**: Adjusted column order to `Domain | Group | Server | Type`.

## [3.1.0] - 2026-03-14
### Added
- **Phase 3 Evolution**: Refactored record consistency to collect and sort results before printing.

## [3.0.0] - 2026-03-13
### Added
- **SOA Sync Visualization**: The `SOA Serial` column now displays `OK(SERIAL)` in green if the zone is synchronized across all servers, or `FAIL(SERIAL)` in red if discrepancies are found.

## [2.9.4] - 2026-03-13
### Added
- **Enhanced Zone Audit (Phase 2)**: 
    - Integrated **Lame Delegation** detection by monitoring the Authoritative Answer (`AA`) flag.
    - Added **SOA Query Latency** tracking to identify slow authoritative servers.
    - Implemented **NS Record Consistency** checks across all servers in a group, alerting if a server returns a different set of name servers.
    - Extracted and prepared detailed SOA metadata (MNAME, RNAME) for reporting.

## [2.9.2] - 2026-03-13
### Added
- **Real-time Progress Indicators**: Integrated a dynamic status bar that tracks the completion percentage of parallel threads across all diagnostic phases.
- **Group-based Sorting**: Phase 1 infrastructure results are now automatically sorted alphabetically by Group name.

## [2.9.1] - 2026-03-13
### Optimized
- **OpenResolver Clarity**: Updated status strings (`REFUSED`, `SERVFAIL`, `OPEN`) to avoid false positives.
- **Phase 1 Layout**: Re-introduced the Server `Group` column.
- **Timestamped Reports**: Report filenames now include execution timestamps.

## [2.9.0] - 2026-03-13
### Added
- **Global Latency UI**: Display latency `(xxms)` for all Phase 1 checks.
- **Advanced Infrastructure Checks**: Root DNSSEC, EDNS0, and Amplification testing.
- **Connectivity Dropping Metrics**: Upgraded PING column with packet loss `%`.

## [2.8.2] - 2026-03-13
### Fixed
- **NSID Attribute Support**: Implemented robust attribute access for extracting the NSID in dnspython (checking for both `.nsid` and `.data`), resolving a script-breaking crash `AttributeError: 'NSIDOption' object has no attribute 'data'` on newer dnspython versions.

## [2.8.1] - 2026-03-13
### Added
- **Recursion Query Latency**: Phase 1 now measures and displays the specific response time for UDP Recursion queries directly in the terminal output, mirroring the TCP and ICMP latency visualizations.

## [2.8.0] - 2026-03-13
### Added
- **Auto-dependency resolution**: The script now automatically detects if required Python packages (`urllib3`, `dnspython`, `requests`, `Jinja2`, `icmplib`) are missing and uses `sys.executable` with `pip` to install them silently on both Windows and Linux, eliminating `ModuleNotFoundError` completely.

## [2.7.0] - 2026-03-13
### Added
- **Granular Latency Tracking**: Phase 1 now measures and displays the specific response time for every successful probe (Port 53 TCP, Port 443 TCP, and DNS UDP).
- **Performance Insight**: Both the terminal output and HTML dashboard now show exactly how long each infrastructure component took to respond, rather than just a single ping latency.

## [2.6.1] - 2026-03-13
### Added
- **Group Tracking**: Phase 1 now displays which groups each server belongs to in the terminal and HTML report.

## [2.6.0] - 2026-03-13
### Optimized
- **Scoped Diagnostics**: The script now automatically identifies which DNS groups are being used in `domains.csv`.
- **Performance**: Phase 1 now only tests servers that are actually required for the current run, ignoring unrelated infrastructure in `groups.csv`.

## [2.5.1] - 2026-03-13
### Fixed
- **Terminal UI Headers**: Added clear headers for each diagnostic phase (Infrastructure, Zones, Records) for better readability.
- **Liveness Logic (Bug Fix)**: Fixed issue where disabled DNS checks could result in a false "ALIVE" status for dead servers.
- **UI Alignment**: Fine-tuned column widths in terminal output for a perfect table layout.

## [2.5.0] - 2026-03-13
### Added
- **Infrastructure Expansion**: Added connectivity testing for Port 443 (HTTPS/DoH).
- **Protocol Separation**: Distinguished between Port 53 TCP and Port 53 UDP in terminal and reports.
- **Robust Circuit Breaker**: Refined the "is_dead" logic to include Port 443 results, ensuring maximum diagnostic coverage before skipping a server.

## [2.4.1] - 2026-03-13
### Added
- **Circuit Breaker Logic**: Automatically detect "dead" servers in Phase 1 and skip redundant tests in subsequent phases.
- **Granular Error States**: Now distinguishes between `OPEN`, `CLOSED`, `TIMEOUT`, and `UNREACHABLE` (instead of masking all failures as "closed").
- **Visual Feedback**: Improved UI and Dashboard with specific badges and coloring for network-related failures.

## [2.4.0] - 2026-03-13
### Added
- **3-Phase Diagnostic Logic**: Refactored the core engine to follow the Server-Infrastructure, Zone-Integrity, and Record-Consistency workflow.
- **Enhanced Configuration**: Full support for `settings.ini` variables, including phase toggles and consistency strictness.
- **Advanced Security Checks**: Added AXFR (Zone Transfer) vulnerability testing and EDNS0 (NSID/Cookies) support.
- **Legacy DIG Mapping**: Translated DIG parameters (`TIMEOUT`, `TRIES`) to native Python logic for backward compatibility.
- **Premium Reporting**: Updated HTML dashboard with detailed phase metrics and modern aesthetics.

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
