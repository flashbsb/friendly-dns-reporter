# FriendlyDNSReporter
> *Because it is always DNS. Or not. But mostly yes.*

[![Python](https://img.shields.io/badge/Language-Python-3776AB.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Stable_(v6.9.2)-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

Does your boss ask for "evidence" that DNS is broken?
Do you enjoy typing `dig` 5,000 times a day?
Do you like staring at raw text output until your eyes bleed?

**No?** Then `FriendlyDNSReporter` is for you.

This tool provides parallel DNS diagnostics for **Windows** and **Linux**, with terminal summaries, structured reports, and an HTML dashboard.

## Features

* **Operational Console (v6.9.2)**: Improved terminal snapshots, inline progress, executive takeaways, and export-safe output.
* **Plain Text Report Export (v6.9.2)**: Generates a `.txt` report for tickets, copy/paste, and offline review.
* **Forensic Analysis Console (v6.9.0)**: HTML dashboard with search, incident focus, interpretation help, and trend charts.
* **Professional JSON Reporting (v6.8.0)**: Hierarchical output with execution metadata and system info for automation.
* **Extended Forensic Legends**: Definitions for status markers, metrics, and scoring.
* **Granular Forensic Scoring**: Individual infrastructure and zone health scores.
* **Selective Diagnostics**: Run only the phases you need with `-p`.
* **3-Phase Circuit Breaker**: Dead or unreachable services can be skipped in later phases.
* **Semantic DNS Audit**: Dangling DNS, wildcard detection, SPF/DMARC heuristics, TTL review, and MX checks.

## Logic Flow

```mermaid
graph TD
    Start((Start)) --> Config["Load settings.ini"]
    Config --> Data["Load domains.csv and groups.csv"]
    Data --> Select{"Phase selection (-p) or defaults"}

    Select --> P1
    Select --> P2
    Select --> P3

    subgraph "Phase 1 - Infrastructure"
        P1["Reachability and service probes"] --> P1A["Ping, UDP/TCP 53, DoT, DoH"]
        P1A --> P1B["Capability and exposure checks"]
        P1B --> P1C["Profile-aware infrastructure score"]
    end

    subgraph "Phase 2 - Zones"
        P2["Zone integrity checks"] --> P2A["SOA, serial, AA, AXFR, DNSSEC, CAA"]
        P2A --> P2B{"SOA available?"}
        P2B -->|Yes| P2C["Full zone analysis"]
        P2B -->|No| P2D["SOA_ONLY / shortened scope"]
        P2C --> P2E["Zone score and synchronization analysis"]
        P2D --> P2E
    end

    subgraph "Phase 3 - Records"
        P3["Repeated record queries"] --> P3A["Consistency checks across A / AAAA / MX / TXT / etc."]
        P3A --> P3B["Semantic audit: dangling DNS, SPF/DMARC, TTL, wildcard"]
        P3B --> P3C["Record findings and divergence metrics"]
    end

    P1C --> Summary
    P2E --> Summary
    P3C --> Summary

    Summary["Aggregate security, privacy, and execution summaries"] --> ReportGen["Generate reports and terminal output"]

    subgraph "Outputs"
        ReportGen --> JSON["JSON report"]
        ReportGen --> HTML["HTML dashboard"]
        ReportGen --> TXT["Plain text report"]
        ReportGen --> CSV["Optional CSV exports"]
        ReportGen --> TERM["Terminal snapshots and executive takeaways"]
    end

    TERM --> End((End))
    JSON --> End
    HTML --> End
    TXT --> End
    CSV --> End
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/flashbsb/FriendlyDNSReporter.git
cd FriendlyDNSReporter
```

2. Run the script:
```bash
python friendly_dns_reporter.py
```

The script currently attempts to install missing dependencies automatically on first run.

## Usage

### Basic Execution

```bash
python friendly_dns_reporter.py
```

### Advanced Examples

```bash
# Run only Phase 1 (Infrastructure) and Phase 3 (Records)
python friendly_dns_reporter.py -p 1,3

# Use custom datasets
python friendly_dns_reporter.py -n my_domains.csv -g my_groups.csv

# Save reports to a custom output directory
python friendly_dns_reporter.py -o reports

# Run only the Zone phase
python friendly_dns_reporter.py -p 2
```

### Command Flags

| Flag | Description |
|------|-------------|
| `-p` | Select phases to run (for example `1`, `1,3`, `2`). Default: all enabled phases. |
| `-n` | Path to the domains CSV. Default: `config/domains.csv`. |
| `-g` | Path to the groups CSV. Default: `config/groups.csv`. |
| `-o` | Output directory for generated reports. |
| `-h` | Show command help. |

Parallelism, consistency count, timeouts, scoring options, and feature toggles are configured in `config/settings.ini`.

## Configuration

The `config/settings.ini` file centralizes runtime behavior:

- `ENABLE_PHASE_*`: toggle Infrastructure, Zone, or Record phases.
- `MAX_THREADS`: parallelism limit.
- `DNS_TIMEOUT` / `DNS_RETRIES`: DNS engine behavior.
- `STRICT_*_CHECK`: record consistency tolerance for IPs, order, and TTL.
- `ENABLE_*_REPORT`: control JSON, HTML, CSV, and related outputs.

## Reports

The tool can generate:

- `JSON`: full structured report used by the dashboard.
- `HTML`: interactive forensic dashboard.
- `TXT`: plain text summary for copy/paste and attachments.
- `CSV`: optional phase detail and summary exports.

## Technical Glossary

| Status | Phase | Meaning |
|--------|-------|---------|
| `OK` | All | Service or check completed successfully. |
| `P_ONLY` | 1 | Port is open, but the DNS service did not behave like a healthy responder. |
| `DIV!` | 3 | Repeated checks returned materially different answers. |
| `LAME` | 2 | The server is expected to be authoritative but did not behave authoritatively. |
| `XFR-OK` | 2 | AXFR was allowed, which may expose the zone. |
| `REFUSED` / `NO_RECURSION` | 1 | Recursion appears restricted rather than publicly exposed. |
| `OPEN` | 1 | The server answered a third-party recursive request and may be publicly exposed. |

## Input Files

The loader automatically detects `;`, `,`, and tab-delimited CSV input.

### `config/groups.csv`

```csv
# NAME;DESCRIPTION;TYPE;TIMEOUT;SERVERS
GOOGLE;Google Public DNS;recursive;2;8.8.8.8,8.8.4.4
OPENDNS;Cisco OpenDNS;recursive;3;208.67.222.222,208.67.220.220
```

The `TYPE` column is used to decide whether recursion should be requested for that group.

### `config/domains.csv`

```csv
# DOMAIN;GROUPS;RECORDS;EXTRA
google.com;GOOGLE,CLOUDFLARE;A,AAAA,TXT;www,mail
wikipedia.org;QUAD9,OPENDNS;A,SOA;
```

## Contributing

Found a bug or want to improve the diagnostics? Pull requests are welcome.

## License

MIT. Use it as you wish, just do not blame the tool if your DNS misbehaves.

## Legal Disclaimer

This script is like a horoscope for your DNS: based on facts, interpreted by algorithms, and subject to the mood of the network gods. By running it, you accept that:

1. **Responsibility? Zero.** If your DNS explodes, your internet vanishes, or your cat learns COBOL because of this script, it is on you.
2. **The Journey is Dark.** The script analyzes what it receives but cannot know who interfered with the path.
3. **Scores are just numbers.** They are guidance, not absolute truth.
4. **Technological hallucinations happen.** Results are a snapshot in time.
5. **Use at your own risk.** DNS is still DNS.
