"""
UI and Terminal Formatting for FriendlyDNSReporter.
"""

# ANSI Palette
RESET = "\033[0m"
OK     = "\033[92m"  # Green
FAIL   = "\033[91m"  # Red
WARN   = "\033[93m"  # Yellow
INFO   = "\033[96m"  # Cyan
BOLD   = "\033[1m"

def print_banner():
    print("\n" + "=" * 80)
    print(f"{BOLD}FRIENDLY DNS REPORTER - PYTHON EDITION{RESET}")
    print("=" * 80)

def print_header(threads, consistency, target):
    print(f"Threads: {threads} | Consistency: {consistency}x | Dataset: {target}")
    print("-" * 80)

def print_phase(name):
    print(f"{INFO}PHASE {name}{RESET}\n")

def print_summary_table(total, success, fail, div, sync_issues, reports):
    print("\n" + "=" * 80)
    print(f"{BOLD}FINAL DIAGNOSTIC SUMMARY{RESET}")
    print("=" * 80)
    print(f"  Total Queries   : {total}")
    print(f"  Successful (OK) : {OK}{success}{RESET}")
    print(f"  Failures (ERR)  : {(FAIL if fail > 0 else OK)}{fail}{RESET}")
    print(f"  Divergences (DIV): {(WARN if div > 0 else OK)}{div}{RESET}")
    print(f"  SOA Sync Issues : {(FAIL if sync_issues > 0 else OK)}{sync_issues}{RESET}")
    print("-" * 80)
    print(f"  Reports Generated:")
    for label, path in reports.items():
        print(f"  {INFO}{label:5}:{RESET} {path}")
    print("=" * 80 + "\n")

def print_interrupt():
    print("\n\n" + "!" * 80)
    print(f" {FAIL}INTERRUPTED: User cancellation requested.{RESET}")
    print(" Terminating pending threads... please wait.")
    print("!" * 80 + "\n")

def format_result(group, target, server, rtype, status, latency, is_consistent):
    status_clr = OK if status == "NOERROR" else FAIL
    consistency_str = f" [{WARN}DIV!{RESET}]" if not is_consistent else ""
    return f"[{INFO}{group:10}{RESET}] {target:25} -> {server:15} | {rtype:5} | {status_clr}{status:8}{RESET} | {latency:4.1f}ms{consistency_str}"
