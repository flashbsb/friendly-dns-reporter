#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
FRIENDLY DNS REPORTER - PYTHON EDITION
=============================================================================
Version: 2.3.0
Author: flashbsb
Description: Automated DNS diagnostics for Windows and Linux.
=============================================================================
"""

import argparse
import sys
import os
import csv
import concurrent.futures
import threading
import urllib3
import logging
from datetime import datetime

from core.dns_engine import DNSEngine
from core.connectivity import Connectivity
from core.reporting import Reporter
from core.config_loader import Settings
import core.ui as ui

# Silence DoH/DoT HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup Logging
def setup_logging(log_dir):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"friendly_dns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout) # Keep terminal output
        ]
    )
    # Silence third-party logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return log_file

def check_dependencies():
    """Verify required libraries."""
    required = {"dns": "dnspython", "requests": "requests", "jinja2": "jinja2", "icmplib": "icmplib"}
    missing = [pkg for mod, pkg in required.items() if not __import__(mod, fromlist=[''])]
    if missing:
        print(f"\nERROR: Missing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)

def load_datasets(domains_path, groups_path):
    """Load and normalize CSV datasets."""
    def _read_csv(path):
        if not os.path.exists(path): return []
        with open(path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f, delimiter=';')
            reader.fieldnames = [fn.lstrip('#').strip().upper() for fn in reader.fieldnames] if reader.fieldnames else []
            return [{k.lstrip('#').strip().upper(): v for k, v in row.items() if k} for row in reader if any(row.values()) and not any(str(v).startswith('#') for v in row.values())]

    groups = _read_csv(groups_path)
    domains = _read_csv(domains_path)
    return domains, {g['NAME']: g['SERVERS'].split(',') for g in groups if g.get('NAME') and g.get('SERVERS')}

def run_diagnostic(target, group_name, server, record_types, dns_engine, conn, args, settings, results, lock):
    """Worker task for parallel execution with Feature Parity logic."""
    server = server.strip()
    if not server: return
    
    # Infrastructure Checks
    ping_res = {"is_alive": False}
    if settings.enable_ping:
        ping_res = conn.ping(server, count=settings.ping_count)
    
    port53 = conn.check_port(server, 53)
    
    # Optional Advanced Checks based on settings
    version = dns_engine.query_version(server) if settings.check_bind_version else "DISABLED"
    is_recursive = dns_engine.check_recursion(server) if settings.enable_recursion_check else False
    
    # Feature capabilities (always useful to know if we are testing)
    is_dnssec = dns_engine.check_dnssec(server, target) if settings.enable_dnssec_check else False
    supports_dot = dns_engine.check_dot(server) if settings.enable_dot_check else False
    supports_doh = dns_engine.check_doh(server) if settings.enable_doh_check else False
    
    local_results = []
    for rtype in record_types:
        rtype = rtype.strip().upper()
        if not rtype: continue
        
        queries = []
        for i in range(args.consistency):
            # Rate-limiting / Anti-Flood SLEEP
            if i > 0 and settings.sleep_time > 0:
                import time
                time.sleep(settings.sleep_time)
                
            res = dns_engine.query(server, target, rtype)
            queries.append(res)
            
        is_consistent = all(tuple(q['answers']) == tuple(queries[0]['answers']) for q in queries)
        main_q = queries[0]
        
        entry = {
            "domain": target, "group": group_name, "server": server, "type": rtype,
            "status": main_q['status'], "latency": main_q['latency'],
            "ping": "OK" if ping_res.get('is_alive') else "FAIL",
            "port53": "OPEN" if port53 else "CLOSED",
            "version": version, "recursion": "OPEN" if is_recursive else "CLOSED",
            "dnssec": "VALIDATING" if is_dnssec else "NO",
            "dot": "YES" if supports_dot else "NO", "doh": "YES" if supports_doh else "NO",
            "internally_consistent": "YES" if is_consistent else "DIV!",
            "answers": ", ".join(main_q['answers'])
        }
        local_results.append(entry)
        
        # Real-time UI report
        with lock:
            print(ui.format_result(group_name, target, server, rtype, main_q['status'], main_q['latency'], is_consistent))

    with lock:
        results.extend(local_results)

def main():
    check_dependencies()
    settings = Settings()
    
    parser = argparse.ArgumentParser(description="FriendlyDNSReporter - Professional Suite")
    parser.add_argument("-n", "--domains", default=os.path.join("config", "domains.csv"), help="Domains CSV")
    parser.add_argument("-g", "--groups", default=os.path.join("config", "groups.csv"), help="Groups CSV")
    parser.add_argument("-o", "--output", default=settings.log_dir, help="Output DIR")
    parser.add_argument("-c", "--consistency", type=int, default=settings.consistency_checks, help="Checks count")
    parser.add_argument("-t", "--threads", type=int, default=settings.max_threads, help="Threads count")
    args = parser.parse_args()
    
    # setup_logging(args.output) # Optional: if we want a formal log file
    
    ui.print_banner()
    ui.print_header(args.threads, args.consistency, os.path.basename(args.domains))
    
    domains_raw, dns_groups = load_datasets(args.domains, args.groups)
    if not domains_raw or not dns_groups:
        print(f"[{ui.FAIL}ERROR{ui.RESET}] Datasets missing or empty in 'config/' folder.")
        sys.exit(1)

    # Build task list
    tasks = []
    for entry in domains_raw:
        domain = entry.get('DOMAIN')
        if not domain: continue
        targets = [domain] + [f"{h.strip()}.{domain}" for h in (entry.get('EXTRA') or '').split(',') if h.strip()]
        for target in targets:
            for group in (entry.get('GROUPS') or '').split(','):
                group = group.strip()
                for server in dns_groups.get(group, []):
                    tasks.append((target, group, server, (entry.get('RECORDS') or '').split(',')))

    dns_engine = DNSEngine(timeout=settings.timeout)
    conn = Connectivity(timeout=settings.timeout)
    results, lock = [], threading.Lock()

    ui.print_phase("1: Distributed Diagnostics")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(run_diagnostic, *t, dns_engine, conn, args, settings, results, lock) for t in tasks]
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        ui.print_interrupt()
        sys.exit(130)

    # Phase 2: SOA Sync
    ui.print_phase("2: Synchronization & Serials")
    sync_issues = 0
    soa_success_count = 0
    soa_map = {}
    
    for r in results:
        if r['type'] == "SOA":
            if r['status'] == "NOERROR":
                soa_success_count += 1
                key = (r['domain'], r['group'])
                soa_map.setdefault(key, {})[r['server']] = r['answers'].split(', ')[0].split(' ')[2] if ' ' in r['answers'] else "?"

    if soa_success_count == 0:
        print(f"    [{ui.WARN}SKIPPED{ui.RESET}] No SOA data was retrieved for synchronization check.")
    else:
        for (domain, group), serials in soa_map.items():
            if len(set(serials.values())) > 1:
                sync_issues += 1
                print(f"    [{ui.FAIL}SYNC ERROR{ui.RESET}] SOA out of sync for {ui.BOLD}{domain}{ui.RESET} (Group: {ui.INFO}{group}{ui.RESET})")

        if sync_issues == 0:
            print(f"    {ui.OK}[OK] All server groups are internally synchronized.{ui.RESET}")

    # Export & Summary
    reporter = Reporter(args.output)
    paths = {
        "JSON": reporter.export_json(results, "report.json"),
        "CSV": reporter.export_csv(results, "report.csv", list(results[0].keys()) if results else []),
        "HTML": reporter.generate_html({"results": results}, "dashboard.html")
    }
    
    total = len(results)
    success = sum(1 for r in results if r['status'] == "NOERROR")
    div = sum(1 for r in results if r['internally_consistent'] == "DIV!")
    ui.print_summary_table(total, success, total-success, div, sync_issues, paths)

if __name__ == "__main__":
    main()
