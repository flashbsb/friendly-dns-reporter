import json
import csv
from jinja2 import Environment, FileSystemLoader
import os
import re

class Reporter:
    def __init__(self, output_dir="logs"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def export_json(self, data, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        # Update index
        if not filename.startswith("reports_index"):
            self.update_index(filename)
            
        return path

    def update_index(self, new_report):
        index_path = os.path.join(self.output_dir, "reports_index.json")
        index = {"reports": []}
        
        if os.path.exists(index_path):
            try:
                with open(index_path, 'r', encoding='utf-8') as f:
                    index = json.load(f)
            except:
                pass
        
        if new_report not in index["reports"]:
            index["reports"].append(new_report)
            # Keep latest reports first for the dashboard selector default.
            index["reports"].sort(reverse=True)
            
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(index, f, indent=4)

    def export_csv(self, data, filename, fieldnames):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerows(data)
        return path

    def export_text(self, report_data, filename):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self._build_text_report(report_data))
        return path

    def generate_html(self, context, filename, template_name="dashboard.html"):
        path = os.path.join(self.output_dir, filename)
        
        # Setup Jinja2 environment to load from core/templates
        base_dir = os.path.dirname(os.path.dirname(__file__))
        template_dir = os.path.join(base_dir, 'core', 'templates')
        
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template(template_name)
        
        html_content = template.render(context)
            
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return path

    def _build_text_report(self, report_data):
        summary = report_data.get("summary", {})
        metadata = report_data.get("metadata", {})
        analytics = report_data.get("analytics", {})
        details = report_data.get("detailed_results", {})
        infra = details.get("infrastructure", {})
        zones = details.get("zones", [])
        records = details.get("records", [])

        def clean(value):
            text = re.sub(r"\x1b\[[0-9;]*m", "", str(value))
            return text

        def add_section(title, rows=None):
            lines.append(title)
            lines.append("-" * 80)
            if rows:
                lines.extend(rows)
            else:
                lines.append("No data available.")
            lines.append("")

        def fmt_bool(value):
            if value is True:
                return "YES"
            if value is False:
                return "NO"
            if value is None:
                return "N/E"
            return clean(value)

        def fmt_latency(value):
            if value is None or value == "":
                return "N/A"
            return f"{clean(value)}ms"

        def fmt_probe_evidence(item, probe_name, label=None):
            label = label or probe_name
            protocol = item.get(f"{probe_name}_protocol")
            rcode = item.get(f"{probe_name}_rcode")
            flags = item.get(f"{probe_name}_flags") or []
            query_size = item.get(f"{probe_name}_query_size")
            response_size = item.get(f"{probe_name}_response_size")
            authority_count = item.get(f"{probe_name}_authority_count")
            answer_count = item.get(f"{probe_name}_answer_count")
            aa = item.get(f"{probe_name}_aa")
            tc = item.get(f"{probe_name}_tc")
            http_status = item.get(f"{probe_name}_http_status")
            ra = item.get(f"{probe_name}_ra")

            details = []
            if protocol:
                details.append(f"proto={clean(protocol)}")
            if rcode:
                details.append(f"rcode={clean(rcode)}")
            if flags:
                details.append(f"flags={clean(','.join(map(str, flags[:4])))}")
            if query_size is not None:
                details.append(f"q={clean(query_size)}B")
            if response_size is not None:
                details.append(f"r={clean(response_size)}B")
            if authority_count is not None:
                details.append(f"auth={clean(authority_count)}")
            if answer_count is not None:
                details.append(f"answers={clean(answer_count)}")
            if aa is not None:
                details.append(f"aa={'Y' if aa else 'N'}")
            if tc is not None:
                details.append(f"tc={'Y' if tc else 'N'}")
            if http_status is not None:
                details.append(f"http={clean(http_status)}")
            if ra is not None:
                details.append(f"ra={'Y' if ra else 'N'}")
            if not details:
                return f"{label}=N/A"
            return f"{label}=" + ",".join(details)

        def fmt_probe_repeat(item, probe_name, label=None):
            label = label or probe_name
            sample_count = item.get(f"{probe_name}_sample_count", 0) or 0
            if sample_count <= 0:
                return f"{label}=N/E"
            avg_latency = fmt_latency(item.get(f"{probe_name}_latency_avg"))
            min_latency = fmt_latency(item.get(f"{probe_name}_latency_min"))
            max_latency = fmt_latency(item.get(f"{probe_name}_latency_max"))
            jitter = fmt_latency(item.get(f"{probe_name}_latency_jitter"))
            stable = item.get(f"{probe_name}_status_consistent")
            stable_str = "stable" if stable is True else ("flap" if stable is False else "n/e")
            return f"{label}={sample_count}x {stable_str} [{min_latency}/{avg_latency}/{max_latency}] j={jitter}"

        lines = ["FRIENDLY DNS REPORTER", "=" * 80]
        add_section("Metadata", [
            f"Version: {clean(metadata.get('version', 'N/A'))}",
            f"Timestamp: {clean(summary.get('timestamp', metadata.get('timestamp', 'N/A')))}",
            f"Domains CSV: {clean(metadata.get('arguments', {}).get('domains', 'N/A'))}",
            f"Groups CSV: {clean(metadata.get('arguments', {}).get('groups', 'N/A'))}",
            f"Output directory: {clean(metadata.get('config', {}).get('output_directory', 'N/A'))}",
            f"Platform: {clean(metadata.get('system_info', {}).get('os', 'N/A'))} {clean(metadata.get('system_info', {}).get('os_release', ''))}".rstrip(),
            f"Python: {clean(metadata.get('system_info', {}).get('python_version', 'N/A'))}",
        ])

        add_section("Executive Summary", [
            f"Total queries: {clean(summary.get('total_queries', 0))}",
            f"Successful queries: {clean(summary.get('success_queries', 0))}",
            f"Divergences: {clean(summary.get('divergences', 0))}",
            f"Zone issues: {clean(summary.get('zone_sync_issues', 0))}",
            f"Security score: {clean(summary.get('security_score', 'N/A'))}",
            f"Privacy score: {clean(summary.get('privacy_score', 'N/A'))}",
            f"Global grade: {clean(summary.get('global_grade', 'N/A'))}",
            f"Execution time: {clean(summary.get('execution_time_s', 0))}s",
        ])

        phase_sections = [
            ("Phase 1 Analytics", analytics.get("phase1_infrastructure", {})),
            ("Phase 2 Analytics", analytics.get("phase2_zones", {})),
            ("Phase 3 Analytics", analytics.get("phase3_records", {})),
        ]
        for title, data in phase_sections:
            add_section(title, [f"{key}: {clean(value)}" for key, value in data.items()])

        add_section("Coverage", [
            f"Infrastructure rows: {len(infra)}",
            f"Zone rows: {len(zones)}",
            f"Record rows: {len(records)}",
        ])

        findings = [r for r in records if r.get("findings")]
        wildcard_hits = len({(r.get("domain"), r.get("server")) for r in records if r.get("wildcard_detected")})

        add_section("Operational Highlights", [
            f"Servers with public recursion: {sum(1 for r in infra.values() if r.get('resolver_exposed') is True)}",
            f"Desynchronized domains: {len({z.get('domain') for z in zones if z.get('zone_is_synced') is False})}",
            f"Queries with findings: {len(findings)}",
            f"Wildcard zone/server pairs: {wildcard_hits}",
        ])

        infra_rows = []
        for server, item in sorted(infra.items()):
            infra_rows.append(
                " | ".join([
                    f"Server={server}",
                    f"Groups={clean(item.get('groups', 'N/A'))}",
                    f"Profile={clean(item.get('server_profile', 'unknown'))}",
                    f"Alive={fmt_bool(not item.get('is_dead', False))}",
                    f"Ping={clean(item.get('ping', 'N/A'))}",
                    f"PingAvg={fmt_latency(item.get('latency'))}",
                    f"PingMin={fmt_latency(item.get('latency_min'))}",
                    f"PingMax={fmt_latency(item.get('latency_max'))}",
                    f"UDP53={fmt_latency(item.get('udp53_probe_lat'))}",
                    f"Score={clean(item.get('infrastructure_score', 'N/A'))}",
                    f"Resolver={clean(item.get('classification', item.get('open_resolver', 'N/A')))}",
                    f"DoT={clean(item.get('dot', 'N/A'))}",
                    f"DoH={clean(item.get('doh', 'N/A'))}",
                    f"WebRisk={','.join(map(str, item.get('web_risks', []))) if item.get('web_risks') else 'none'}",
                    f"Coverage={clean(item.get('probe_coverage_ratio', 'N/A'))}%",
                ])
            )
            infra_rows.append(
                "  Timings: " + " | ".join([
                    f"TCP53-Conn={fmt_latency(item.get('port53t_conn_lat'))}",
                    f"TCP53-Probe={fmt_latency(item.get('port53t_probe_lat'))}",
                    f"Version={fmt_latency(item.get('version_lat'))}",
                    f"Recursion={fmt_latency(item.get('recursion_lat'))}",
                    f"DoT-Conn={fmt_latency(item.get('port853_conn_lat'))}",
                    f"DoT-Probe={fmt_latency(item.get('dot_lat'))}",
                    f"DoH-Conn={fmt_latency(item.get('port443_conn_lat'))}",
                    f"DoH-Probe={fmt_latency(item.get('doh_lat'))}",
                    f"DNSSEC={fmt_latency(item.get('dnssec_lat'))}",
                    f"EDNS0={fmt_latency(item.get('edns0_lat'))}",
                    f"ECS={fmt_latency(item.get('ecs_lat'))}",
                    f"QNAME={fmt_latency(item.get('qname_min_lat'))}",
                    f"Cookies={fmt_latency(item.get('cookies_lat'))}",
                    f"WebRisk={fmt_latency(item.get('web_risk_lat'))}",
                    f"OpenResolver={fmt_latency(item.get('open_resolver_lat'))}",
                    f"ProbeAvg={fmt_latency(item.get('probe_latency_avg'))}",
                ])
            )
            infra_rows.append(
                "  Observability: " + " | ".join([
                    f"UDP53={clean(item.get('udp53_probe_timing_source', 'N/A'))}/{clean(item.get('udp53_probe_failure_reason', 'N/A'))}",
                    f"TCP53={clean(item.get('tcp53_probe_timing_source', 'N/A'))}/{clean(item.get('tcp53_probe_failure_reason', 'N/A'))}",
                    f"ECS={clean(item.get('ecs_timing_source', 'N/A'))}/{clean(item.get('ecs_failure_reason', 'N/A'))}",
                    f"QNAME={clean(item.get('qname_min_timing_source', 'N/A'))}/{clean(item.get('qname_min_failure_reason', 'N/A'))}",
                    f"Cookies={clean(item.get('cookies_timing_source', 'N/A'))}/{clean(item.get('cookies_failure_reason', 'N/A'))}",
                    f"Web80={clean(item.get('web_risk_status', {}).get(80, 'N/A'))}",
                    f"Web443={clean(item.get('web_risk_status', {}).get(443, 'N/A'))}",
                ])
            )
            infra_rows.append(
                "  Evidence: " + " | ".join([
                    fmt_probe_evidence(item, "version", "Version"),
                    fmt_probe_evidence(item, "recursion", "Recursion"),
                    fmt_probe_evidence(item, "dnssec", "DNSSEC"),
                    fmt_probe_evidence(item, "edns0", "EDNS0"),
                    fmt_probe_evidence(item, "open_resolver", "OpenRes"),
                    fmt_probe_evidence(item, "doh_probe", "DoH"),
                ])
            )
            infra_rows.append(
                "  Repeatability: " + " | ".join([
                    fmt_probe_repeat(item, "udp53_probe", "UDP53"),
                    fmt_probe_repeat(item, "tcp53_probe", "TCP53"),
                    fmt_probe_repeat(item, "dot_probe", "DoT"),
                    fmt_probe_repeat(item, "doh_probe", "DoH"),
                    fmt_probe_repeat(item, "open_resolver", "OpenRes"),
                ])
            )
        add_section("Phase 1 Details", infra_rows)

        zone_rows = []
        for item in sorted(zones, key=lambda z: (z.get("domain", ""), z.get("server", ""))):
            audit = item.get("zone_audit", {})
            zone_rows.append(
                " | ".join([
                    f"Domain={clean(item.get('domain', 'N/A'))}",
                    f"Server={clean(item.get('server', 'N/A'))}",
                    f"Group={clean(item.get('group', 'N/A'))}",
                    f"Status={clean(item.get('status', 'N/A'))}",
                    f"Latency={fmt_latency(item.get('latency'))}",
                    f"Scope={clean(item.get('check_scope', 'N/A'))}",
                    f"Serial={clean(item.get('serial', 'N/A'))}",
                    f"Synced={fmt_bool(item.get('zone_is_synced'))}",
                    f"AA={fmt_bool(item.get('aa'))}",
                    f"AXFR={clean(item.get('axfr_detail', 'N/A'))}",
                    f"DNSSEC={fmt_bool(item.get('dnssec'))}",
                    f"CAA={len(item.get('caa_records', []))}",
                    f"NS Consistent={fmt_bool(item.get('ns_consistent'))}",
                    f"MNAME Reachable={clean(audit.get('mname_reachable', 'N/A'))}",
                ])
            )
            zone_rows.append(
                "  Timings: " + " | ".join([
                    f"SOA={fmt_latency(item.get('soa_latency'))}",
                    f"SOA-Fallback={fmt_latency(item.get('soa_fallback_latency'))}",
                    f"NS={fmt_latency(item.get('ns_latency'))}",
                    f"AXFR={fmt_latency(item.get('axfr_latency'))}",
                    f"CAA={fmt_latency(item.get('caa_latency'))}",
                    f"Zone-DNSSEC={fmt_latency(item.get('zone_dnssec_latency'))}",
                ])
            )
            zone_rows.append(
                "  Scope: " + " | ".join([
                    f"Confidence={clean(item.get('scope_confidence', 'N/A'))}",
                    f"Fallback={'YES' if item.get('used_fallback') else 'NO'}",
                ])
            )
            zone_rows.append(
                "  Evidence: " + " | ".join([
                    fmt_probe_evidence(item, "soa", "SOA"),
                    fmt_probe_evidence(item, "ns", "NS"),
                    fmt_probe_evidence(item, "caa", "CAA"),
                    fmt_probe_evidence(item, "zone_dnssec", "ZoneDNSSEC"),
                ])
            )
            zone_rows.append(
                "  Repeatability: " + " | ".join([
                    fmt_probe_repeat(item, "soa", "SOA"),
                    fmt_probe_repeat(item, "ns", "NS"),
                ])
            )
            if audit.get("timers_issues"):
                zone_rows.append(f"  Timers issues: {clean('; '.join(audit['timers_issues']))}")
        add_section("Phase 2 Details", zone_rows)

        record_rows = []
        for item in sorted(records, key=lambda r: (r.get("domain", ""), r.get("server", ""), r.get("type", ""))):
            record_rows.append(
                " | ".join([
                    f"Domain={clean(item.get('domain', 'N/A'))}",
                    f"Server={clean(item.get('server', 'N/A'))}",
                    f"Group={clean(item.get('group', 'N/A'))}",
                    f"Type={clean(item.get('type', 'N/A'))}",
                    f"Status={clean(item.get('status', 'N/A'))}",
                    f"Latency={fmt_latency(item.get('latency'))}",
                    f"First={fmt_latency(item.get('latency_first'))}",
                    f"Avg={fmt_latency(item.get('latency_avg'))}",
                    f"Min={fmt_latency(item.get('latency_min'))}",
                    f"Max={fmt_latency(item.get('latency_max'))}",
                    f"Consistent={clean(item.get('internally_consistent', 'N/A'))}",
                    f"Wildcard={fmt_bool(item.get('wildcard_detected'))}",
                    f"Answers={clean(item.get('answers', ''))}",
                ])
            )
            record_rows.append(
                "  Timings: " + " | ".join([
                    f"Chain={fmt_latency(item.get('chain_latency'))}",
                    f"MX25={fmt_latency(item.get('mx_port25_latency'))}",
                    f"Wildcard={fmt_latency(item.get('wildcard_latency'))}",
                ])
            )
            if item.get("findings"):
                for finding in item["findings"]:
                    record_rows.append(f"  Finding: {clean(finding)}")
            if item.get("wildcard_answers"):
                record_rows.append(f"  Wildcard answers: {clean(' | '.join(item['wildcard_answers']))}")
        add_section("Phase 3 Details", record_rows)

        return "\n".join(lines) + "\n"
