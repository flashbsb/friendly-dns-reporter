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
        analytics = report_data.get("analytics", {})
        details = report_data.get("detailed_results", {})
        infra = details.get("infrastructure", {})
        zones = details.get("zones", [])
        records = details.get("records", [])

        def clean(value):
            text = re.sub(r"\x1b\[[0-9;]*m", "", str(value))
            return text

        lines = []
        lines.append("FRIENDLY DNS REPORTER")
        lines.append("=" * 80)
        lines.append(f"Timestamp: {clean(summary.get('timestamp', 'N/A'))}")
        lines.append("")
        lines.append("Executive Summary")
        lines.append("-" * 80)
        lines.append(f"Total queries: {clean(summary.get('total_queries', 0))}")
        lines.append(f"Successful queries: {clean(summary.get('success_queries', 0))}")
        lines.append(f"Divergences: {clean(summary.get('divergences', 0))}")
        lines.append(f"Zone issues: {clean(summary.get('zone_sync_issues', 0))}")
        lines.append(f"Security score: {clean(summary.get('security_score', 'N/A'))}")
        lines.append(f"Privacy score: {clean(summary.get('privacy_score', 'N/A'))}")
        lines.append(f"Global grade: {clean(summary.get('global_grade', 'N/A'))}")
        lines.append(f"Execution time: {clean(summary.get('execution_time_s', 0))}s")
        lines.append("")

        sections = [
            ("Phase 1 Analytics", analytics.get("phase1_infrastructure", {})),
            ("Phase 2 Analytics", analytics.get("phase2_zones", {})),
            ("Phase 3 Analytics", analytics.get("phase3_records", {})),
        ]
        for title, data in sections:
            lines.append(title)
            lines.append("-" * 80)
            if data:
                for key, value in data.items():
                    lines.append(f"{key}: {clean(value)}")
            else:
                lines.append("No analytics available.")
            lines.append("")

        lines.append("Coverage")
        lines.append("-" * 80)
        lines.append(f"Infrastructure rows: {len(infra)}")
        lines.append(f"Zone rows: {len(zones)}")
        lines.append(f"Record rows: {len(records)}")
        lines.append("")

        findings = [r for r in records if r.get("findings")]
        wildcard_hits = len({(r.get("domain"), r.get("server")) for r in records if r.get("wildcard_detected")})
        lines.append("Operational Highlights")
        lines.append("-" * 80)
        lines.append(f"Servers with public recursion: {sum(1 for r in infra.values() if r.get('resolver_exposed') is True)}")
        lines.append(f"Desynchronized domains: {len({z.get('domain') for z in zones if z.get('zone_is_synced') is False})}")
        lines.append(f"Queries with findings: {len(findings)}")
        lines.append(f"Wildcard zone/server pairs: {wildcard_hits}")
        return "\n".join(lines) + "\n"
