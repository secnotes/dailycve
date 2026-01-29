import os
from datetime import datetime
from collector import CVECollector
from reporter import generate_html_report, generate_markdown_report
from config import Config

def main():
    # Create necessary directories
    os.makedirs('docs', exist_ok=True)
    os.makedirs('docs/reports', exist_ok=True)
    os.makedirs(Config.get_current_year_report_dir(), exist_ok=True)

    # Initialize collector
    collector = CVECollector()

    # Collect daily CVEs
    cves = collector.collect_daily_cves(days=Config.LOOKBACK_DAYS)

    # Generate HTML report
    generate_html_report(cves, Config.REPORT_HTML_PATH)

    # Generate markdown report for archiving
    md_filename = Config.get_markdown_report_path()
    generate_markdown_report(cves, md_filename)

    print(f"Daily CVE collection completed!")
    print(f"Found {len(cves)} high-risk vulnerabilities")
    print(f"HTML report saved as {Config.REPORT_HTML_PATH}")
    print(f"Markdown archive saved as {md_filename}")

if __name__ == "__main__":
    main()