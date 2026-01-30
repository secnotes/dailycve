#!/usr/bin/env python3
"""
Test script to verify CVE collection functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from collector import CVECollector
from reporter import generate_html_report
from config import Config
import os

def test_cve_collection():
    print("Testing CVE collection functionality...")

    # Create necessary directories
    os.makedirs('reports', exist_ok=True)
    os.makedirs(Config.get_current_year_report_dir(), exist_ok=True)

    # Initialize collector
    collector = CVECollector()

    # Test collection with a smaller timeframe to reduce API load during testing
    print("Collecting recent CVEs (testing mode)...")
    cves = collector.collect_daily_cves(days=1)

    print(f"Collected {len(cves)} high-risk CVEs")

    # Display the first few CVEs for verification
    for i, cve in enumerate(cves[:3]):  # Show first 3
        print(f"\nCVE #{i+1}: {cve['id']}")
        print(f"  CVSS Score: {cve.get('cvss_score', 'Unknown')}")
        print(f"  EPSS Score: {cve.get('epss_score', 'Unknown')}")
        print(f"  In CISA KEV: {cve.get('in_cisa_kev', False)}")
        print(f"  Description: {cve['description'][:100]}...")

    # Generate test reports
    if cves:
        print("\nGenerating test reports...")
        generate_html_report(cves, 'test_report.html')
        print("Test reports generated: test_report.html")
    else:
        print("No high-risk CVEs found for the test period.")

    return cves

if __name__ == "__main__":
    collected_cves = test_cve_collection()
    print(f"\nTest completed. Collected {len(collected_cves)} high-risk CVEs.")