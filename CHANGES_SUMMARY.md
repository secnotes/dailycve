# Daily CVE Collection System - Updated

This project has been successfully modified to meet the new requirements:

## Key Changes Made:

1. **CVE Source Update**:
   - Removed NVD and GitHub advisory sources
   - Implemented CVE collection from CVEProject/cvelistV5
   - Downloads daily delta ZIP files from GitHub releases

2. **Download and Archive**:
   - Downloads the "CVE YYYY-MM-DD at End of Day" delta ZIP files
   - Processes ZIP files in memory without saving to disk
   - No longer saves ZIP files to reduce storage usage

3. **Data Processing**:
   - Parses JSON files from the ZIP archive
   - Extracts vendor and product information from CVE JSON schema
   - Filters for high-risk vulnerabilities based on CVSS, CISA KEV, and EPSS scores

4. **Corrected Entry Type Classification**:
   - Fixed "Newly Published" vs "Recently Modified" classification logic
   - "Newly Published": CVEs published on the target date
   - "Recently Modified": CVEs published earlier but modified on the target date

5. **UI Changes**:
   - Removed product information from the HTML report sidebar
   - Kept only vendor filtering functionality
   - Updated UI to reflect the improved vendor data from CVE v5 format

6. **Report Generation Changes**:
   - Added markdown report generation functionality
   - Markdown reports saved to `docs/reports/YYYY/daily_cve_YYYYMMDD.md` format
   - HTML reports still generated as secondary step
   - Markdown reports include top vendors table and detailed CVE listings

7. **Removed Components**:
   - Eliminated unused import references in code

## Current Status:

- ✅ Collects CVE data from CVEProject/cvelistV5
- ✅ Processes ZIP files in memory without saving to disk
- ✅ Generates both Markdown and HTML reports
- ✅ Saves markdown reports in docs/reports/YYYY/daily_cve_YYYYMMDD.md format
- ✅ Shows vendor filtering (without product breakdown)
- ✅ Correctly classifies "Newly Published" vs "Recently Modified" CVEs
- ✅ Follows the updated requirements

The system is working as intended and will generate a markdown report followed by an HTML report containing all high-risk vulnerabilities from the previous day's CVE data.