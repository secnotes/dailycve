# Daily CVE Collection System - Updated

This project has been successfully modified to meet the new requirements:

## Key Changes Made:

1. **CVE Source Update**:
   - Removed NVD and GitHub advisory sources
   - Implemented CVE collection from CVEProject/cvelistV5
   - Downloads daily delta ZIP files from GitHub releases

2. **Download and Archive**:
   - Downloads the "CVE YYYY-MM-DD at End of Day" delta ZIP files
   - Saves ZIP files to `docs/json/YYYY/MM/` directory structure
   - Properly archives historical data

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

6. **Removed Components**:
   - Eliminated markdown report generation (only HTML reports remain)
   - Removed unused import references in code

## Current Status:

- ✅ Collects CVE data from CVEProject/cvelistV5
- ✅ Downloads and archives ZIP files properly
- ✅ Generates HTML reports only
- ✅ Shows vendor filtering (without product breakdown)
- ✅ Correctly classifies "Newly Published" vs "Recently Modified" CVEs
- ✅ Follows the updated requirements

The system is working as intended and will generate a report.html file containing all high-risk vulnerabilities from the previous day's CVE data.