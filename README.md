# CVE Daily

Automated daily CVE monitoring system that aggregates high-risk vulnerabilities from multiple public sources and generates human-readable reports.

## Features

- Fetches latest CVEs from NVD, GitHub advisories, and other public sources
- Filters high-risk vulnerabilities based on:
  - CVSS score > 7.0
  - Presence in CISA KEV (Known Exploited Vulnerabilities) List
  - EPSS score > 0.10
- Uses AI to enhance vulnerability descriptions for readability
- Generates daily HTML reports
- Archives historical reports in Markdown format by year/month
- Automated daily updates via GitHub Actions

## Structure

- `src/`: Main application code
- `reports/`: Archived reports organized by year/month
- `actions/`: GitHub Actions workflow files
- `data/`: Temporary data storage during processing

## Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run locally: `python src/main.py`

## License

MIT