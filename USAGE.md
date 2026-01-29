# CVE Daily - Automated CVE Monitoring System

This project implements an automated system to collect, filter, and report high-risk CVEs (Common Vulnerabilities and Exposures) on a daily basis.

## Overview

CVE Daily is a security intelligence tool that:
- Aggregates CVE data from public sources (NVD, GitHub Advisories)
- Filters vulnerabilities based on risk indicators (CVSS, EPSS, CISA KEV)
- Generates daily HTML reports for immediate consumption
- Archives historical data in Markdown format organized by year
- Automatically updates via GitHub Actions

## Architecture

### Data Sources
1. **NVD (National Vulnerability Database)**: Primary source for CVE details
2. **CISA KEV (Known Exploited Vulnerabilities)**: List of actively exploited vulnerabilities
3. **EPSS (Exploit Prediction Scoring System)**: Probability of exploitation
4. **GitHub Security Advisories**: Additional vulnerability intelligence

### Risk Classification
A CVE is classified as "high-risk" if it meets ANY of these criteria:
- CVSS score > 7.0 (High/Critical severity)
- Listed in CISA KEV catalog
- EPSS score > 0.10 (10%+ probability of exploitation)

### Components

#### 1. Collector (`src/collector.py`)
- Fetches CVE data from NVD API (both newly published and recently modified CVEs)
- Downloads CISA KEV list
- Retrieves EPSS scores
- Extracts vendor/product information from CVE configurations or by keyword analysis
- Filters high-risk vulnerabilities
- Optional AI enhancement of vulnerability descriptions

#### 2. Reporter (`src/reporter.py`)
- Generates styled HTML reports with rich information and modern UI
- Creates archival Markdown documents
- Formats data for readability
- Includes vulnerability metrics (CVSS, EPSS, CISA KEV status)
- Provides direct links to NVD, MITRE, and EPSS for each CVE
- Distinguishes between newly published and recently modified CVEs
- Features interactive filtering system with dual-panel layout
- Optimized sidebar with scrollable vendor filter list and Show More functionality
- Implements advanced composite filtering allowing combination of filters

#### 3. Configuration (`src/config.py`)
- Centralized settings management
- Risk thresholds
- API endpoints
- File paths

#### 4. Automation (`github/workflows/daily-update.yml`)
- Scheduled execution (daily at 00:00 UTC)
- Automatic commit and push of updated reports
- Runs without human intervention

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd cvedaily

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: Add OpenAI API key for AI-enhanced descriptions
cp .env.example .env
# Edit .env and add OPENAI_API_KEY=your_api_key_here
```

## Usage

### Manual Execution
```bash
# Activate virtual environment
source venv/bin/activate

# Run daily collection
python src/main.py
```

### With AI Enhancement
```bash
# Set OpenAI API key
export OPENAI_API_KEY=your_api_key_here
python src/main.py
```

### Test Script
```bash
# Run the test script
python test_collector.py
```

## Output Files

- `report.html`: Current day's high-risk CVEs in HTML format (rich UI with metrics and interactive filters)
- `reports/YYYY/daily_cve_YYYYMMDD.md`: Daily Markdown archives organized by year
- Generated reports include:
  - CVE identifier (e.g., CVE-2023-1234)
  - Enhanced vulnerability descriptions
  - CVSS scores with severity indicators
  - EPSS probabilities
  - CISA KEV listing status
  - Direct links to NVD, MITRE, and EPSS pages
  - Publication dates and modification dates
  - Status indicators (New vs Recently Updated)
  - Vendor/Product classifications

## Report Features

The HTML report includes:

### Advanced Interactive Filtering System
- **Dual-panel Layout**: Main content panel and filtering sidebar
- **Scrollable Sidebar**: The vendor filter list is scrollable with max-height (85vh) and custom scrollbars
- **Applied Filters Display**: Shows currently active filters at the top of the sidebar
- **Summary Filters**: Click on any statistic in the summary to filter (e.g., "In CISA KEV" button)
- **Composite Filtering**: Combines multiple filter types simultaneously (Status + Vendor/Product filters)
- **Filter Toggle System**: Click to add/remove filters, allowing multiple simultaneous selections
- **Real-time Filter Status**: Shows currently applied filters at the top of the sidebar
- **Vendor Filters**: Sidebar lists top 20 vendors/products by count with "Show More" button; click to show additional vendors
- **Show More Functionality**: Expand vendor list to see all available filters (37 more in example)
- **Status Filters**: Filter by "In CISA KEV", "High EPSS", "Recently Modified", etc. with toggle capability
- **Card-level Filters**: Each CVE card has clickable tags (CVSS, EPSS, CISA KEV, etc.) to filter
- **Vendor Tags**: Each CVE displays clickable vendor tags that filter the report
- **Clear All Filters Button**: Reset all filters to view all CVEs

### Filter Combinations Supported
- Status + Vendor (e.g., "Recently Modified" AND "Vendor: google")
- Multiple vendors (e.g., "Vendor: microsoft" OR "Vendor: apple")
- Multiple statuses (e.g., "High EPSS" AND "In CISA KEV")
- Mixed combinations (e.g., "Newly Published" AND ("Vendor: google" OR "Vendor: microsoft"))

### Optimized Vendor Handling
- **Top 20 Vendors**: The sidebar initially shows the top 20 vendors by vulnerability count
- **Show More Button**: Reveal additional vendors beyond the initial 20 with a single click
- **Smart Scrolling**: Custom scrollbar styling for better UX
- **Responsive Limits**: Long vendor lists are constrained to prevent UI issues
- **Applied Filters Display**: Shows currently active filters at the top of the sidebar for better visibility

### Visual Elements
- 📊 Summary statistics dashboard
- 🛡️ CVSS severity ratings with color coding
- 📈 EPSS scores showing exploitation likelihood
- 🇺🇸 CISA KEV indicators for known exploited vulnerabilities
- 🔗 Direct links to NVD, MITRE, and EPSS for each CVE
- 🔄 Indicators for recently modified CVEs vs new publications
- 🏢 Vendor/product tags for classification
- 📱 Responsive design for desktop and mobile viewing
- 🎨 Modern UI with hover effects and card-based layout

## Markdown Report Features

The Markdown report includes:
- **Vendor Summary Table**: Top 10 vendors by vulnerability count at the top of the report
- **Detailed CVE Listings**: Each CVE with metrics and metadata
- **Organized Format**: Clear separation between CVE entries

## Configuration Options

Edit `src/config.py` to customize:
- Risk thresholds (CVSS and EPSS)
- Lookback days
- API endpoints
- Output paths

## GitHub Actions Setup

1. Create a GitHub repository
2. Copy this project to the repository
3. Optionally add `OPENAI_API_KEY` to repository secrets (Settings → Secrets and variables → Actions)
4. The workflow will run automatically daily at 00:00 UTC

## Dependencies

The system requires Python 3.8+ and these packages:
- requests: HTTP requests
- beautifulsoup4: HTML parsing
- pandas: Data manipulation (optional, for advanced analysis)
- openai: AI enhancement (optional)
- python-dotenv: Environment variable management
- html2text: HTML to text conversion
- jinja2: HTML template rendering

## Troubleshooting

- **Missing dependencies**: Run `pip install -r requirements.txt`
- **Rate limiting**: The system uses public APIs which may have rate limits
- **Network connectivity**: Ensure network access to data sources
- **No CVEs found**: This is expected on days with no high-risk vulnerabilities

## Security Considerations

- Uses only public, unauthenticated APIs where possible
- Minimal external dependencies
- Sanitizes all data inputs
- Designed for transparency and auditability

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool provides security intelligence based on publicly available vulnerability databases. Information accuracy depends on the data sources. Use for educational and defensive security purposes only.