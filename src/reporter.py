import os
from datetime import datetime
from jinja2 import Template
import html
import re
from decimal import Decimal, ROUND_HALF_UP
import markdown

def sanitize_vendor_id(vendor):
    """Sanitize vendor names to create safe IDs for HTML elements"""
    # Replace non-alphanumeric characters with underscores
    return re.sub(r'[^a-zA-Z0-9]', '_', vendor)

def round_epss_score(score):
    """Round EPSS score to 3 decimal places with proper rounding"""
    if score is None:
        return 0.0
    # Convert to Decimal for precise rounding
    decimal_score = Decimal(str(score))
    rounded = decimal_score.quantize(Decimal('0.001'), rounding=ROUND_HALF_UP)
    return float(rounded)


def convert_markdown_code_blocks(text):
    """Convert markdown code blocks (backticks) to HTML <code> tags"""
    # Replace inline code blocks marked with single backticks
    import re
    # Pattern to match text between backticks
    pattern = r'`(.*?)`'
    # Replace with <code> tags
    result = re.sub(pattern, r'<code>\1</code>', text)
    return result

def generate_markdown_report(cves, output_path='docs/reports/YYYY/daily_cve_YYYYMMDD.md', total_cve_count=None):
    """Generate Markdown report with CVE data"""

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Calculate statistics
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) >= 0.01)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')

    # Add CVSS severity counts
    critical_count = sum(1 for cve in cves if cve.get('cvss_score', 0) >= 9.0)
    high_count = sum(1 for cve in cves if 7.0 <= cve.get('cvss_score', 0) < 9.0)
    medium_count = sum(1 for cve in cves if 4.0 <= cve.get('cvss_score', 0) < 7.0)
    low_count = sum(1 for cve in cves if 0 < cve.get('cvss_score', 0) < 4.0)

    # Collect all unique vendors
    all_vendors = set()
    vendor_counts = {}
    for cve in cves:
        for vendor in cve.get('vendors', []):
            all_vendors.add(vendor)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort vendors by count and limit to top 10
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    top_vendors = dict(sorted_vendors[:10])  # Top 10 vendors

    # Start generating markdown content
    md_content = f"# Daily CVE Report - {datetime.now().strftime('%Y-%m-%d')}\n\n"
    md_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_content += f"Total Vulnerabilities: {total_cve_count if total_cve_count is not None else len(cves)}\n\n"

    # Add Top Vendors table
    md_content += "## Top Vendors by Vulnerability Count\n"
    md_content += "| Vendor | Count |\n"
    md_content += "|--------|-------|\n"
    for vendor, count in top_vendors.items():
        md_content += f"| {vendor} | {count} |\n"
    md_content += "\n\n---\n\n"

    # Add each CVE
    for cve in cves:
        severity = 'low'
        if cve.get('cvss_score', 0) >= 9.0:
            severity = 'critical'
        elif cve.get('cvss_score', 0) >= 7.0:
            severity = 'high'
        elif cve.get('cvss_score', 0) >= 4.0:
            severity = 'medium'

        # Format entry type
        status_text = "Newly Published" if cve.get('entry_type') == 'published' else "Recently Modified"

        # Format vendors
        vendor_list = ', '.join(cve.get('vendors', [])) if cve.get('vendors') else 'N/A'

        md_content += f"## {cve['id']}\n\n"
        # Add both CVSS and EPSS scores to the markdown report
        md_content += f"**CVSS Score:** {cve.get('cvss_score', 0):.1f} | **EPSS Score:** {round_epss_score(cve.get('epss_score', 0)):.3f} | **Status:** {status_text} | **Vendors:** {vendor_list}\n\n"
        md_content += f"{cve.get('description', 'No description available')}\n\n"

        # Add publication and modification dates
        pub_date = cve.get('published_date', '')[:10] if cve.get('published_date') else 'Unknown'
        mod_date = cve.get('last_modified', '')[:10] if cve.get('last_modified') else 'Unknown'
        md_content += f"*Published: {pub_date}*\n"
        if mod_date != pub_date:
            md_content += f"*Last Modified: {mod_date}*\n"
        else:
            md_content += f"*Last Modified: {pub_date}*\n"
        md_content += "\n---\n\n"

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md_content)

    print(f"Markdown report generated: {output_path}")


def generate_html_report(cves, output_path='index.html', total_cve_count=None):
    """Generate HTML report with CVE data"""

    # Define the HTML template as a string
    html_template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daily CVE Report - {{ date }}</title>
    <style>
        :root {
            --primary-color: #d32f2f;
            --secondary-color: #1976d2;
            --tertiary-color: #388e3c;
            --warning-color: #ffa726;
            --light-bg: #f5f5f5;
            --card-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 25px;
        }

        .main-content {
            background-color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
        }

        .sidebar {
            background-color: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
            height: fit-content;
            position: sticky;
            top: 20px;
            max-height: 90vh;  /* 增加最大高度到90vh，提供更多空间 */
            overflow-y: auto;  /* 允许垂直滚动 */
        }

        /* 自定义滚动条样式 */
        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: #c1c1c1;
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: #a8a8a8;
        }

        header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid var(--primary-color);
            padding-bottom: 15px;
        }

        h1 {
            color: var(--primary-color);
            margin: 0;
            font-size: 2.2em;
        }

        .filter-status {
            margin-bottom: 25px;
        }

        .current-filters {
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }

        .current-filters strong {
            display: block;
            margin-bottom: 5px;
            color: #495057;
        }

        #active-filters {
            color: #6c757d;
            font-size: 0.9em;
        }

        .filter-section {

        }

        .filter-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }

        .filter-list {
            list-style: none;
            padding: 0;
        }

        .filter-item {
            padding: 2px 0;
            cursor: pointer;
            color: var(--secondary-color);
        }

        .filter-item:hover {
            text-decoration: underline;
        }

        .extra-vendor {
            background-color: transparent;
        }

        /* CVSS severity filter styles */
        .filter-critical {
            background-color: #ffebee;
            color: #c62828;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .filter-high {
            background-color: #fff3e0;
            color: #e65100;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .filter-medium {
            background-color: #fff8e1;
            color: #f57f17;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .filter-low {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        /* Status filter styles */
        .filter-modified-item {
            background-color: #e3f2fd;
            color: #1565c0;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .filter-published-item {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .summary-box {
            background: linear-gradient(135deg, #e3f2fd, #f5f5f5);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            border-left: 5px solid var(--secondary-color);
        }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            box-shadow: var(--card-shadow);
            cursor: pointer;
            transition: transform 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-3px);
        }

        .stat-number {
            font-size: 1.8em;
            font-weight: bold;
            color: var(--primary-color);
        }

        .cve-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }

        .cve-card {
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
            background: white;
            display: none; /* Initially hide all cards */
            max-height: 700px; /* 增加卡片最大高度以容纳更多内容 */
            display: flex;
            flex-direction: column;
            box-sizing: border-box; /* 确保padding包含在高度内 */
            min-height: 320px; /* 设置最小高度以保持一致性 */
        }

        .cve-card.filtered-in {
            display: flex;
        }

        .cve-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.15);
        }

        .cve-header {
            background: linear-gradient(135deg, #f5f5f5, #e8e8e8);
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0; /* 防止头部被压缩 */
        }

        .cve-id {
            font-weight: bold;
            font-size: 1.1em;
            color: var(--primary-color);
        }

        .cve-severity {
            font-weight: bold;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
        }

        .severity-critical {
            background-color: #ffebee;
            color: #b71c1c;
        }

        .severity-high {
            background-color: #fff3e0;
            color: #e65100;
        }

        .severity-medium {
            background-color: #fff8e1;
            color: #f57f17;
        }

        .severity-low {
            background-color: #e8f5e9;
            color: #2e7d32;
        }

        .cve-metrics {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 10px 0;
        }

        .metric-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 500;
            cursor: pointer;
        }

        .metric-tag:hover {
            opacity: 0.8;
        }

        .tag-cvss {
            background-color: #ffebee;
            color: #c62828;
        }

        .tag-epss {
            background-color: #e8f5e9;
            color: #2e7d32;
        }

        .tag-cisa {
            background-color: #e3f2fd;
            color: #1565c0;
        }

        .tag-exp {
            background-color: #fff3e0;
            color: #f57c00;
        }

        .cve-vendors {
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 8px;
            font-size: 0.9em;
        }

        .cve-vendor-tag {
            display: inline-block;
            padding: 3px 8px;
            margin: 2px;
            background-color: #e9ecef;
            border-radius: 10px;
            font-size: 0.8em;
            cursor: pointer;
        }

        .cve-vendor-tag:hover {
            background-color: #dee2e6;
        }

        .cve-body {
            padding: 20px;
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow: hidden;
            min-height: 0; /* Allow content to scroll if needed */
        }

        .cve-description {
            margin-bottom: 15px;
            line-height: 1.6; /* 调整行高 */
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 6; /* 限制为6行 */
            -webkit-box-orient: vertical;
            word-break: break-word; /* 确保长单词也能适当换行 */
            flex-shrink: 0; /* 防止被压缩 */
        }

        /* Container for elements that should be grouped at the bottom */
        .cve-content-group {
            display: flex;
            flex-direction: column;
            margin-top: auto; /* Push to the bottom */
            flex-shrink: 0; /* Prevent from shrinking */
        }

        .cve-links {
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid #eee;
            flex-shrink: 0; /* 防止被压缩 */
        }

        .link-item {
            display: inline-block;
            margin-right: 15px;
            margin-bottom: 8px;
        }

        .link-btn {
            display: inline-block;
            padding: 6px 12px;
            background-color: #f0f0f0;
            color: #333;
            text-decoration: none;
            border-radius: 6px;
            font-size: 0.85em;
            transition: background-color 0.2s;
        }

        .link-btn:hover {
            background-color: #e0e0e0;
        }

        .cve-meta {
            font-size: 0.85em;
            color: #666;
            padding-top: 10px;
            border-top: 1px dashed #eee;
            flex-shrink: 0; /* 防止被压缩 */
        }

        .no-cves {
            text-align: center;
            padding: 60px 20px;
            color: #666;
            font-size: 1.2em;
        }

        .info-icon {
            margin-right: 5px;
        }

        .show-all-btn {
            display: block;
            width: 100%;
            padding: 10px;
            background-color: #4caf50;
            color: white;
            text-align: center;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 15px;
            font-weight: bold;
        }

        .show-all-btn:hover {
            background-color: #45a049;
        }

        .show-more-btn {
            display: block;
            width: 100%;
            padding: 8px;
            background-color: #2196f3;
            color: white;
            text-align: center;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
            font-size: 0.9em;
        }

        .show-more-btn:hover {
            background-color: #1976d2;
        }

        .filter-item.selected {
            font-weight: bold;
            background-color: #e3f2fd;
            padding: 3px 0;
        }

        @media (max-width: 1200px) {
            }
        }

        @media (min-width: 1201px) and (min-height: 801px) and (max-height: 1000px) {
            /* 中等高度屏幕 */
            .sidebar {
                max-height: 80vh;
            }
        }

        @media (min-width: 1201px) and (min-height: 1001px) {
            /* 高屏幕 */
            .sidebar {
                max-height: 85vh;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
                grid-template-columns: 1fr;
            }

            .cve-grid {
                grid-template-columns: 1fr;
            }

            .cve-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .cve-metrics {
                width: 100%;
            }

            .cve-card {
                max-height: none; /* 在移动设备上去除卡片最大高度限制，允许内容完全展开 */
                min-height: auto; /* 让卡片高度适应内容 */
            }

            .cve-description {
                -webkit-line-clamp: 10; /* 在移动设备上允许显示更多行文本 */
            }
        }

        @media (max-width: 480px) {
            /* 针对更小的屏幕进行额外优化 */
            .cve-card {
                min-height: auto;
            }

            .cve-header {
                padding: 12px 15px; /* 减少内边距 */
            }

            .cve-body {
                padding: 15px; /* 减少内边距 */
            }

            .cve-description {
                -webkit-line-clamp: 8; /* 在极小屏幕上显示较少的行数 */
            }

            .metric-tag {
                padding: 3px 8px; /* 减少标签内边距 */
                font-size: 0.75em; /* 稍微缩小字体 */
            }

            .cve-vendor-tag {
                padding: 2px 6px; /* 减少供应商标签内边距 */
                font-size: 0.75em; /* 稍微缩小字体 */
            }
        }
    </style>
</head>
<body>
    <a href="https://github.com/secnotes/dailycve" class="github-corner" aria-label="View source on GitHub">
        <svg width="80" height="80" viewBox="0 0 250 250" style="fill:#d32f2f; color:#fff; position: fixed; top: 0; border: 0; right: 0; z-index: 1000;" aria-hidden="true">
            <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
            <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
            <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
        </svg>
    </a>
    <style>
        .github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
        @keyframes octocat-wave{
            0%,100%{transform:rotate(0)}
            20%,60%{transform:rotate(-25deg)}
            40%,80%{transform:rotate(10deg)}
        }
        @media (max-width:500px){
            .github-corner:hover .octo-arm{animation:none}
            .github-corner .octo-arm{animation:octocat-wave 560ms ease-in-out}
        }
    </style>
    <div class="container">
        <div class="main-content">
            <header>
                <h1>🔍 Daily CVE Report - {{ date }}</h1>
                <p>High-Risk Vulnerabilities Collected from Multiple Sources</p>
            </header>

            <div class="summary-box">
                <h2>📊 Summary</h2>
                <p><strong>Report Generated:</strong> {{ generated_time }}</p>

                <div class="summary-stats">
                    <div class="stat-card" onclick="applySingleFilter('all')">
                        <div class="stat-number">{{ cve_count }}</div>
                        <div>Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card" onclick="applySingleFilter('high-risk')">
                        <div class="stat-number">{{ high_risk_count }}</div>
                        <div>High Risk (CVSS > 7.0)</div>
                    </div>
                    <div class="stat-card" onclick="toggleStatusFilter('cisa')">
                        <div class="stat-number">{{ cisa_kev_count }}</div>
                        <div>In CISA KEV</div>
                    </div>
                    <div class="stat-card" onclick="toggleStatusFilter('epss')">
                        <div class="stat-number">{{ epss_high_count }}</div>
                        <div>High EPSS (≥0.01)</div>
                    </div>
                </div>
            </div>

            {% if cves %}
                <div class="cve-grid" id="cve-grid">
                    {% for cve in cves %}
                    <div class="cve-card filtered-in" id="cve-{{ cve.id|replace('-', '_') }}"
                         data-cvss="{{ cve.cvss_score }}"
                         data-epss="{{ cve.epss_score }}"
                         data-cisa="{{ cve.in_cisa_kev|lower }}"
                         data-modified="{{ 'True' if cve.entry_type == 'modified' else 'False' }}"
                         data-vendors="{{ cve.vendors|join(',') }}">
                        <div class="cve-header">
                            <div class="cve-id">{{ cve.id }}</div>
                            <div class="cve-severity severity-{{ cve.severity }}">{{ cve.severity|title }}</div>
                        </div>

                        <div class="cve-body">
                            <div class="cve-description">
                                {{ convert_md_code(cve.description)|safe }}
                            </div>

                            <!-- Group all other content together to align at bottom -->
                            <div class="cve-content-group">
                                {% if cve.cvss_score >= 0 or cve.epss_score > 0 or cve.in_cisa_kev %}
                                <div class="cve-metrics">
                                    <span class="metric-tag tag-cvss" onclick="applySingleFilterByCVSS({{ cve.cvss_score }})">🛡️ CVSS: {{ "%.1f"|format(cve.cvss_score) }}</span>

                                    {% if cve.epss_score > 0 %}
                                        <span class="metric-tag tag-epss" onclick="applySingleFilterByEPSS({{ "%.3f"|format(round_epss(cve.epss_score)) }})">📈 EPSS: {{ "%.3f"|format(round_epss(cve.epss_score)) }}</span>
                                    {% endif %}

                                    {% if cve.in_cisa_kev %}
                                        <span class="metric-tag tag-cisa" onclick="toggleStatusFilter('cisa')">🇺🇸 CISA KEV</span>
                                    {% endif %}

                                    {% if cve.entry_type == 'modified' %}
                                        <span class="metric-tag tag-exp" onclick="toggleStatusFilter('modified')">🔄 Recently Updated</span>
                                    {% else %}
                                        <span class="metric-tag tag-cvss" onclick="toggleStatusFilter('published')">🆕 New Entry</span>
                                    {% endif %}

                                    {% if cve.exploits %}
                                        <span class="metric-tag tag-exp">💥 Known Exploits</span>
                                    {% endif %}
                                </div>
                                {% endif %}

                                {% if cve.vendors %}
                                <div class="cve-vendors">
                                    <strong>/vendors/:</strong>
                                    {% for vendor in cve.vendors %}
                                    <span class="cve-vendor-tag" onclick="toggleVendorFilter('{{ vendor }}')">{{ vendor }}</span>
                                    {% endfor %}
                                </div>
                                {% endif %}

                                <div class="cve-links">
                                    <div class="link-item">
                                        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve.id }}" target="_blank" class="link-btn">📝 MITRE CVE</a>
                                    </div>
                                    <div class="link-item">
                                        <a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank" class="link-btn">🔍 NVD Details</a>
                                    </div>
                                    {% if cve.epss_score > 0 %}
                                    <div class="link-item">
                                        <a href="https://epss.cyentia.com/?cve={{ cve.id }}" target="_blank" class="link-btn">📊 EPSS Score</a>
                                    </div>
                                    {% endif %}
                                </div>

                                <div class="cve-meta">
                                    <strong>Published:</strong> {{ cve.published_date[:10] if cve.published_date else 'Unknown' }}
                                    {% if cve.last_modified and cve.last_modified != cve.published_date %}
                                    | <strong>Modified:</strong> {{ cve.last_modified[:10] }}
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <div class="no-cves">
                    <p>✅ No high-risk vulnerabilities detected for {{ date }}.</p>
                </div>
            {% endif %}
        </div>

        <div class="sidebar">
            <div class="filter-section">
                <div class="filter-title">🛡️ Filter by CVSS Severity</div>
                <ul class="filter-list">
                    <li class="filter-item filter-critical" id="filter-critical" onclick="applySingleFilterBySeverity('critical')">Critical (CVSS ≥ 9.0) ({{ critical_count }})</li>
                    <li class="filter-item filter-high" id="filter-high" onclick="applySingleFilterBySeverity('high')">High (7.0 ≤ CVSS < 9.0) ({{ high_count }})</li>
                    <li class="filter-item filter-medium" id="filter-medium" onclick="applySingleFilterBySeverity('medium')">Medium (4.0 ≤ CVSS < 7.0) ({{ medium_count }})</li>
                    <li class="filter-item filter-low" id="filter-low" onclick="applySingleFilterBySeverity('low')">Low (0 < CVSS < 4.0) ({{ low_count }})</li>
                </ul>
            </div>

            <div class="filter-section">
                <div class="filter-title">🏷️ Filter by Status</div>
                <ul class="filter-list">
                    <li class="filter-item filter-modified-item" id="filter-modified" onclick="toggleStatusFilter('modified')">Recently Modified ({{ modified_count }})</li>
                    <li class="filter-item filter-published-item" id="filter-published" onclick="toggleStatusFilter('published')">Newly Published ({{ published_count }})</li>
                </ul>
            </div>

            {% if all_vendors_list %}
            <div class="filter-section">
                <div class="filter-title">🏢 Filter by Vendor</div>
                <ul class="filter-list" id="vendor-filter-list">
                    {% for vendor in initial_vendors %}
                    <li class="filter-item" id="filter-vendor-{{ sanitize_vendor_id(vendor) }}" onclick="toggleVendorFilter('{{ vendor }}')" style="display:block;">{{ vendor }} ({{ all_sorted_vendors[vendor] }})</li>
                    {% endfor %}
                    {% for vendor in all_vendors_list %}
                    <li class="filter-item extra-vendor" id="filter-vendor-{{ sanitize_vendor_id(vendor) }}" onclick="toggleVendorFilter('{{ vendor }}')" style="display:none;">{{ vendor }} ({{ all_sorted_vendors[vendor] }})</li>
                    {% endfor %}
                </ul>
                {% if all_vendors_list|length > 19 %}
                <button class="show-more-btn" onclick="toggleMoreVendors()" id="show-more-btn">Show More Vendors ({{ all_vendors_list|length - 19 }} more)</button>
                {% endif %}
            </div>
            {% endif %}

        </div>
    </div>

    <script>
        // Initialize all CVEs as visible and initialize filter state
        document.addEventListener('DOMContentLoaded', function() {
            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.classList.add('filtered-in');
            });

            // Initialize active filters object
            window.activeFilters = {
                status: [],
                vendors: []
            };
        });

        // Variable to track if more vendors are shown
        let moreVendorsShown = false;

        // Toggle status filter (CISA, EPSS, Modified, Published)
        function toggleStatusFilter(filterType) {
            const index = window.activeFilters.status.indexOf(filterType);
            if (index > -1) {
                // Remove filter
                window.activeFilters.status.splice(index, 1);
            } else {
                // Add filter
                // Handle mutually exclusive filters (modified/published)
                if (filterType === 'modified' || filterType === 'published') {
                    // Remove the opposite one if it exists
                    const modIndex = window.activeFilters.status.indexOf('modified');
                    const pubIndex = window.activeFilters.status.indexOf('published');

                    if (modIndex > -1) {
                        window.activeFilters.status.splice(modIndex, 1);
                    }
                    if (pubIndex > -1) {
                        window.activeFilters.status.splice(pubIndex, 1);
                    }
                }

                window.activeFilters.status.push(filterType);
            }

            applyAllFilters();
            updateSelectedFiltersHighlight();
        }

        // Toggle vendor filter (mutually exclusive)
        function toggleVendorFilter(vendor) {
            const index = window.activeFilters.vendors.indexOf(vendor);
            if (index > -1) {
                // Remove filter (deselect current vendor)
                window.activeFilters.vendors = [];
            } else {
                // Replace with new filter (select only this vendor)
                window.activeFilters.vendors = [vendor];
            }

            applyAllFilters();
            updateSelectedFiltersHighlight();
        }

        // Apply single filter (for summary stats clicks)
        function applySingleFilter(filterType) {
            if (filterType === 'all') {
                clearAllFilters();
            } else if (filterType === 'high-risk') {
                // Apply high risk filter (CVSS > 7.0)
                window.activeFilters = {
                    status: ['high-risk'],
                    vendors: []
                };
                applyAllFilters();
                updateSelectedFiltersHighlight();
            }
        }

        // Apply CVSS-specific filter
        function applySingleFilterByCVSS(minScore) {
            window.activeFilters = {
                status: [`cvss-${minScore}`],
                vendors: []
            };
            applyAllFilters();
        }

        // Apply CVSS severity filter (critical, high, medium, low)
        function applySingleFilterBySeverity(severity) {
            window.activeFilters = {
                status: [`severity-${severity}`],
                vendors: []
            };
            applyAllFilters();
            updateSelectedFiltersHighlight();
        }

        // Apply EPSS-specific filter
        function applySingleFilterByEPSS(minScore) {
            window.activeFilters = {
                status: [`epss-${minScore}`],
                vendors: []
            };
            applyAllFilters();
        }

        // Apply all active filters
        function applyAllFilters() {
            const allCards = document.querySelectorAll('.cve-card');

            allCards.forEach(card => {
                let showCard = true;

                // Apply status filters
                if (window.activeFilters.status.length > 0) {
                    for (let filter of window.activeFilters.status) {
                        switch(filter) {
                            case 'cisa':
                                if (card.getAttribute('data-cisa') !== 'true') {
                                    showCard = false;
                                }
                                break;
                            case 'epss':
                                if ((parseFloat(card.getAttribute('data-epss')) || 0) < 0.01) {
                                    showCard = false;
                                }
                                break;
                            case 'modified':
                                if (card.getAttribute('data-modified') !== 'True') {
                                    showCard = false;
                                }
                                break;
                            case 'published':
                                if (card.getAttribute('data-modified') !== 'False') {
                                    showCard = false;
                                }
                                break;
                            case 'high-risk':
                                if ((parseFloat(card.getAttribute('data-cvss')) || 0) <= 7.0) {
                                    showCard = false;
                                }
                                break;
                            default:
                                // Handle CVSS specific filter
                                if (filter.startsWith('cvss-')) {
                                    const minCvss = parseFloat(filter.split('-')[1]);
                                    if ((parseFloat(card.getAttribute('data-cvss')) || 0) < minCvss) {
                                        showCard = false;
                                    }
                                }
                                // Handle EPSS specific filter
                                else if (filter.startsWith('epss-')) {
                                    const minEpss = parseFloat(filter.split('-')[1]);
                                    if ((parseFloat(card.getAttribute('data-epss')) || 0) < minEpss) {
                                        showCard = false;
                                    }
                                }
                                // Handle CVSS severity specific filter
                                else if (filter.startsWith('severity-')) {
                                    const severity = filter.split('-')[1];
                                    const cvssScore = parseFloat(card.getAttribute('data-cvss')) || 0;

                                    switch(severity) {
                                        case 'critical':
                                            if (cvssScore < 9.0) {
                                                showCard = false;
                                            }
                                            break;
                                        case 'high':
                                            if (cvssScore < 7.0 || cvssScore >= 9.0) {
                                                showCard = false;
                                            }
                                            break;
                                        case 'medium':
                                            if (cvssScore < 4.0 || cvssScore >= 7.0) {
                                                showCard = false;
                                            }
                                            break;
                                        case 'low':
                                            if (cvssScore >= 4.0 || cvssScore === 0) {
                                                showCard = false;
                                            }
                                            break;
                                    }
                                }
                                break;
                        }

                        // If any filter condition fails, stop checking other filters
                        if (!showCard) break;
                    }
                }

                // If status filters passed, apply vendor filters
                if (showCard && window.activeFilters.vendors.length > 0) {
                    const cardVendorsStr = card.getAttribute('data-vendors') || '';
                    const cardVendors = cardVendorsStr.split(',');

                    // Check if any of the active vendor filters match this card
                    let hasMatchingVendor = false;
                    for (let vendor of window.activeFilters.vendors) {
                        if (cardVendors.includes(vendor)) {
                            hasMatchingVendor = true;
                            break;
                        }
                    }

                    if (!hasMatchingVendor) {
                        showCard = false;
                    }
                }

                // Update card visibility
                if (showCard) {
                    card.style.display = 'block';
                    card.classList.add('filtered-in');
                } else {
                    card.style.display = 'none';
                    card.classList.remove('filtered-in');
                }
            });

            // Update the display of active filters
            updateActiveFiltersDisplay();
        }

        // Clear all filters
        function clearAllFilters() {
            window.activeFilters = {
                status: [],
                vendors: []
            };

            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.style.display = 'block';
                card.classList.add('filtered-in');
            });

            updateActiveFiltersDisplay();
            updateSelectedFiltersHighlight();
        }

        // Update the display of active filters
        function updateActiveFiltersDisplay() {
            const activeFiltersDiv = document.getElementById('active-filters');
            let filterText = [];

            // Add status filters
            for (let status of window.activeFilters.status) {
                switch(status) {
                    case 'cisa':
                        filterText.push('CISA KEV');
                        break;
                    case 'epss':
                        filterText.push('High EPSS');
                        break;
                    case 'modified':
                        filterText.push('Recently Modified');
                        break;
                    case 'published':
                        filterText.push('Newly Published');
                        break;
                    case 'high-risk':
                        filterText.push('High Risk (CVSS > 7.0)');
                        break;
                    default:
                        if (status.startsWith('cvss-')) {
                            const minCvss = parseFloat(status.split('-')[1]);
                            filterText.push(`CVSS ≥ ${minCvss}`);
                        } else if (status.startsWith('epss-')) {
                            const minEpss = parseFloat(status.split('-')[1]);
                            filterText.push(`EPSS ≥ ${minEpss}`);
                        }
                        break;
                }
            }

            // Add vendor filters
            for (let vendor of window.activeFilters.vendors) {
                filterText.push(`Vendor: ${vendor}`);
            }

            if (filterText.length === 0) {
                activeFiltersDiv.textContent = 'None';
            } else {
                activeFiltersDiv.innerHTML = filterText.join(', ');
            }
        }

        // Update the display of active filters
        function updateActiveFiltersDisplay() {
            const activeFiltersDiv = document.getElementById('active-filters');
            let filterText = [];

            // Add status filters
            for (let status of window.activeFilters.status) {
                switch(status) {
                    case 'cisa':
                        filterText.push('CISA KEV');
                        break;
                    case 'epss':
                        filterText.push('High EPSS');
                        break;
                    case 'modified':
                        filterText.push('Recently Modified');
                        break;
                    case 'published':
                        filterText.push('Newly Published');
                        break;
                    case 'high-risk':
                        filterText.push('High Risk (CVSS > 7.0)');
                        break;
                    default:
                        if (status.startsWith('cvss-')) {
                            const minCvss = parseFloat(status.split('-')[1]);
                            filterText.push(`CVSS ≥ ${minCvss}`);
                        } else if (status.startsWith('epss-')) {
                            const minEpss = parseFloat(status.split('-')[1]);
                            filterText.push(`EPSS ≥ ${minEpss}`);
                        }
                        break;
                }
            }

            // Add vendor filters
            for (let vendor of window.activeFilters.vendors) {
                filterText.push(`Vendor: ${vendor}`);
            }

            if (filterText.length === 0) {
                activeFiltersDiv.textContent = 'None';
            } else {
                activeFiltersDiv.innerHTML = filterText.join(', ');
            }
        }

        // Update highlight for selected filters in sidebar
        function updateSelectedFiltersHighlight() {
            // Remove all selected classes
            const allFilterItems = document.querySelectorAll('.filter-item');
            allFilterItems.forEach(item => {
                item.classList.remove('selected');
            });

            // Add selected class to active status filters
            if (window.activeFilters.status.length > 0) {
                window.activeFilters.status.forEach(status => {
                    let elementId = null;
                    switch(status) {
                        case 'cisa':
                            elementId = 'filter-cisa';
                            break;
                        case 'epss':
                            elementId = 'filter-epss';
                            break;
                        case 'modified':
                            elementId = 'filter-modified';
                            break;
                        case 'published':
                            elementId = 'filter-published';
                            break;
                        case 'severity-critical':
                            elementId = 'filter-critical';
                            break;
                        case 'severity-high':
                            elementId = 'filter-high';
                            break;
                        case 'severity-medium':
                            elementId = 'filter-medium';
                            break;
                        case 'severity-low':
                            elementId = 'filter-low';
                            break;
                        default:
                            // Skip specific CVSS and EPSS filters as they are not in the sidebar
                            break;
                    }

                    if (elementId) {
                        const element = document.getElementById(elementId);
                        if (element) {
                            element.classList.add('selected');
                        }
                    }
                });
            }

            // Add selected class to active vendor filter
            if (window.activeFilters.vendors.length > 0) {
                const vendor = window.activeFilters.vendors[0]; // We only support single vendor filter
                // Sanitize vendor name for use in ID - replace any non-alphanumeric characters with underscores
                const sanitizedVendor = vendor.replace(/[^a-zA-Z0-9]/g, '_');
                const vendorId = 'filter-vendor-' + sanitizedVendor;
                const vendorElement = document.getElementById(vendorId);
                if (vendorElement) {
                    vendorElement.classList.add('selected');
                }
            }
        }

        // Clear all filters (still available via JavaScript API)
        function clearAllFilters() {
            window.activeFilters = {
                status: [],
                vendors: []
            };

            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.style.display = 'block';
                card.classList.add('filtered-in');
            });

            updateActiveFiltersDisplay();
            updateSelectedFiltersHighlight();
        }

        // Toggle more vendors
        function toggleMoreVendors() {
            const extraVendors = document.querySelectorAll('.extra-vendor');
            const showMoreBtn = document.getElementById('show-more-btn');

            if (!moreVendorsShown) {
                // Show all extra vendors
                extraVendors.forEach(item => {
                    item.style.display = 'block';
                });

                showMoreBtn.textContent = 'Show Less Vendors';
                moreVendorsShown = true;
            } else {
                // Hide extra vendors (keep only the first 20)
                extraVendors.forEach((item, index) => {
                    item.style.display = 'none';
                });

                showMoreBtn.textContent = 'Show More Vendors ({{ all_vendors_list|length - 19 }} more)';
                moreVendorsShown = false;
            }
        }
    </script>

    <!-- Footer with link to original markdown report -->
    <hr style="border: 0; border-top: 1px solid #eee; margin: 30px auto; width: 100%; max-width: 1600px;">
    <footer style="padding: 20px; text-align: center; color: #666;">
        <div style="margin-bottom: 10px;">
            <strong>For AI/Bot consumption:</strong>
            <a href="reports/{{ date[:4] }}/daily_cve_{{ date|replace('-', '') }}.md" target="_blank" rel="noopener noreferrer"
               style="color: #1976d2; text-decoration: none; padding: 5px 10px; border: 1px solid #1976d2; border-radius: 4px; display: inline-block; margin-left: 10px;">
               📄 Original Markdown Report
            </a>
        </div>
        <small>
            Daily CVE Report - Generated on {{ generated_time }} |
            <a href="https://github.com/secnotes/dailycve" style="color: #666; text-decoration: none;">GitHub Project</a>
        </small>
    </footer>
</body>
</html>
    """

    # Create template and add our custom filter
    template = Template(html_template_str)
    template.globals['sanitize_vendor_id'] = sanitize_vendor_id
    template.globals['round_epss'] = round_epss_score
    template.globals['convert_md_code'] = convert_markdown_code_blocks

    # Calculate statistics
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) >= 0.01)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')

    # Add CVSS severity counts
    critical_count = sum(1 for cve in cves if cve.get('cvss_score', 0) >= 9.0)
    high_count = sum(1 for cve in cves if 7.0 <= cve.get('cvss_score', 0) < 9.0)
    medium_count = sum(1 for cve in cves if 4.0 <= cve.get('cvss_score', 0) < 7.0)
    low_count = sum(1 for cve in cves if 0 < cve.get('cvss_score', 0) < 4.0)

    # Collect all unique vendors
    all_vendors = set()
    vendor_counts = {}
    for cve in cves:
        for vendor in cve.get('vendors', []):
            all_vendors.add(vendor)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort vendors by count and limit to top 19
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    top_vendors = dict(sorted_vendors[:19])  # Top 19 vendors
    all_sorted_vendors = dict(sorted_vendors)  # All vendors sorted by count

    # Prepare data for template
    initial_vendors = list(top_vendors.keys())

    # Format the data for the template
    formatted_cves = []
    for cve in cves:
        # Determine severity based on CVSS score
        severity = 'low'
        if cve.get('cvss_score', 0) >= 9.0:
            severity = 'critical'
        elif cve.get('cvss_score', 0) >= 7.0:
            severity = 'high'
        elif cve.get('cvss_score', 0) >= 4.0:
            severity = 'medium'

        # Determine entry type for display
        entry_type = cve.get('entry_type', 'published')
        entry_label = ''
        if entry_type == 'modified':
            entry_label = '🔄 Updated'
        else:
            entry_label = '📅 New'

        formatted_cves.append({
            'id': cve['id'],
            'description': html.escape(cve['description']) if cve['description'] else 'No description available',
            'cvss_score': cve.get('cvss_score', 0),
            'epss_score': cve.get('epss_score', 0),
            'in_cisa_kev': cve.get('in_cisa_kev', False),
            'exploits': cve.get('exploits', False),
            'published_date': cve.get('published_date', ''),
            'last_modified': cve.get('last_modified', ''),
            'severity': severity,
            'entry_type': entry_type,
            'entry_label': entry_label,
            'vendors': cve.get('vendors', []),
            'products': []  # Remove products from UI
        })

    # Render the template
    html_content = template.render(
        date=datetime.now().strftime('%Y-%m-%d'),
        generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        cve_count=total_cve_count if total_cve_count is not None else len(formatted_cves),
        high_risk_count=high_risk_count,
        cisa_kev_count=cisa_kev_count,
        epss_high_count=epss_high_count,
        modified_count=modified_count,
        published_count=published_count,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        cves=formatted_cves,
        initial_vendors=initial_vendors,
        all_vendors_list=list(all_sorted_vendors.keys()),
        all_sorted_vendors=all_sorted_vendors
    )

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")