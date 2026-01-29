import os
from datetime import datetime
from jinja2 import Template
import html
import re

def sanitize_vendor_id(vendor):
    """Sanitize vendor names to create safe IDs for HTML elements"""
    # Replace non-alphanumeric characters with underscores
    return re.sub(r'[^a-zA-Z0-9]', '_', vendor)

def generate_html_report(cves, output_path='report.html'):
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
            margin-bottom: 25px;
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
            background-color: #f9f9f9;
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
        }

        .cve-card.filtered-in {
            display: block;
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
        }

        .cve-description {
            margin-bottom: 15px;
            line-height: 1.7;
        }

        .cve-links {
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid #eee;
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
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px dashed #eee;
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
        }
    </style>
</head>
<body>
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
                        <div>High EPSS (>0.10)</div>
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
                                {{ cve.description|e }}
                            </div>

                            {% if cve.cvss_score > 0 or cve.epss_score > 0 or cve.in_cisa_kev %}
                            <div class="cve-metrics">
                                {% if cve.cvss_score > 0 %}
                                    <span class="metric-tag tag-cvss" onclick="applySingleFilterByCVSS({{ cve.cvss_score }})">🛡️ CVSS: {{ "%.1f"|format(cve.cvss_score) }}</span>
                                {% endif %}

                                {% if cve.epss_score > 0 %}
                                    <span class="metric-tag tag-epss" onclick="applySingleFilterByEPSS({{ "%.3f"|format(cve.epss_score) }})">📈 EPSS: {{ "%.3f"|format(cve.epss_score) }}</span>
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
                                    <a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank" class="link-btn">🔍 NVD Details</a>
                                </div>
                                <div class="link-item">
                                    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve.id }}" target="_blank" class="link-btn">📝 MITRE CVE</a>
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
                <div class="filter-title">🏷️ Filter by Status</div>
                <ul class="filter-list">
                    <li class="filter-item" id="filter-cisa" onclick="toggleStatusFilter('cisa')">In CISA KEV ({{ cisa_kev_count }})</li>
                    <li class="filter-item" id="filter-epss" onclick="toggleStatusFilter('epss')">High EPSS (>0.10) ({{ epss_high_count }})</li>
                    <li class="filter-item" id="filter-modified" onclick="toggleStatusFilter('modified')">Recently Modified ({{ modified_count }})</li>
                    <li class="filter-item" id="filter-published" onclick="toggleStatusFilter('published')">Newly Published ({{ published_count }})</li>
                </ul>
            </div>

            {% if all_vendors_list %}
            <div class="filter-section">
                <div class="filter-title">🏢 Filter by Vendor/Product</div>
                <ul class="filter-list" id="vendor-filter-list">
                    {% for vendor in initial_vendors|sort %}
                    <li class="filter-item" id="filter-vendor-{{ sanitize_vendor_id(vendor) }}" onclick="toggleVendorFilter('{{ vendor }}')" style="display:block;">{{ vendor }} ({{ all_sorted_vendors[vendor] }})</li>
                    {% endfor %}
                    {% for vendor in all_vendors_list|sort %}
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
                                if ((parseFloat(card.getAttribute('data-epss')) || 0) <= 0.10) {
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
</body>
</html>
    """

    # Create template and add our custom filter
    template = Template(html_template_str)
    template.globals['sanitize_vendor_id'] = sanitize_vendor_id

    # Calculate statistics
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) > 0.10)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')

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
            'products': cve.get('products', [])
        })

    # Render the template
    html_content = template.render(
        date=datetime.now().strftime('%Y-%m-%d'),
        generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        cve_count=len(formatted_cves),
        high_risk_count=high_risk_count,
        cisa_kev_count=cisa_kev_count,
        epss_high_count=epss_high_count,
        modified_count=modified_count,
        published_count=published_count,
        cves=formatted_cves,
        initial_vendors=initial_vendors,
        all_vendors_list=list(all_sorted_vendors.keys()),
        all_sorted_vendors=all_sorted_vendors
    )

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")


def generate_markdown_report(cves, output_path):
    """Generate Markdown report for archiving"""

    # Count vendor occurrences for summary
    vendor_counts = {}
    for cve in cves:
        for vendor in cve.get('vendors', []):
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort vendors by count (top 10)
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    md_content = f"""# Daily CVE Report - {datetime.now().strftime('%Y-%m-%d')}

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total High-Risk Vulnerabilities: {len(cves)}

## Top Vendors by Vulnerability Count
"""

    # Add vendor summary table
    if sorted_vendors:
        md_content += "| Vendor | Count |\n|--------|-------|\n"
        for vendor, count in sorted_vendors:
            md_content += f"| {vendor} | {count} |\n"
    else:
        md_content += "No vendor information extracted.\n"

    md_content += f"""

---

"""

    for cve in cves:
        md_content += f"## {cve['id']}\n\n"

        # Add metrics
        metrics = []
        if cve.get('cvss_score', 0) > 0:
            metrics.append(f"**CVSS Score:** {cve['cvss_score']:.1f}")
        if cve.get('epss_score', 0) > 0:
            metrics.append(f"**EPSS Score:** {cve['epss_score']:.3f}")
        if cve.get('in_cisa_kev', False):
            metrics.append("**CISA KEV:** Listed")

        # Add entry type
        entry_type = cve.get('entry_type', 'published')
        if entry_type == 'modified':
            metrics.append("**Status:** Recently Updated")
        else:
            metrics.append("**Status:** Newly Published")

        # Add vendors if available
        if cve.get('vendors'):
            vendor_list = ', '.join(cve['vendors'])
            metrics.append(f"**Vendors:** {vendor_list}")

        if metrics:
            md_content += " | ".join(metrics) + "\n\n"

        md_content += f"{cve['description']}\n\n"

        if cve.get('published_date'):
            md_content += f"*Published: {cve['published_date'][:10]}*\n"
        if cve.get('last_modified') and cve.get('last_modified') != cve.get('published_date'):
            md_content += f"*Last Modified: {cve['last_modified'][:10]}*\n"

        md_content += "\n---\n\n"

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md_content)

    print(f"Markdown report generated: {output_path}")