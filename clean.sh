#!/bin/bash
# Clean temporary files and caches

echo "Cleaning temporary files..."

# Remove Python cache files
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
find . -type f -name "*.pyo" -delete

# Remove test files
rm -f test_report.html test_report.md

# Show what's left
echo "Project cleaned. Remaining files:"
find . -maxdepth 2 -type f | grep -v "venv/" | sort