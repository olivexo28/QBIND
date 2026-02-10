#!/bin/bash
#
# QBIND Whitepaper PDF Build Script
#
# This script converts the QBIND whitepaper from Markdown to PDF using pandoc.
#
# Usage:
#   ./build_whitepaper.sh
#
# Requirements:
#   - pandoc (>= 2.0)
#   - pdflatex (from TeX Live or similar LaTeX distribution)
#
# Output:
#   - docs/whitepaper/QBIND_WHITEPAPER.pdf
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${SCRIPT_DIR}/QBIND_WHITEPAPER.md"
OUTPUT_FILE="${SCRIPT_DIR}/QBIND_WHITEPAPER.pdf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  QBIND Whitepaper PDF Build Script"
echo "=========================================="
echo ""

# Check for pandoc
if ! command -v pandoc &> /dev/null; then
    echo -e "${RED}ERROR: pandoc is not installed.${NC}"
    echo ""
    echo "To install pandoc:"
    echo "  - Ubuntu/Debian: sudo apt-get install pandoc"
    echo "  - macOS (Homebrew): brew install pandoc"
    echo "  - Fedora: sudo dnf install pandoc"
    echo "  - Or download from: https://pandoc.org/installing.html"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓${NC} pandoc found: $(pandoc --version | head -n 1)"

# Check for pdflatex (LaTeX engine)
if ! command -v pdflatex &> /dev/null; then
    echo -e "${YELLOW}WARNING: pdflatex is not installed.${NC}"
    echo ""
    echo "To install pdflatex (part of TeX Live):"
    echo "  - Ubuntu/Debian: sudo apt-get install texlive-latex-base texlive-latex-extra texlive-fonts-recommended"
    echo "  - macOS (Homebrew): brew install --cask mactex-no-gui"
    echo "  - Fedora: sudo dnf install texlive-scheme-basic texlive-collection-latexextra"
    echo "  - Or download from: https://www.tug.org/texlive/"
    echo ""
    echo "Attempting to use pandoc's built-in PDF engine (may have limited formatting)..."
    USE_LATEX=false
else
    echo -e "${GREEN}✓${NC} pdflatex found: $(pdflatex --version | head -n 1)"
    USE_LATEX=true
fi

# Check for input file
if [ ! -f "${INPUT_FILE}" ]; then
    echo -e "${RED}ERROR: Input file not found: ${INPUT_FILE}${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Input file found: ${INPUT_FILE}"
echo ""

# Build PDF
echo "Building PDF..."
echo ""

if [ "$USE_LATEX" = true ]; then
    # Use xelatex engine for better Unicode support
    pandoc "${INPUT_FILE}" \
        -o "${OUTPUT_FILE}" \
        --pdf-engine=xelatex \
        -V geometry:margin=1in \
        -V fontsize=11pt \
        -V documentclass=article \
        -V colorlinks=true \
        -V linkcolor=blue \
        -V urlcolor=blue \
        -V toccolor=black \
        --toc \
        --toc-depth=3 \
        -V toc-title="Table of Contents" \
        --highlight-style=tango \
        -V papersize=letter \
        -V mainfont="DejaVu Serif" \
        -V sansfont="DejaVu Sans" \
        -V monofont="DejaVu Sans Mono"
else
    # Fallback: try without LaTeX (produces less polished output)
    # This uses pandoc's built-in HTML-to-PDF conversion if available
    echo -e "${YELLOW}Note: Building without LaTeX. Output quality may be reduced.${NC}"
    
    # Check for wkhtmltopdf as a fallback
    if command -v wkhtmltopdf &> /dev/null; then
        echo "Using wkhtmltopdf as PDF engine..."
        pandoc "${INPUT_FILE}" \
            -o "${OUTPUT_FILE}" \
            --pdf-engine=wkhtmltopdf \
            --toc \
            --toc-depth=3
    else
        echo -e "${RED}ERROR: No PDF engine available.${NC}"
        echo ""
        echo "Please install one of the following:"
        echo "  1. TeX Live (pdflatex) - recommended for best quality"
        echo "  2. wkhtmltopdf - alternative PDF engine"
        echo ""
        exit 1
    fi
fi

# Check if output was created
if [ -f "${OUTPUT_FILE}" ]; then
    echo ""
    echo -e "${GREEN}=========================================="
    echo "  Build successful!"
    echo "===========================================${NC}"
    echo ""
    echo "Output: ${OUTPUT_FILE}"
    echo ""
    
    # Show file size
    FILE_SIZE=$(ls -lh "${OUTPUT_FILE}" | awk '{print $5}')
    echo "File size: ${FILE_SIZE}"
    
    # Show page count if pdfinfo is available
    if command -v pdfinfo &> /dev/null; then
        PAGE_COUNT=$(pdfinfo "${OUTPUT_FILE}" 2>/dev/null | grep "Pages:" | awk '{print $2}')
        if [ -n "${PAGE_COUNT}" ]; then
            echo "Page count: ${PAGE_COUNT}"
        fi
    fi
    
    echo ""
else
    echo -e "${RED}ERROR: PDF generation failed. Output file not created.${NC}"
    exit 1
fi