#!/bin/bash
#
# QBIND Whitepaper PDF Build Script
#
# This script builds QBIND whitepaper PDFs.
#
# Usage:
#   ./build_whitepaper.sh         # Build v1 (Markdown -> PDF via pandoc)
#   ./build_whitepaper.sh v1      # Build v1 (same as default)
#   ./build_whitepaper.sh v2      # Build v2 (LaTeX -> PDF via pdflatex)
#
# Requirements:
#   - For v1: pandoc (>= 2.0), pdflatex (from TeX Live or similar LaTeX distribution)
#   - For v2: pdflatex or xelatex (from TeX Live or similar LaTeX distribution)
#
# Output:
#   - v1: docs/whitepaper/QBIND_WHITEPAPER.pdf
#   - v2: docs/whitepaper_v2/qbind_whitepaper_v2.pdf
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Parse command line argument for version
BUILD_VERSION="${1:-v1}"

# v1 paths (Markdown-based whitepaper)
V1_INPUT_FILE="${SCRIPT_DIR}/QBIND_WHITEPAPER.md"
V1_OUTPUT_FILE="${SCRIPT_DIR}/QBIND_WHITEPAPER.pdf"

# v2 paths (LaTeX-based whitepaper)
V2_DIR="${REPO_ROOT}/docs/whitepaper_v2"
V2_INPUT_FILE="${V2_DIR}/qbind_whitepaper_v2.tex"
V2_OUTPUT_FILE="${V2_DIR}/qbind_whitepaper_v2.pdf"

# For backward compatibility with existing scripts
INPUT_FILE="${V1_INPUT_FILE}"
OUTPUT_FILE="${V1_OUTPUT_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  QBIND Whitepaper PDF Build Script"
echo "=========================================="
echo ""

# ==============================================================================
# Build v1 whitepaper (Markdown -> PDF via pandoc)
# ==============================================================================
build_v1() {
    echo "Building v1 whitepaper (Markdown -> PDF via pandoc)..."
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
    if [ ! -f "${V1_INPUT_FILE}" ]; then
        echo -e "${RED}ERROR: Input file not found: ${V1_INPUT_FILE}${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Input file found: ${V1_INPUT_FILE}"
    echo ""

    # Build PDF
    echo "Building PDF..."
    echo ""

    if [ "$USE_LATEX" = true ]; then
        # Use xelatex engine for better Unicode support
        pandoc "${V1_INPUT_FILE}" \
            -o "${V1_OUTPUT_FILE}" \
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
            pandoc "${V1_INPUT_FILE}" \
                -o "${V1_OUTPUT_FILE}" \
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
    check_output "${V1_OUTPUT_FILE}"
}

# ==============================================================================
# Build v2 whitepaper (LaTeX -> PDF via pdflatex)
#
# The v2 whitepaper is a LaTeX-based document located at:
#   docs/whitepaper_v2/qbind_whitepaper_v2.tex
#
# It includes v2 section files from:
#   docs/whitepaper_v2/sections/01_executive_summary.tex
#   docs/whitepaper_v2/sections/02_system_overview.tex
#   docs/whitepaper_v2/sections/03_execution_and_state.tex
#
# Output:
#   docs/whitepaper_v2/qbind_whitepaper_v2.pdf
#
# Example:
#   ./build_whitepaper.sh v2
# ==============================================================================
build_v2() {
    echo "Building v2 whitepaper (LaTeX -> PDF via pdflatex)..."
    echo ""
    
    # Check for pdflatex
    if ! command -v pdflatex &> /dev/null; then
        echo -e "${RED}ERROR: pdflatex is not installed.${NC}"
        echo ""
        echo "To install pdflatex (part of TeX Live):"
        echo "  - Ubuntu/Debian: sudo apt-get install texlive-latex-base texlive-latex-extra texlive-fonts-recommended"
        echo "  - macOS (Homebrew): brew install --cask mactex-no-gui"
        echo "  - Fedora: sudo dnf install texlive-scheme-basic texlive-collection-latexextra"
        echo "  - Or download from: https://www.tug.org/texlive/"
        echo ""
        exit 1
    fi

    echo -e "${GREEN}✓${NC} pdflatex found: $(pdflatex --version | head -n 1)"

    # Check for input file
    if [ ! -f "${V2_INPUT_FILE}" ]; then
        echo -e "${RED}ERROR: Input file not found: ${V2_INPUT_FILE}${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Input file found: ${V2_INPUT_FILE}"
    echo ""

    # Build PDF using pdflatex (run twice for ToC/refs)
    echo "Building PDF (pass 1 of 2)..."
    (cd "${V2_DIR}" && pdflatex -interaction=nonstopmode -halt-on-error qbind_whitepaper_v2.tex) || {
        echo -e "${RED}ERROR: pdflatex pass 1 failed.${NC}"
        exit 1
    }
    
    echo ""
    echo "Building PDF (pass 2 of 2 for ToC/refs)..."
    (cd "${V2_DIR}" && pdflatex -interaction=nonstopmode -halt-on-error qbind_whitepaper_v2.tex) || {
        echo -e "${RED}ERROR: pdflatex pass 2 failed.${NC}"
        exit 1
    }

    # Check if output was created
    check_output "${V2_OUTPUT_FILE}"
    
    # Clean up auxiliary files (optional, keep them by default for debugging)
    # rm -f "${V2_DIR}"/*.aux "${V2_DIR}"/*.log "${V2_DIR}"/*.out "${V2_DIR}"/*.toc
}

# ==============================================================================
# Helper function: Check if output was created and report success
# ==============================================================================
check_output() {
    local output_file="$1"
    
    if [ -f "${output_file}" ]; then
        echo ""
        echo -e "${GREEN}=========================================="
        echo "  Build successful!"
        echo "===========================================${NC}"
        echo ""
        echo "Output: ${output_file}"
        echo ""
        
        # Show file size
        FILE_SIZE=$(ls -lh "${output_file}" | awk '{print $5}')
        echo "File size: ${FILE_SIZE}"
        
        # Show page count if pdfinfo is available
        if command -v pdfinfo &> /dev/null; then
            PAGE_COUNT=$(pdfinfo "${output_file}" 2>/dev/null | grep "Pages:" | awk '{print $2}')
            if [ -n "${PAGE_COUNT}" ]; then
                echo "Page count: ${PAGE_COUNT}"
            fi
        fi
        
        echo ""
    else
        echo -e "${RED}ERROR: PDF generation failed. Output file not created.${NC}"
        exit 1
    fi
}

# ==============================================================================
# Main: Dispatch to the appropriate build function based on version argument
# ==============================================================================
case "${BUILD_VERSION}" in
    v1|V1|"")
        echo "Target: v1 (Markdown whitepaper)"
        echo ""
        build_v1
        ;;
    v2|V2)
        echo "Target: v2 (LaTeX whitepaper)"
        echo ""
        build_v2
        ;;
    *)
        echo -e "${RED}ERROR: Unknown version '${BUILD_VERSION}'.${NC}"
        echo ""
        echo "Usage:"
        echo "  ./build_whitepaper.sh         # Build v1 (default)"
        echo "  ./build_whitepaper.sh v1      # Build v1 (Markdown -> PDF via pandoc)"
        echo "  ./build_whitepaper.sh v2      # Build v2 (LaTeX -> PDF via pdflatex)"
        echo ""
        exit 1
        ;;
esac