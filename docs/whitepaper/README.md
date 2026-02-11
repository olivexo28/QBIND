# QBIND Whitepaper

This directory contains the QBIND technical whitepaper and related assets.

## Contents

- `QBIND_WHITEPAPER.md` - Main whitepaper document
- `diagrams/` - Architecture and system diagrams
- `build.sh` - Script to build PDF version using pandoc

## Building the PDF

Prerequisites:
- pandoc
- xelatex (texlive-xetex)

Run:
```bash
./build.sh
```

This will generate `QBIND_WHITEPAPER.pdf` in the current directory.

## Version Control

Changes to the whitepaper must follow versioning discipline:
- Never edit previous sections casually
- Changes must be versioned
- Increment version in header (e.g., Draft v2.1)
