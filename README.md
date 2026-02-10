# QBIND Whitepaper

This directory contains the QBIND Protocol Whitepaper and tools for building it into PDF format.

## Contents

| File | Description |
|------|-------------|
| `QBIND_WHITEPAPER.md` | The whitepaper source in GitHub-flavored Markdown |
| `build_whitepaper.sh` | Script to build the PDF from Markdown |
| `QBIND_WHITEPAPER.pdf` | Generated PDF output (after running build script) |

## Editing the Whitepaper

The whitepaper source is in `QBIND_WHITEPAPER.md`. It uses standard GitHub-flavored Markdown with:

- Standard headers (`#`, `##`, `###`, etc.)
- Tables using pipe syntax
- Code blocks with triple backticks
- ASCII diagrams for architecture illustrations

### Section Structure

The whitepaper follows this structure:

1. **Abstract** - Executive summary
2. **Introduction & Background** - Motivation and threat model
3. **Design Goals** - Core principles
4. **System Architecture** - Technical overview
5. **Cryptography & Key Management** - PQC primitives and key handling
6. **Monetary Policy & Fee Model** - Economic design
7. **Security Model** - Threat defenses and slashing
8. **Performance & Benchmarking** - TPS claims and methodology
9. **Governance & Upgrades** - Council model and upgrade process
10. **Roadmap** - Development phases
11. **Wallet & SDK Roadmap** - Developer tools
12. **Layer-2 and Zero-Knowledge Vision** - Future L2/zk plans
13. **Launch Plan & External Audit** - Launch gates
14. **Conclusion** - Summary
15. **References** - Document links

## Building the PDF

### Prerequisites

To build the PDF, you need:

1. **pandoc** (version 2.0 or later)
2. **TeX Live** (or another LaTeX distribution with `pdflatex`)

#### Installing on Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install pandoc texlive-latex-base texlive-latex-extra texlive-fonts-recommended
```

#### Installing on macOS (Homebrew)

```bash
brew install pandoc
brew install --cask mactex-no-gui
```

#### Installing on Fedora

```bash
sudo dnf install pandoc texlive-scheme-basic texlive-collection-latexextra
```

### Building

Run the build script:

```bash
cd docs/whitepaper
chmod +x build_whitepaper.sh
./build_whitepaper.sh
```

The script will:
1. Check for required tools (pandoc, pdflatex)
2. Convert the Markdown to PDF
3. Generate `QBIND_WHITEPAPER.pdf` in this directory

### Output

The generated PDF will be located at:

```
docs/whitepaper/QBIND_WHITEPAPER.pdf
```

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | February 2026 | Initial whitepaper release (T240) |

## Related Documents

For detailed technical specifications, see:

- [MainNet v0 Specification](../mainnet/QBIND_MAINNET_V0_SPEC.md)
- [Monetary Policy Design](../econ/QBIND_MONETARY_POLICY_DESIGN.md)
- [Key Management Design](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md)
- [Governance & Upgrades Design](../gov/QBIND_GOVERNANCE_AND_UPGRADES_DESIGN.md)
- [Slashing & PQC Offenses Design](../consensus/QBIND_SLASHING_AND_PQC_OFFENSES_DESIGN.md)
- [External Security Audit RFP](../audit/QBIND_EXTERNAL_SECURITY_AUDIT_RFP.md)

## Contributing

When updating the whitepaper:

1. Edit `QBIND_WHITEPAPER.md` directly
2. Ensure all cross-references to other documents are accurate
3. Run `./build_whitepaper.sh` to verify the PDF builds correctly
4. Commit the `.md` source (the PDF is a build artifact and excluded from version control)