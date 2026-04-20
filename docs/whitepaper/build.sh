#!/bin/bash
pandoc QBIND_WHITEPAPER.md \
  -o QBIND_WHITEPAPER.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=1in