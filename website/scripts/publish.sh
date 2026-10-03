#!/usr/bin/env bash
# Produces the site into docs/, the directory GitHub Pages serves from main
# (the same arrangement as agents-exe). Commit the result: docs/ is the
# published site, website/src/ is its source.
set -euo pipefail
cd "$(dirname "$0")/../.."  # repo root
mkdir -p docs/{audios,css,docs,gen/images,gen/out,hashtags,images,js,json,raw,text,topics,videos}
kitchen-sink produce --srcDir website/src --outDir docs
echo "produced $(ls docs/*.html | wc -l) pages into docs/"
