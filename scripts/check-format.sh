#!/usr/bin/env bash
set -euo pipefail

unformatted=""
for module in server client; do
  files=$(rg --files "$module" -g '*.go')
  if [ -n "$files" ]; then
    module_unformatted=$(gofmt -l $files)
    if [ -n "$module_unformatted" ]; then
      unformatted="$unformatted$module_unformatted\n"
    fi
  fi
done

if [ -n "$unformatted" ]; then
  printf 'gofmt required for:\n%b' "$unformatted" >&2
  exit 1
fi
echo "Go formatting clean"
