#!/bin/sh
set -eu

source_dir=${1:?source directory is required}
destination_dir=${2:?destination directory is required}

test -f "$source_dir/index.html"
mkdir -p "$destination_dir"

# The destination is a generated, repository-local embed staging directory.
# Keep only its tracked placeholder before copying the fresh hashed assets.
find "$destination_dir" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
cp -R "$source_dir"/. "$destination_dir"/
