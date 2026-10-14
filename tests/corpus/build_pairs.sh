#!/bin/sh
# Build named+stripped binary pairs for name-propagation donors.
# Usage: tests/corpus/build_pairs.sh [outdir]   (default tests/corpus/build)
set -e
cd "$(dirname "$0")"
OUT=${1:-build}
mkdir -p "$OUT"
for src in pwcheck.c mixed.c bsd/comm.c bsd/cut.c bsd/ln.c bsd/mkdir.c bsd/rm.c bsd/true.c; do
    n=$(basename "$src" .c)
    cc -O2 -fno-inline -o "$OUT/$n" "$src" || { echo "FAIL $n"; continue; }
    cp "$OUT/$n" "$OUT/${n}-s"
    strip "$OUT/${n}-s"
    echo "ok $n (+stripped)"
done
