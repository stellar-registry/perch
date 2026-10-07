#!/usr/bin/env bash
# Run release_stack.rs's cap_sweep over shapes and keep the raw output.
#
#   lab/run.sh <log-name> <shapes> [flows]
#
# <shapes>  PERCH_CAP_SWEEP: `signers,capped,interp,plain,fan,bytes;...`
# [flows]   PERCH_FLOWS: comma-separated WORST_FLOWS indices (default: all 8)
# STACK     stack directory (default target/lab-stack)
#
# Writes lab/results/<log-name>.log. Tabulate with lab/merge.py.
set -u
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
eval "$(scripts/zk-toolchain.sh)"
mkdir -p lab/results
STACK=${STACK:-target/lab-stack}
if [ -n "${3:-}" ]; then export PERCH_FLOWS="$3"; fi
PERCH_KEYS=1 PERCH_STACK_DIR="$STACK" PERCH_CAP_SWEEP="$2" \
  cargo test -q -p perch-integration-tests --test release_stack cap_sweep -- \
  --ignored --nocapture --test-threads 1 > "lab/results/$1.log" 2>&1
echo "exit $? $1"
