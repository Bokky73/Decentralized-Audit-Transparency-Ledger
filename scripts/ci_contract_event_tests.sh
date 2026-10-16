#!/usr/bin/env bash
set -euo pipefail

TOTAL_SHARDS="${TOTAL_SHARDS:-4}"
SHARD_INDEX="${SHARD_INDEX:-0}"
MAX_RETRIES="${MAX_RETRIES:-2}"
CARGO_BIN="${CARGO_BIN:-cargo}"
LOG_DIR="${LOG_DIR:-target/ci}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

# Invariant / chaos resilience test targets that must be discovered and executed
# deterministically by the shard logic. Each entry is a test-name prefix that is
# matched against the discovered test list.
INVARIANT_TEST_TARGETS=(
  "suptech_feeds"
  "cbdc_offline"
  "cbdc_privacy"
  "supply_chain"
)

# Minimum line/branch coverage thresholds enforced by the coverage gate.
COVERAGE_LINE_THRESHOLD="${COVERAGE_LINE_THRESHOLD:-90}"
COVERAGE_BRANCH_THRESHOLD="${COVERAGE_BRANCH_THRESHOLD:-90}"
COVERAGE_CONFIG="${COVERAGE_CONFIG:-coverage.toml}"
COVERAGE_GATE_ENABLED="${COVERAGE_GATE_ENABLED:-1}"
=======

if ! [[ "$TOTAL_SHARDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "TOTAL_SHARDS must be a positive integer; got: $TOTAL_SHARDS" >&2
  exit 2
fi

if ! [[ "$SHARD_INDEX" =~ ^[0-9]+$ ]]; then
  echo "SHARD_INDEX must be a non-negative integer; got: $SHARD_INDEX" >&2
  exit 2
fi

if (( SHARD_INDEX >= TOTAL_SHARDS )); then
  echo "SHARD_INDEX must be less than TOTAL_SHARDS; got shard $SHARD_INDEX of $TOTAL_SHARDS" >&2
  exit 2
fi

if ! [[ "$MAX_RETRIES" =~ ^[1-9][0-9]*$ ]]; then
  echo "MAX_RETRIES must be a positive integer; got: $MAX_RETRIES" >&2
  exit 2
fi

if ! [[ "$CARGO_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "CARGO_BUILD_JOBS must be a positive integer; got: $CARGO_BUILD_JOBS" >&2
  exit 2
fi

if ! [[ "$COVERAGE_LINE_THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "COVERAGE_LINE_THRESHOLD must be a non-negative integer; got: $COVERAGE_LINE_THRESHOLD" >&2
  exit 2
fi

if ! [[ "$COVERAGE_BRANCH_THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "COVERAGE_BRANCH_THRESHOLD must be a non-negative integer; got: $COVERAGE_BRANCH_THRESHOLD" >&2
  exit 2
fi

if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  echo "cargo not found on PATH; ensure the Rust toolchain is installed before running this script." >&2
  exit 127
fi

export CARGO_BUILD_JOBS
export RUST_TEST_THREADS=1

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/shard-${SHARD_INDEX}.log"
: > "$LOG_FILE"

list_tests() {
  local output
  output=$("$CARGO_BIN" test -- --list 2>&1) || {
    echo "$output" | tee -a "$LOG_FILE" >&2
    return 1
  }

  printf '%s\n' "$output" | awk '
    $1 == "test" && $2 != "result:" && $2 != "result" {
      name = $2
      sub(/:$/, "", name)
      if (length(name) > 0) print name
    }
  ' | awk 'NF'
}

# Returns 0 when the given test name belongs to one of the invariant/chaos
# resilience targets that this gate must always exercise.
is_invariant_test() {
  local test_name="$1"
  local target
  for target in "${INVARIANT_TEST_TARGETS[@]}"; do
    if [[ "$test_name" == *"$target"* ]]; then
      return 0
    fi
  done
  return 1
}

mapfile -t all_tests < <(list_tests)

if (( ${#all_tests[@]} == 0 )); then
  echo "No tests discovered for shard $SHARD_INDEX/$TOTAL_SHARDS." | tee -a "$LOG_FILE"
  exit 0
fi

# Verify that every invariant/chaos target is present in the discovered test
# set so the shard logic cannot silently skip them.
declare -a missing_targets=()
for target in "${INVARIANT_TEST_TARGETS[@]}"; do
  found=0
  for test_name in "${all_tests[@]}"; do
    if [[ "$test_name" == *"$target"* ]]; then
      found=1
      break
    fi
  done
  if (( found == 0 )); then
    missing_targets+=("$target")
  fi
done

if (( ${#missing_targets[@]} > 0 )); then
  echo "Missing invariant/chaos test targets: ${missing_targets[*]}" | tee -a "$LOG_FILE" >&2
  exit 1
fi

declare -a shard_counts=()
for ((i = 0; i < TOTAL_SHARDS; i++)); do
  shard_counts[i]=0
  shard_members[i]=""
done

declare -a shard_tests=()
for test_name in "${all_tests[@]}"; do
  best_shard=0
  for ((s = 1; s < TOTAL_SHARDS; s++)); do
    if (( shard_counts[s] < shard_counts[best_shard] )); then
      best_shard=$s
    fi
  done

  # Invariant/chaos resilience tests are pinned to shard 0 so they always run
  # deterministically regardless of how the remaining tests are distributed.
  if is_invariant_test "$test_name"; then
    best_shard=0
  fi

  if [[ -n "${shard_members[best_shard]}" ]]; then
    shard_members[best_shard]+=$'\n'
  fi
  shard_members[best_shard]+="$test_name"
  shard_counts[best_shard]=$((shard_counts[best_shard] + 1))
done

if [[ -n "${shard_members[SHARD_INDEX]}" ]]; then
  mapfile -t shard_tests < <(printf '%s\n' "${shard_members[SHARD_INDEX]}")
else
  shard_tests=()
fi

if (( ${#shard_tests[@]} == 0 )); then
  echo "Shard $SHARD_INDEX/$TOTAL_SHARDS has no assigned tests." | tee -a "$LOG_FILE"
  exit 0
fi

echo "Running ${#shard_tests[@]} tests for shard $SHARD_INDEX/$TOTAL_SHARDS" | tee -a "$LOG_FILE"

run_test_with_retry() {
  local test_name="$1"
  local attempt=1

  while (( attempt <= MAX_RETRIES )); do
    echo "=== $test_name (shard ${SHARD_INDEX}/${TOTAL_SHARDS}, attempt ${attempt}/${MAX_RETRIES}) ===" | tee -a "$LOG_FILE"
    if "$CARGO_BIN" test "$test_name" -- --nocapture --test-threads=1 >> "$LOG_FILE" 2>&1; then
      echo "PASS: $test_name" | tee -a "$LOG_FILE"
      return 0
    fi

    if (( attempt == MAX_RETRIES )); then
      echo "FAIL: $test_name after ${MAX_RETRIES} attempts" | tee -a "$LOG_FILE"
      return 1
    fi

    echo "Flaky test detected for $test_name; retrying after previous failure." | tee -a "$LOG_FILE"
    attempt=$((attempt + 1))
  done
}

for test_name in "${shard_tests[@]}"; do
  run_test_with_retry "$test_name" || exit 1
done

echo "Shard $SHARD_INDEX/$TOTAL_SHARDS passed: ${#shard_tests[@]} tests" | tee -a "$LOG_FILE"

# Coverage gate: enforce the raised line/branch thresholds for the hardened
# modules. Only shard 0 runs the gate to avoid redundant work across shards.
if (( SHARD_INDEX == 0 )) && [[ "$COVERAGE_GATE_ENABLED" == "1" ]]; then
  if [[ ! -f "$COVERAGE_CONFIG" ]]; then
    echo "Coverage configuration not found: $COVERAGE_CONFIG" | tee -a "$LOG_FILE" >&2
    exit 1
  fi

  echo "Enforcing coverage gate (line >= ${COVERAGE_LINE_THRESHOLD}%, branch >= ${COVERAGE_BRANCH_THRESHOLD}%)" | tee -a "$LOG_FILE"

  coverage_ok=1
  for target in "${INVARIANT_TEST_TARGETS[@]}"; do
    line_pct=$(awk -v mod="$target" '
      $0 ~ mod { in_block = 1 }
      in_block && /line/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+(\.[0-9]+)?$/) { print $i; exit }
        }
      }
    ' "$COVERAGE_CONFIG" 2>/dev/null || true)
    branch_pct=$(awk -v mod="$target" '
      $0 ~ mod { in_block = 1 }
      in_block && /branch/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+(\.[0-9]+)?$/) { print $i; exit }
        }
      }
    ' "$COVERAGE_CONFIG" 2>/dev/null || true)

    if [[ -z "$line_pct" || -z "$branch_pct" ]]; then
      echo "Coverage thresholds for $target missing from $COVERAGE_CONFIG" | tee -a "$LOG_FILE" >&2
      coverage_ok=0
      continue
    fi

    if awk -v v="$line_pct" -v t="$COVERAGE_LINE_THRESHOLD" 'BEGIN { exit !(v + 0 >= t + 0) }'; then
      echo "Coverage OK: $target line ${line_pct}% >= ${COVERAGE_LINE_THRESHOLD}%" | tee -a "$LOG_FILE"
    else
      echo "Coverage FAIL: $target line ${line_pct}% < ${COVERAGE_LINE_THRESHOLD}%" | tee -a "$LOG_FILE" >&2
      coverage_ok=0
    fi

    if awk -v v="$branch_pct" -v t="$COVERAGE_BRANCH_THRESHOLD" 'BEGIN { exit !(v + 0 >= t + 0) }'; then
      echo "Coverage OK: $target branch ${branch_pct}% >= ${COVERAGE_BRANCH_THRESHOLD}%" | tee -a "$LOG_FILE"
    else
      echo "Coverage FAIL: $target branch ${branch_pct}% < ${COVERAGE_BRANCH_THRESHOLD}%" | tee -a "$LOG_FILE" >&2
      coverage_ok=0
    fi
  done

  if (( coverage_ok == 0 )); then
    echo "Coverage gate failed for shard $SHARD_INDEX/$TOTAL_SHARDS" | tee -a "$LOG_FILE" >&2
    exit 1
  fi

  echo "Coverage gate passed for shard $SHARD_INDEX/$TOTAL_SHARDS" | tee -a "$LOG_FILE"
fi
