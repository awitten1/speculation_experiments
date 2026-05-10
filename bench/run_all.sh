#!/bin/bash
set -euo pipefail

TARGET="${TARGET:-0xa5}"
TRIALS="${TRIALS:-10000}"
CPU="${CPU:-0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/bench/results.csv}"

threshold="${THRESHOLD:-200}"
echo "threshold=$threshold" >&2

echo "variant,trial,outcome,leaked_value" > "$OUT"

run_variant() {
    local name="$1" bin="$2"
    shift 2
    echo "running $name..." >&2
    "$bin" --bench-byte "$TARGET" --trials "$TRIALS" --threshold "$threshold" --cpu "$CPU" "$@" \
        | tail -n +2 >> "$OUT"
}

run_variant v1       "$ROOT/spectre_v1/spectre_v1_bounds_bypass"
run_variant v1-flush "$ROOT/spectre_v1/spectre_v1_bounds_bypass" --flush-target
run_variant v2       "$ROOT/spectre_v2/spectre_v2_branch_poison"
run_variant v2-flush "$ROOT/spectre_v2/spectre_v2_branch_poison" --flush-target
run_variant rsb       "$ROOT/spectre-rsb/main"
run_variant rsb-flush "$ROOT/spectre-rsb/main" --flush-target

echo "wrote $OUT" >&2

awk -F, 'NR>1 {tot[$1]++; if ($3=="correct") c[$1]++; else if ($3=="wrong") w[$1]++; else u[$1]++}
         END {printf "%-6s %8s %8s %8s %8s\n", "var", "trials", "correct", "wrong", "unknown";
              for (v in tot) printf "%-6s %8d %7.2f%% %7.2f%% %7.2f%%\n",
                  v, tot[v], 100*c[v]/tot[v], 100*w[v]/tot[v], 100*u[v]/tot[v]}' "$OUT"
