#!/bin/bash
BASE="$(cd "$(dirname "$0")" && pwd)"; export REPO_ROOT="$BASE"
PASS=0; FAIL=0; FAILED_TESTS=""
CA="$BASE/agents/1_collect_agent"
AA="$BASE/agents/2_analysis_agent"
AN="$BASE/agents/3_anonymization_detection_agent"
DE="$BASE/agents/4_decision_agent"

run_test() {
    local name="$1"; local dir="$2"; local file="$3"; local extra="$4"
    cd "$dir"
    PYTHONPATH="$dir:$extra" timeout 120 python3 "$file" > /tmp/test_out.txt 2>&1
    local rc=$?
    if [ $rc -eq 0 ] && ! grep -qiE "ECHEC|FAILED|Traceback|ImportError|ModuleNotFound" /tmp/test_out.txt; then
        echo "  [OK] $name"; PASS=$((PASS+1))
    else
        echo "  [✗] $name"; FAIL=$((FAIL+1)); FAILED_TESTS="$FAILED_TESTS\n    - $name"
    fi
}

echo "========================================================================"
echo "  BILAN COMPLET DE TOUS LES TESTS DU SYSTÈME"
echo "========================================================================"
echo ""; echo "### NIVEAU 1 — COLLECT ###"
for f in "$CA"/tests/*.py; do run_test "$(basename $f)" "$CA" "$f"; done
echo ""; echo "### NIVEAU 1 — ANALYSIS ###"
for f in "$AA"/tests/*.py; do run_test "$(basename $f)" "$AA" "$f"; done
echo ""; echo "### NIVEAU 1 — ANONYMIZATION ###"
for f in "$AN"/tests/*.py; do run_test "$(basename $f)" "$AN" "$f"; done
echo ""; echo "### NIVEAU 1 — DECISION ###"
for f in "$DE"/tests/*.py; do run_test "$(basename $f)" "$DE" "$f"; done
echo ""; echo "### COUCHE AGENTIQUE ###"
for f in "$BASE"/agentic_layer/tests/*.py; do run_test "$(basename $f)" "$BASE/agentic_layer" "$f" "$CA:$AA:$AN:$DE"; done
echo ""; echo "### COUCHE CLOUD ###"
for f in "$BASE"/cloud_adapter/tests/*.py; do run_test "$(basename $f)" "$BASE/cloud_adapter" "$f" "$CA:$AA"; done
echo ""
echo "========================================================================"
echo "  RÉSULTAT : $PASS réussis / $((PASS+FAIL)) tests"
if [ $FAIL -gt 0 ]; then echo -e "  Échecs restants:$FAILED_TESTS"; else echo "  ✅ TOUS LES TESTS PASSENT"; fi
echo "========================================================================"
