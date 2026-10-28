#!/usr/bin/env bash
# pull-model.sh — pull an Ollama model with state-file lifecycle.
#
# Usage: pull-model.sh <model-id>
#
# State files written under $OPENJARVIS_HOME/.state/models/:
#   <model>.downloading  — created on start
#   <model>.ready        — on success (atomic rename)
#   <model>.failed       — on failure after retries
#   <model>.log          — captured stderr

set -euo pipefail

MODEL="${1:-}"
if [[ -z "$MODEL" ]]; then
    echo "usage: pull-model.sh <model-id>" >&2
    exit 2
fi

OPENJARVIS_HOME="${OPENJARVIS_HOME:-$HOME/.openjarvis}"
STATE_DIR="$OPENJARVIS_HOME/.state/models"
mkdir -p "$STATE_DIR"

# Windows treats ':' in a filename as an alternate data stream. Keep the
# Ollama model ID unchanged for the command, but encode it in marker paths.
STATE_MODEL="$MODEL"
case "${OSTYPE:-}" in
    msys*|cygwin*|win32*) STATE_MODEL="${MODEL//:/%3A}" ;;
esac
DOWNLOADING="$STATE_DIR/${STATE_MODEL}.downloading"
READY="$STATE_DIR/${STATE_MODEL}.ready"
FAILED="$STATE_DIR/${STATE_MODEL}.failed"
LOG="$STATE_DIR/${STATE_MODEL}.log"

# Cleanup any prior state for this model.
rm -f "$READY" "$FAILED"
touch "$DOWNLOADING"

MAX_RETRIES=3
attempt=0
last_exit=0

while [[ $attempt -lt $MAX_RETRIES ]]; do
    attempt=$((attempt + 1))
    if ollama pull "$MODEL" >>"$LOG" 2>&1; then
        # Atomic rename: write to .tmp then mv.
        tmp="$STATE_DIR/${MODEL}.ready.tmp"
        date -u +"%Y-%m-%dT%H:%M:%SZ" > "$tmp"
        mv "$tmp" "$READY"
        rm -f "$DOWNLOADING"
        exit 0
    else
        last_exit=$?
    fi
done

# All retries exhausted.
{
    echo "pull-model.sh: $MODEL failed after $MAX_RETRIES attempts (exit=$last_exit)"
    tail -n 50 "$LOG" 2>/dev/null || true
} > "$FAILED"
rm -f "$DOWNLOADING"
exit "$last_exit"
