#!/bin/bash
set -euo pipefail

# Only run in remote (Claude Code on the web) sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# Install Node.js dependencies (idempotent — uses npm cache)
npm install

# Restore git remote if GH_PAT env var is set (set it in session environment settings)
if [ -n "${GH_PAT:-}" ]; then
  git remote set-url origin "https://${GH_PAT}@github.com/korhovoyn-sketch/telegramprostir.git" 2>/dev/null || true
fi
