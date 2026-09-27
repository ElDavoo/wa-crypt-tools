#!/usr/bin/env bash
#
# The checks an agent must pass before its work is worth pushing — this repository's lint, its
# tests, whatever else CI would refuse the branch for.
#
# REPLACE THE BODY. What ships here succeeds and does nothing, so the pipeline runs end to end
# before you have configured anything.
#
# This is a script and not a composite action on purpose, and the reason decides it: the agent
# is told to run these itself, mid-turn, before it finishes. A composite action cannot be
# invoked from inside a prompt. A script is the only form both the workflow and the agent can
# reach, which is what stops them drifting into two different definitions of "passing" — the
# failure where CI rejects a branch for a gate the agent was never able to run.
#
# Contract:
#   - exit 0 if everything passed, non-zero otherwise
#   - print enough on failure to diagnose from, on stdout or stderr
#   - be runnable from a clean checkout after project-setup has run, and from the agent's
#     working tree mid-change
#   - be cheap. It runs on every fix round, and once more inside each of them.
#
# Put the *fast* gates here — the ones worth failing before a push. Slow legs (an emulator
# matrix, a full release build) belong in CI, where the fix loop picks their failures up from
# the logs.

set -uo pipefail

failed=0

# Runs one gate, keeps going after a failure, and reports all of them rather than only the
# first. An agent that is shown one failure at a time spends one round per gate.
gate() {
  local name=$1; shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    printf '%s: passed\n' "$name"
  else
    printf '%s: FAILED\n' "$name"
    failed=1
  fi
}

# CI's lint job, minus the advisory mypy leg. The rule set is not repeated here -- it lives in
# [tool.ruff.lint] in pyproject.toml, which both this and CI read, so the two cannot drift into
# different definitions of "lint passes". That drift is exactly what the old copy of flake8's
# `--select=E9,F63,F7,F82` invited.
gate ruff ruff check .
gate "ruff format" ruff format --check .

# pytest must run from the repo root: tests/test_*.py open fixtures by relative path
# (tests/res/...), and tests/tools-invocation/ shells out to the installed console scripts
# (wacreatekey, ...) by bare name, which project-setup's editable install puts on PATH.
gate pytest python -m pytest -q

if [ "$failed" -ne 0 ]; then
  printf '\nOne or more gates failed.\n'
  exit 1
fi

printf '\nAll gates passed.\n'
