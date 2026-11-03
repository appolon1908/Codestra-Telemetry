#!/usr/bin/env bash
set -eo pipefail
die(){ echo "GOVERNANCE_FAIL: $*" >&2; exit 1; }
active=$(tr -d '\r\n' < .codestra/active-lane); expected=$(cat .codestra/expected-origin); origin=$(git remote get-url origin)
[ "$origin" = "$expected" ] || die "wrong origin"; git fetch --quiet origin main || die "fetch failed"; base=$(git rev-parse origin/main); b=$(git branch --show-current); mode=local; [ "$1" = "--ci" ] && mode=ci
if [ "$mode" = local ]; then [ -n "$b" ] || die "detached"; [ "$b" != main ] || die "main forbidden"; [ "$b" = "$active" ] || die "wrong branch"; [ -z "$(git status --porcelain)" ] || die "dirty start"; fi
if [ "$mode" = ci ] && [ "$GITHUB_EVENT_NAME" = pull_request ]; then [ "$GITHUB_HEAD_REF" = "$active" ] || die "wrong PR head"; fi
git merge-base --is-ancestor "$base" HEAD || die "stale branch"
scan=$(git diff --unified=0 origin/main...HEAD || true)
echo "$scan"|grep -E '^\+.*(PRODUCTION_GO|LIVE_EFFECTS|ALLOW_PRODUCTION_EFFECTS)[[:space:]]*[:=][[:space:]]*(true|1|yes|on)' >/dev/null && die "production effects enabled"
echo "$scan"|grep -Ei '^\+.*((/metrics|/internal).*(public|internet|0\.0\.0\.0)|(public|internet|0\.0\.0\.0).*(/metrics|/internal))' >/dev/null && die "public metrics/internal route"
echo "$scan"|grep -Ei '^\+.*(x-bypass-auth|x-disable-auth|x-skip-auth|authorization:[[:space:]]*none)' >/dev/null && die "auth bypass"
echo "GOVERNANCE_OK active=$active base=$base head=$(git rev-parse HEAD)"
