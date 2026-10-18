#!/usr/bin/env bash
# Keeps the rustls fork current and vproxy pinned to it.
#
# vproxy builds against a fork of rustls 0.23 (branch reality-0.23) that adds
# ClientConfig::session_id_hook and ClientConfig::client_hello_rewriter.
# Upstream keeps publishing 0.23.x from its rel-0.23 branch, so the fork has
# to follow it. This script, run weekly by .github/workflows/rustls-sync.yml:
#
#   1. fetches upstream rel-0.23 into a clone of the fork;
#   2. if upstream moved: merges it into reality-0.23 (a merge, never a rebase,
#      so every rev that vproxy ever pinned stays reachable), runs the rustls
#      test suite and pushes the fork;
#   3. if the fork head differs from the rev pinned in Cargo.toml: bumps the
#      rev, runs fmt/clippy/tests of vproxy and commits to main;
#   4. on a merge conflict or any other failure opens (or comments on) an issue;
#   5. opens an issue once when upstream publishes rustls 0.24, because then the
#      patches have to be ported to a new branch by hand.
#
# Environment:
#   FORK_REPO        GitHub owner/name of the fork        (maxeliseyev/rustls)
#   FORK_BRANCH      patched branch in the fork           (reality-0.23)
#   UPSTREAM_BRANCH  upstream release branch to follow    (rel-0.23)
#   FORK_DIR         local clone of the fork, created if missing (rustls-fork)
#   FORK_PUSH_URL    where to push the fork; the workflow uses an SSH deploy key
#   DRY_RUN=1        never push, commit or file issues; in merge mode stop after
#                    the rustls tests (the merged rev is not on GitHub yet, so
#                    vproxy cannot be built against it)
#   GH_TOKEN/GH_REPO issues are filed with gh in GH_REPO when GH_TOKEN is set
#
# Exit codes: 0 done or nothing to do, 2 merge conflict (issue filed), 1 error.
set -euo pipefail

FORK_REPO=${FORK_REPO:-maxeliseyev/rustls}
FORK_BRANCH=${FORK_BRANCH:-reality-0.23}
UPSTREAM_BRANCH=${UPSTREAM_BRANCH:-rel-0.23}
FORK_DIR=${FORK_DIR:-rustls-fork}
FORK_PUSH_URL=${FORK_PUSH_URL:-git@github.com:$FORK_REPO.git}
DRY_RUN=${DRY_RUN:-0}
UPSTREAM_URL=https://github.com/rustls/rustls.git
# Keep in sync with .github/workflows/ci.yml.
CLIPPY_FLAGS="-D warnings -A clippy::manual_ignore_case_cmp -A clippy::manual_is_multiple_of -A clippy::len_without_is_empty -A clippy::large_enum_variant"
BOT_NAME="github-actions[bot]"
BOT_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

run_url="${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"
[ -n "${GITHUB_RUN_ID:-}" ] || run_url="(local run)"
conflict_reported=0

log() { printf '\n==> %s\n' "$*"; }
summary() {
    printf '%s\n' "$*"
    [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n\n' "$*" >>"$GITHUB_STEP_SUMMARY"
}

# file_issue TITLE BODY [once]
# Creates an issue, or comments on the open issue with the same title.
# With "once" the issue is created only if no issue with that title ever existed.
file_issue() {
    local title=$1 body=$2 once=${3:-} number
    if [ "$DRY_RUN" = 1 ] || [ -z "${GH_TOKEN:-}" ]; then
        log "Issue not filed (dry run or no GH_TOKEN): $title"
        printf '%s\n' "$body"
        return 0
    fi
    local state=open
    [ "$once" != once ] || state=all
    number=$(gh issue list --state "$state" --search "\"$title\" in:title" --json number,title \
        --jq ".[] | select(.title == \"$title\") | .number" | head -n1)
    if [ -n "$number" ] && [ "$once" = once ]; then
        log "Issue #$number already exists: $title"
    elif [ -n "$number" ]; then
        gh issue comment "$number" --body "$body"
        log "Commented on issue #$number: $title"
    else
        gh issue create --title "$title" --body "$body"
    fi
}

on_exit() {
    local code=$1
    if [ "$code" != 0 ] && [ "$conflict_reported" = 0 ]; then
        file_issue "rustls sync: workflow failed" \
            "The weekly rustls fork sync failed (exit code $code). See the run log: $run_url"
    fi
}
trap 'on_exit $?' EXIT

fork_git() { git -C "$FORK_DIR" "$@"; }

# ---------------------------------------------------------------------------
log "Preparing a clone of $FORK_REPO@$FORK_BRANCH in $FORK_DIR"
if [ ! -d "$FORK_DIR/.git" ]; then
    git clone --quiet --branch "$FORK_BRANCH" "https://github.com/$FORK_REPO.git" "$FORK_DIR"
fi
fork_git remote get-url upstream >/dev/null 2>&1 || fork_git remote add upstream "$UPSTREAM_URL"
fork_git fetch --quiet --tags upstream "$UPSTREAM_BRANCH"
fork_git config user.name "$BOT_NAME"
fork_git config user.email "$BOT_EMAIL"

if [ "$DRY_RUN" != 1 ]; then
    log "Checking push access to $FORK_PUSH_URL"
    git ls-remote --heads "$FORK_PUSH_URL" "$FORK_BRANCH" >/dev/null
fi

# ---------------------------------------------------------------------------
log "Looking for a rustls 0.24 release"
released=$(fork_git tag --list 'v/0.24.*' | grep -vE -- '-(dev|pre|alpha|beta|rc)' || true)
if [ -n "$released" ]; then
    summary "rustls 0.24 is released: $(echo "$released" | tr '\n' ' ')"
    file_issue "rustls 0.24 is out: port the $FORK_BRANCH patches" \
"Upstream published $(echo "$released" | tr '\n' ' ').

tokio-rustls, hyper-rustls and reqwest will move to 0.24 and \`$UPSTREAM_BRANCH\` will only get backports. The fork patches (session_id_hook, client_hello_rewriter, SCT tolerance in CertificateEntry) have to be ported to a new branch on top of 0.24 and vproxy repointed to it.

Filed by $run_url" once
fi

# ---------------------------------------------------------------------------
log "Comparing fork, upstream and the rev pinned in Cargo.toml"
fork_head=$(fork_git rev-parse HEAD)
behind=$(fork_git rev-list --count "HEAD..upstream/$UPSTREAM_BRANCH")
upstream_tag=$(fork_git describe --tags --abbrev=0 "upstream/$UPSTREAM_BRANCH")
pinned=$(grep -E '^rustls = \{ git = "https://github\.com/'"$FORK_REPO"'\.git"' Cargo.toml \
    | sed -nE 's/.*rev = "([0-9a-f]+)".*/\1/p' || true)
if [ -z "$pinned" ]; then
    echo "Cargo.toml has no [patch.crates-io] rustls entry pointing at $FORK_REPO" >&2
    exit 1
fi
echo "fork head:      $fork_head"
echo "pinned rev:     $pinned"
echo "upstream:       $upstream_tag, $behind commit(s) not in the fork"

if [ "$behind" != 0 ]; then
    mode=merge
elif [ "${fork_head#"$pinned"}" != "$fork_head" ]; then
    mode=none
else
    mode=bump
fi
log "Mode: $mode"

# ---------------------------------------------------------------------------
if [ "$mode" = merge ]; then
    log "Merging upstream/$UPSTREAM_BRANCH ($upstream_tag) into $FORK_BRANCH"
    if ! fork_git merge --no-ff --no-edit \
        -m "Merge upstream $UPSTREAM_BRANCH ($upstream_tag) into $FORK_BRANCH" \
        "upstream/$UPSTREAM_BRANCH"; then
        conflicts=$(fork_git diff --name-only --diff-filter=U)
        fork_git merge --abort || true
        summary "Merge conflict with upstream $upstream_tag in: $(echo "$conflicts" | tr '\n' ' ')"
        conflict_reported=1
        file_issue "rustls sync: merge conflict with upstream $UPSTREAM_BRANCH" \
"Upstream \`$UPSTREAM_BRANCH\` ($upstream_tag) does not merge cleanly into \`$FORK_BRANCH\`.

Conflicting files:
\`\`\`
$conflicts
\`\`\`

Resolve by hand in a clone of the fork:
\`\`\`
git fetch upstream
git merge upstream/$UPSTREAM_BRANCH
cargo test -p rustls --locked --all-features --all-targets
git push origin $FORK_BRANCH
\`\`\`
then re-run the sync workflow: it will bump \`rev\` in Cargo.toml and test vproxy.

Run: $run_url"
        exit 2
    fi
    fork_head=$(fork_git rev-parse HEAD)
    echo "merged: $fork_head"

    log "Running the rustls test suite on the merged fork"
    (cd "$FORK_DIR" && cargo test -p rustls --locked --all-features --all-targets)

    if [ "$DRY_RUN" = 1 ]; then
        summary "Dry run: would push $fork_head to $FORK_PUSH_URL and pin it in Cargo.toml"
        exit 0
    fi
    log "Pushing the fork"
    fork_git push "$FORK_PUSH_URL" "HEAD:refs/heads/$FORK_BRANCH"
    summary "Fork merged with upstream $upstream_tag ($behind commits), pushed $fork_head"
fi

# ---------------------------------------------------------------------------
if [ "$mode" != none ]; then
    new=$(fork_git rev-parse --short=8 HEAD)
    log "Pinning rustls rev $new in Cargo.toml"
    sed -i.bak -E 's|(^rustls = \{ git = "https://github\.com/'"$FORK_REPO"'\.git", rev = ")[0-9a-f]+(")|\1'"$new"'\2|' Cargo.toml
    rm -f Cargo.toml.bak
    grep -q "rev = \"$new\"" Cargo.toml
    cargo update --quiet -p rustls
    git --no-pager diff --stat

    log "Testing vproxy against the new fork"
    cargo fmt --check
    # shellcheck disable=SC2086
    cargo clippy --all-targets -- $CLIPPY_FLAGS
    cargo test --locked

    if [ "$DRY_RUN" = 1 ]; then
        summary "Dry run: would commit the bump to $new"
        git --no-pager diff -- Cargo.toml Cargo.lock
        exit 0
    fi
    git config user.name "$BOT_NAME"
    git config user.email "$BOT_EMAIL"
    git add Cargo.toml Cargo.lock
    git commit --quiet -m "Sync rustls fork with upstream $UPSTREAM_BRANCH ($upstream_tag)

Fork $FORK_REPO@$FORK_BRANCH is now at $fork_head.
Merged and tested by $run_url"
    git push origin HEAD:main
    summary "vproxy pinned to rustls fork $new ($upstream_tag), pushed to main"
else
    summary "Nothing to do: fork is at upstream $upstream_tag and Cargo.toml pins its head ($pinned)"
fi
