#!/usr/bin/env bash
# Computes the full multi-instance desktop dev environment.
# Source this file from desktop dev commands; it exports:
#   BUZZ_VITE_PORT, BUZZ_HMR_PORT, VITE_PORT, VITE_HMR_PORT
#   BUZZ_RELAY_PORT, BUZZ_RELAY_URL
#   BUZZ_INSTANCE_SLUG, BUZZ_WORKTREE_LABEL, VITE_DEV_BRANCH (worktrees only)
#   BUZZ_DEV_PROFILE, VITE_DEV_PROFILE (explicit profiles only)
#   BUZZ_DEV_KEYRING_SERVICE (explicit profiles only)
#   BUZZ_TAURI_CONFIG
#   BUZZ_PRIVATE_KEY (worktrees only, when BUZZ_SHARE_IDENTITY=1)

WORKTREE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

EXPLICIT_PROFILE="${BUZZ_DEV_PROFILE:-}"
if [[ -n "$EXPLICIT_PROFILE" && ! "$EXPLICIT_PROFILE" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]]; then
    echo "instance-env: BUZZ_DEV_PROFILE must be a lowercase slug of 1-32 letters, digits, or hyphens" >&2
    return 1 2>/dev/null || exit 1
fi

BASE_INSTANCE_SLUG=""
INSTANCE_LABEL=""
unset VITE_DEV_BRANCH
unset VITE_DEV_PROFILE

# In worktrees, extract a label from the branch name and derive a unique app
# identity and icon so multiple local desktop instances can run side by side.
#
# Worktree detection: compare --git-dir to --git-common-dir. In the main
# working tree these are identical; in any worktree (whether under .worktrees/,
# .claude/worktrees/, or elsewhere on disk) they differ.
if git rev-parse --is-inside-work-tree &>/dev/null; then
    GIT_DIR=$(git rev-parse --git-dir)
    GIT_COMMON_DIR=$(git rev-parse --git-common-dir 2>/dev/null)
    if [[ -n "$GIT_COMMON_DIR" && "$GIT_DIR" != "$GIT_COMMON_DIR" ]]; then
        BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
        export BUZZ_WORKTREE_LABEL="${BRANCH_NAME##*/}"
        BASE_INSTANCE_SLUG=$(echo "$BRANCH_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//')
        INSTANCE_LABEL="$BUZZ_WORKTREE_LABEL"
        export VITE_DEV_BRANCH="$BUZZ_WORKTREE_LABEL"

        # BUZZ_SHARE_IDENTITY=1: reuse the main dev checkout's Nostr key so
        # worktrees skip onboarding and share the same identity. The per-worktree
        # identifier is kept so concurrent instances don't collide on
        # tauri-plugin-single-instance or the app data directory.
        if [[ "${BUZZ_SHARE_IDENTITY:-0}" == "1" ]]; then
            CANONICAL_KEY="$HOME/Library/Application Support/xyz.block.buzz.app.dev/identity.key"
            LEGACY_CANONICAL_KEY="$HOME/Library/Application Support/xyz.block.sprout.app.dev/identity.key"
            if [[ -f "$CANONICAL_KEY" ]]; then
                export BUZZ_PRIVATE_KEY="$(cat "$CANONICAL_KEY")"
            elif [[ -f "$LEGACY_CANONICAL_KEY" ]]; then
                export BUZZ_PRIVATE_KEY="$(cat "$LEGACY_CANONICAL_KEY")"
            else
                echo "⚠ BUZZ_SHARE_IDENTITY=1 but no identity found at $CANONICAL_KEY or $LEGACY_CANONICAL_KEY — run Buzz from repo root first" >&2
            fi
        fi

    fi
fi

# An explicit profile creates another isolation namespace inside the same
# checkout. Worktree identity remains part of the slug so the same profile can
# also be launched safely from two worktrees.
if [[ -n "$EXPLICIT_PROFILE" ]]; then
    if [[ -n "$BASE_INSTANCE_SLUG" ]]; then
        export BUZZ_INSTANCE_SLUG="${BASE_INSTANCE_SLUG}-${EXPLICIT_PROFILE}"
        INSTANCE_LABEL="${INSTANCE_LABEL} / ${EXPLICIT_PROFILE}"
    else
        export BUZZ_INSTANCE_SLUG="$EXPLICIT_PROFILE"
        INSTANCE_LABEL="$EXPLICIT_PROFILE"
    fi
    export VITE_DEV_PROFILE="$EXPLICIT_PROFILE"
    export BUZZ_DEV_KEYRING_SERVICE="buzz-desktop-dev.${BUZZ_INSTANCE_SLUG}"
elif [[ -n "$BASE_INSTANCE_SLUG" ]]; then
    export BUZZ_INSTANCE_SLUG="$BASE_INSTANCE_SLUG"
else
    unset BUZZ_INSTANCE_SLUG
fi

# Derive stable ports from the worktree root and, when present, the explicit
# profile. The no-profile seed intentionally remains unchanged for backward
# compatibility with existing worktree launch commands.
PORT_SEED="$WORKTREE_ROOT"
if [[ -n "$EXPLICIT_PROFILE" ]]; then
    PORT_SEED="${PORT_SEED}:${BUZZ_INSTANCE_SLUG}"
fi
BASE_PORT=$(python3 -c "import hashlib,sys; h=int(hashlib.sha256(sys.argv[1].encode()).hexdigest(), 16); print(10000 + h % 55000)" "$PORT_SEED")
export BUZZ_VITE_PORT=$BASE_PORT
export BUZZ_HMR_PORT=$((BASE_PORT + 1))
export BUZZ_RELAY_PORT=3000
export VITE_PORT="$BUZZ_VITE_PORT"
export VITE_HMR_PORT="$BUZZ_HMR_PORT"
export BUZZ_RELAY_URL="${BUZZ_RELAY_URL:-ws://localhost:3000}"

DEV_URL="http://localhost:${BUZZ_VITE_PORT}"
if [[ "${BUZZ_RESET_WEBVIEW_STATE:-0}" == "1" ]]; then
    DEV_URL="${DEV_URL}?resetDevState=1"
fi

INSTANCE_ID="xyz.block.buzz.app.dev"
PRODUCT_NAME="Buzz Dev"
if [[ -n "${BUZZ_INSTANCE_SLUG:-}" ]]; then
    INSTANCE_ID="${INSTANCE_ID}.${BUZZ_INSTANCE_SLUG}"
    PRODUCT_NAME="Buzz Dev (${INSTANCE_LABEL})"
fi

BUZZ_TAURI_CONFIG="{\"build\":{\"devUrl\":\"${DEV_URL}\",\"beforeDevCommand\":\"exec ./node_modules/.bin/vite --port ${BUZZ_VITE_PORT} --strictPort\"},\"identifier\":\"${INSTANCE_ID}\",\"productName\":\"${PRODUCT_NAME}\"}"

# Keep the established worktree icon treatment. Identity isolation does not
# depend on icon generation succeeding.
if [[ -n "${BUZZ_WORKTREE_LABEL:-}" ]]; then
    ICON_DIR="$WORKTREE_ROOT/desktop/src-tauri/target/dev-icons"
    mkdir -p "$ICON_DIR"
    DEV_ICON="$ICON_DIR/icon.icns"
    GENERATE_DEV_ICON="$WORKTREE_ROOT/scripts/generate-dev-icon.swift"
    BASE_ICON="$WORKTREE_ROOT/desktop/src-tauri/icons/icon.icns"

    if swift "$GENERATE_DEV_ICON" "$BASE_ICON" "$DEV_ICON" "$BUZZ_WORKTREE_LABEL"; then
        echo "🌳 Worktree: ${BUZZ_WORKTREE_LABEL}"
        BUZZ_TAURI_CONFIG="{\"build\":{\"devUrl\":\"${DEV_URL}\",\"beforeDevCommand\":\"exec ./node_modules/.bin/vite --port ${BUZZ_VITE_PORT} --strictPort\"},\"identifier\":\"${INSTANCE_ID}\",\"productName\":\"${PRODUCT_NAME}\",\"bundle\":{\"icon\":[\"$DEV_ICON\"]}}"
    fi
fi

export BUZZ_TAURI_CONFIG
