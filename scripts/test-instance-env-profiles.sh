#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

read_profile() {
    local profile="$1"
    BUZZ_DEV_PROFILE="$profile" BUZZ_RELAY_URL="ws://preview-relay.test:3000" \
        bash -c 'source "$1/scripts/instance-env.sh"; printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$BUZZ_INSTANCE_SLUG" "$BUZZ_VITE_PORT" "$BUZZ_HMR_PORT" "$BUZZ_DEV_KEYRING_SERVICE" "${CARGO_TARGET_DIR:-}" "$BUZZ_TAURI_CONFIG"' bash "$repo_root"
}

alice=$(read_profile alice)
bob=$(read_profile bob)

IFS=$'\t' read -r alice_slug alice_vite alice_hmr alice_keyring alice_target alice_config <<< "$alice"
IFS=$'\t' read -r bob_slug bob_vite bob_hmr bob_keyring bob_target bob_config <<< "$bob"

[[ "$alice_slug" == *alice ]]
[[ "$bob_slug" == *bob ]]
[[ "$alice_vite" != "$bob_vite" ]]
[[ "$alice_hmr" != "$bob_hmr" ]]
[[ "$alice_vite" != "$alice_hmr" ]]
[[ "$alice_vite" != "$bob_hmr" ]]
[[ "$bob_vite" != "$bob_hmr" ]]
[[ "$bob_vite" != "$alice_hmr" ]]
[[ "$alice_keyring" == "buzz-desktop-dev.${alice_slug}" ]]
[[ "$bob_keyring" == "buzz-desktop-dev.${bob_slug}" ]]
[[ "$alice_keyring" != "$bob_keyring" ]]
# Profiles share normal Cargo caches. Their runtime identity, app data,
# keyrings, and web ports remain isolated without duplicating gigabytes of
# compiled Rust dependencies.
[[ -z "$alice_target" ]]
[[ -z "$bob_target" ]]
[[ "$alice_config" == *"xyz.block.buzz.app.dev.${alice_slug}"* ]]
[[ "$bob_config" == *"xyz.block.buzz.app.dev.${bob_slug}"* ]]
[[ "$alice_config" == *"Buzz Dev ("*alice* ]]
[[ "$bob_config" == *"Buzz Dev ("*bob* ]]

grep -Fqx '    BUZZ_MARMOT_PREVIEW=1 VITE_BUZZ_LOCAL_PREVIEW=1 BUZZ_DEV_PROFILE=alice just desktop-standalone {{ARGS}}' "$repo_root/Justfile"
grep -Fqx '    BUZZ_MARMOT_PREVIEW=1 VITE_BUZZ_LOCAL_PREVIEW=1 BUZZ_DEV_PROFILE=bob just desktop-standalone {{ARGS}}' "$repo_root/Justfile"
[[ $(grep -c 'BUZZ_MARMOT_PREVIEW=1' "$repo_root/Justfile") -eq 2 ]]
[[ $(grep -c 'VITE_BUZZ_LOCAL_PREVIEW=1' "$repo_root/Justfile") -eq 2 ]]

if BUZZ_DEV_PROFILE='../production' bash -c 'source "$1/scripts/instance-env.sh"' bash "$repo_root" >/dev/null 2>&1; then
    echo "expected an unsafe profile slug to be rejected" >&2
    exit 1
fi

echo "desktop preview profiles are isolated"
