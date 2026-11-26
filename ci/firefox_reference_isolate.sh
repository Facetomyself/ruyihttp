#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
set -euo pipefail

slot=$1
shift
python=$(command -v python)
case "$slot" in
    linux_x86_64|linux_aarch64)
        # Namespace has only the loopback adapter and no remote routes. Run the
        # browser as the normal account with its usual content sandbox enabled.
        sudo unshare --net -- bash -euc '
            ip link set lo up
            envvars=("PATH=$PATH" "GITHUB_SHA=$1" "GITHUB_RUN_ID=$2" "GITHUB_RUN_ATTEMPT=$3"
                     "ImageOS=$4" "ImageVersion=$5" "FIREFOX_REFERENCE_BOOTSTRAP=$6"
                     "FIREFOX_REFERENCE_H2_PREFACE=$7")
            shift 7
            user=$1; shift
            exec runuser -u "$user" -- env "${envvars[@]}" "$@"
        ' _ "${GITHUB_SHA:-}" "${GITHUB_RUN_ID:-}" "${GITHUB_RUN_ATTEMPT:-}" \
            "${ImageOS:-}" "${ImageVersion:-}" "${FIREFOX_REFERENCE_BOOTSTRAP:-h1}" \
            "${FIREFOX_REFERENCE_H2_PREFACE:-0}" "$(id -un)" "$python" ci/firefox_reference_capture.py capture "$slot" "$@"
        ;;
    darwin_x86_64|darwin_arm64)
        # The outer Seatbelt sandbox conflicts with Firefox's own content
        # sandbox, so isolate new IP egress at the macOS packet filter instead.
        [[ ${GITHUB_ACTIONS:-} == true || ${FIREFOX_REFERENCE_DEDICATED_MAC:-} == 1 ]]
        pf=/sbin/pfctl
        anchor="com.apple/ruyihttp-reference-$$"
        lease=
        cleanup() {
            sudo "$pf" -a "$anchor" -F rules >/dev/null 2>&1 || true
            if [[ -n "$lease" ]]; then sudo "$pf" -X "$lease" >/dev/null 2>&1 || true; fi
        }
        trap cleanup EXIT
        trap 'exit 130' INT HUP TERM
        if ! sudo "$pf" -sr 2>/dev/null | awk '/^anchor "com.apple\/\*"/ { found=1 } END { exit !found }'; then
            # An ephemeral Mac image can boot with an empty active ruleset.
            sudo "$pf" -f /etc/pf.conf
        fi
        sudo "$pf" -sr 2>/dev/null | awk '/^anchor "com.apple\/\*"/ { found=1 } END { exit !found }'
        printf 'block drop out quick on ! lo0 all\n' | sudo "$pf" -a "$anchor" -f -
        activation=$(sudo "$pf" -E 2>&1)
        lease=$(printf '%s\n' "$activation" | awk '/Token[[:space:]]*:/ { print $NF }')
        [[ $lease =~ ^[0-9]+$ ]]
        sudo "$pf" -a "$anchor" -sr 2>/dev/null | awk '/^block drop out quick on ! lo0 all/ {found=1} END {exit !found}'
        FIREFOX_REFERENCE_MACOS_GUARD=pf "$python" ci/firefox_reference_capture.py capture "$slot" "$@"
        ;;
    win_amd64)
        # A Windows-native shell establishes per-executable rules for this
        # exact copy; the helper cleans them even when the browser fails.
        powershell.exe -NoProfile -NonInteractive -File ci/firefox_reference_isolate_windows.ps1 \
            "$(cygpath -w "$python")" "$1" "$(cygpath -w "$2")" "$(cygpath -w "$3")" "${5:-2}"
        ;;
    *) printf 'Unexpected native slot: %s\n' "$slot" >&2; exit 2 ;;
esac
