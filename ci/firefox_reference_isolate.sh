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
                     "ImageOS=$4" "ImageVersion=$5" "FIREFOX_REFERENCE_BOOTSTRAP=$6")
            shift 6
            user=$1; shift
            exec runuser -u "$user" -- env "${envvars[@]}" "$@"
        ' _ "${GITHUB_SHA:-}" "${GITHUB_RUN_ID:-}" "${GITHUB_RUN_ATTEMPT:-}" \
            "${ImageOS:-}" "${ImageVersion:-}" "${FIREFOX_REFERENCE_BOOTSTRAP:-h1}" \
            "$(id -un)" "$python" ci/firefox_reference_capture.py capture "$slot" "$@"
        ;;
    darwin_x86_64|darwin_arm64)
        # The runner applies Seatbelt to Firefox only. The observer process
        # explicitly binds its TCP/UDP fixtures to IPv4 loopback.
        "$python" ci/firefox_reference_capture.py capture "$slot" "$@"
        ;;
    win_amd64)
        # A Windows-native shell establishes per-executable rules for this
        # exact copy; the helper cleans them even when the browser fails.
        powershell.exe -NoProfile -NonInteractive -File ci/firefox_reference_isolate_windows.ps1 \
            "$(cygpath -w "$python")" "$1" "$(cygpath -w "$2")" "$(cygpath -w "$3")" "${5:-2}"
        ;;
    *) printf 'Unexpected native slot: %s\n' "$slot" >&2; exit 2 ;;
esac
