#!/usr/bin/env bash
# Run outside the source tree with an installed wheel and its SOCKS extra.
set -euo pipefail
ci_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
py="${PYTHON:-python}"
export RUYIHTTP_TEST_NATIVE_RETRY=1
unset NECKO_CORE_LIBRARY NECKO_QUIC_LIBRARY
if [[ $(uname -s) == Darwin ]] && command -v brew >/dev/null; then
    export PATH="$(brew --prefix openssl@3)/bin:$PATH"
fi
"$py" -c 'import pathlib, sys, ruyihttp, socks; p=pathlib.Path(ruyihttp.__file__).resolve(); assert not p.is_relative_to(pathlib.Path(sys.argv[1]).resolve().parent), p; print("tested package:",p)' "$ci_dir"
for name in cookie_site retry_safety connection_budget socks_deadline http2_early_response; do
    "$py" -m unittest discover -s "$ci_dir/../tests" -p "test_${name}.py" -v
done
"$py" -u "$ci_dir/smoke_connect_budget.py"
"$py" -u "$ci_dir/smoke_h2_early_response.py"
