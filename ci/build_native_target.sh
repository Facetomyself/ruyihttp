#!/usr/bin/env bash
# Build from the pinned upstream C/C++/Rust and Firefox vendor tree.
set -euo pipefail
slot=${1:?target slot required}
donor=${2:?donor checkout required}
output=${3:?native output directory required}
mkdir -p "$output"
manifest_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$donor"
case "$slot" in
  linux_aarch64)
    [[ $(uname -sm) == 'Linux aarch64' ]]
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends clang libclang-dev ninja-build patchelf
    python -B tools/build_necko_linux.py --firefox-source "$donor/firefox" --jobs 3 --http3
    input=$(compgen -G "$donor/vendor/necko-derived/python/lib/python*/site-packages/necko")
    ;;
  darwin_x86_64)
    [[ $(uname -sm) == 'Darwin x86_64' ]]
    export MACOSX_DEPLOYMENT_TARGET=15.0 MACH_NO_TERMINAL_FOOTER=1
    export MOZCONFIG="$donor/ci/firefox/macos/mozconfig.browser"
    cd firefox
    mach() { ./mach --no-interactive "$@" </dev/null; }
    mach configure
    mach build pre-export export
    python "$donor/ci/firefox/deps.py" "$donor/obj/browser" > "$donor/obj/browser-steps.txt"
    # Only NSS/NSPR/mozglue here: omit unrelated Skia/SpiderMonkey build units.
    while read -r dir target; do
      if [[ $dir == gfx/skia ]]; then continue; fi
      if [[ -n $target ]]; then mach build --directory "$dir" "$target"; else mach build --allow-subdirectory-build "$dir"; fi
    done < "$donor/obj/browser-steps.txt"
    cd "$donor"
    python - <<'PY'
from pathlib import Path
p = Path('tools/build.py')
s = p.read_text()
old = '"-arch", "arm64",\n        "-I", str(include / "nss"),'
assert s.count(old) == 1
p.write_text(s.replace(old, old.replace('arm64', 'x86_64')))
PY
    python -B tools/build.py --necko-core-only --firefox-gfx-obj "$donor/obj/browser"
    patch="$manifest_root/native/patches/macos-necko-quic-tls-info.patch"
    shasum -a 256 "$patch"
    git apply --check "$patch"
    git apply "$patch"
    RUYIJS_DONOR_OBJ="$donor/obj/browser" python -B tools/build_necko_quic.py library
    input="$donor/dist/necko_tls"
    ;;
  *) printf 'Unknown target: %s\n' "$slot" >&2; exit 2 ;;
esac
python -B - "$manifest_root" "$slot" "$input" "$output" <<'PY'
import shutil
import sys
from pathlib import Path
root, platform, source, target = sys.argv[1:]
sys.path.insert(0, str(Path(root) / 'tools'))
from build_native import PLATFORM_FILES
for name in PLATFORM_FILES[platform]:
    shutil.copy2(Path(source) / name, Path(target) / name)
PY
if [[ $slot == linux_aarch64 ]]; then
  # DT_RUNPATH on the two bridges alone does not cover sibling dependencies of NSS.
  for lib in "$output"/*.so; do patchelf --set-rpath '$ORIGIN' "$lib"; done
fi
file "$output"/*
