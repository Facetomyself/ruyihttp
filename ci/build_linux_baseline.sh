#!/usr/bin/env bash
# Build on native hardware with the Bullseye loader, headers, compiler and linker.
set -euo pipefail
slot=${1:?native Linux slot}
donor=${2:?absolute donor path}
output=${3:?absolute native output path}
evidence=${4:?absolute build evidence path}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${slot#linux_}
[[ $(uname -sm) == "Linux $arch" ]]

if [[ ${5:-} != --inside ]]; then
  [[ $(getconf GNU_LIBC_VERSION) != 'glibc 2.31' ]]
  [[ $donor == "$RUNNER_TEMP/"* && $output == "$RUNNER_TEMP/"* && $evidence == "$RUNNER_TEMP/"* ]]
  python -B "$root/tools/linux_baseline.py" pins "$slot" > "$evidence/builder-pins.env"
  . "$evidence/builder-pins.env"
  docker pull --platform "linux/$BASELINE_ARCH" "$BASELINE_IMAGE"
  [[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$BASELINE_IMAGE") == "linux/$BASELINE_ARCH" ]]
  docker image inspect "$BASELINE_IMAGE" > "$evidence/builder-image.json"
  docker run --rm --pull=never --platform "linux/$BASELINE_ARCH" \
    --mount "type=bind,src=$root,dst=$root,readonly" \
    --mount "type=bind,src=$RUNNER_TEMP,dst=$RUNNER_TEMP" \
    --env-file "$evidence/builder-pins.env" --workdir "$root" "$BASELINE_IMAGE" \
    bash ci/build_linux_baseline.sh "$slot" "$donor" "$output" "$evidence" --inside
  exit
fi

# All APT writes and installation take place inside the disposable container.
[[ -n ${BASELINE_IMAGE:?missing digest-pinned container identity} && $(dpkg --print-architecture) == "$BASELINE_ARCH" ]]
[[ $(getconf GNU_LIBC_VERSION) == 'glibc 2.31' ]]
. /etc/os-release
[[ $ID == debian && $VERSION_CODENAME == bullseye ]]
mkdir -p /tmp/ruyi-apt
printf '%s\n' "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$BASELINE_SNAPSHOT/ bullseye main" \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/$BASELINE_SNAPSHOT/ bullseye-security main" > /tmp/ruyi-apt/sources.list
apt_flags=(-q -o Acquire::Retries=3 -o Dir::Etc::sourcelist=/tmp/ruyi-apt/sources.list -o Dir::Etc::sourceparts=-)
apt-get "${apt_flags[@]}" update
DEBIAN_FRONTEND=noninteractive apt-get "${apt_flags[@]}" install -y --no-install-recommends \
  "clang-16=$BASELINE_CLANG" "libclang-16-dev=$BASELINE_CLANG" \
  "gcc-10=$BASELINE_GCC" "g++-10=$BASELINE_GCC" "libstdc++6=$BASELINE_GCC" "libgcc-s1=$BASELINE_GCC" \
  ninja-build=1.10.1-1 patchelf=0.12-1 libc6-dev libffi-dev libssl-dev libbz2-dev liblzma-dev \
  libreadline-dev libsqlite3-dev zlib1g-dev

fetch_verified() {
  local url=$1 hash=$2 dest=$3
  curl --proto '=https' -fLSs --retry 3 --connect-timeout 30 "$url" -o "$dest"
  printf '%s  %s\n' "$hash" "$dest" | sha256sum -c -
}
work=$(mktemp -d /tmp/ruyi-toolchain.XXXXXX)
export CC=clang CXX=clang++ LIBCLANG_PATH=/usr/lib/llvm-16/lib
export PATH=/opt/ruyi-cpython/bin:/opt/ruyi-rust/bin:/usr/lib/llvm-16/bin:$PATH
export CARGO_NET_OFFLINE=true
fetch_verified "https://www.python.org/ftp/python/$BASELINE_PYTHON/Python-$BASELINE_PYTHON.tar.xz" "$BASELINE_PYTHON_SHA256" "$work/cpython.tar.xz"
tar -xJf "$work/cpython.tar.xz" -C "$work"
(
  cd "$work/Python-$BASELINE_PYTHON"
  ./configure --prefix=/opt/ruyi-cpython --with-ensurepip=install
  make -j4
  make install
) > "$evidence/builder-cpython.log" 2>&1 || { tail -120 "$evidence/builder-cpython.log"; exit 1; }
ln -s python3 /opt/ruyi-cpython/bin/python
rust_target=$arch-unknown-linux-gnu
rust_dist=rust-$BASELINE_RUST-$rust_target
fetch_verified "https://static.rust-lang.org/dist/$rust_dist.tar.xz" "$BASELINE_RUST_SHA256" "$work/rust.tar.xz"
tar -xJf "$work/rust.tar.xz" -C "$work"
"$work/$rust_dist/install.sh" --prefix=/opt/ruyi-rust --components="rustc,cargo,rust-std-$rust_target" --disable-ldconfig

# GCC/Clang and Rust's linker see the container root; check their actual default inputs.
[[ $(getconf GNU_LIBC_VERSION) == 'glibc 2.31' ]]
[[ $(python -c 'import platform; print(platform.python_implementation(), platform.python_version())') == "CPython $BASELINE_PYTHON" ]]
[[ $(rustc -vV | sed -n 's/^host: //p') == "$rust_target" ]]
[[ $(rustc -vV | sed -n 's/^release: //p') == "$BASELINE_RUST" ]]
[[ $(realpath "$(clang++ -print-file-name=libstdc++.so)") == /usr/lib/$arch-linux-gnu/libstdc++.so.* ]]
[[ $(realpath "$(clang -print-file-name=libc.so)") == /usr/lib/$arch-linux-gnu/libc.so ]]
printf '' | clang -E -dM -include features.h -x c - > "$evidence/builder-glibc-headers.txt"
grep -Fx '#define __GLIBC__ 2' "$evidence/builder-glibc-headers.txt"
grep -Fx '#define __GLIBC_MINOR__ 31' "$evidence/builder-glibc-headers.txt"
dpkg-query -W -f='${binary:Package}\t${Version}\n' | LC_ALL=C sort > "$evidence/builder-dpkg.tsv"
{
  uname -sm
  getconf GNU_LIBC_VERSION
  python -V
  clang --version
  gcc-10 --version
  ld --version
  rustc -vV
  cargo -V
} > "$evidence/builder-toolchain.txt"
rustc -vV > "$evidence/standalone-rust.txt"
RUYIHTTP_BULLSEYE_BUILD=1 bash "$root/ci/build_native_target.sh" "$slot" "$donor" "$output"
python -B "$root/tools/check_linux_candidate.py" "$output" --arch "$arch" --baseline --host-providers \
  > "$evidence/baseline-elf.json"
python -B "$root/tools/linux_baseline.py" record "$slot" "$evidence" > "$evidence/baseline-build.json"
