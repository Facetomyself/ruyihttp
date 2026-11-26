#!/usr/bin/env bash
# Qualify an existing artifact on native hosted GitHub Linux. Never rebuild or retag it.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
slot=${1:?supply linux_x86_64 or linux_aarch64}
wheelhouse=${2:?supply exact wheel directory, or any directory for probe}
evidence=${3:?supply evidence directory}
mode=${4:-release}
endpoint=${5:-all}
index=sha256:65c6bdcca22db1a3468a0262ae05f38a0a718f51e9818cd09c12094aaae28a33
case "$slot" in
  linux_x86_64) docker_arch=amd64; digest=sha256:4e96d6c7c610e5b2a46ff8a36cc76a159d57a5b865d580eda29d51afdc1a1923 ;;
  linux_aarch64) docker_arch=arm64; digest=sha256:7f7a235298401ed56b486968fbb19049fda940005e114ad917e0e60362c93342 ;;
  *) echo "Wrong Linux floor slot: $slot" >&2; exit 2 ;;
esac
case "$mode" in release|candidate|probe) ;; *) exit 2 ;; esac
case "$endpoint" in all|3.10|3.14) ;; *) exit 2 ;; esac
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(uname -s) == Linux && $(uname -m) == "${slot#linux_}" ]]
[[ $(docker info --format '{{.OSType}}/{{.Architecture}}') == "linux/${slot#linux_}" ]]
mkdir -p -- "$wheelhouse" "$evidence"
wheelhouse=$(cd -- "$wheelhouse" && pwd -P)
evidence=$(cd -- "$evidence" && pwd -P)
staging=$(mktemp -d "${RUNNER_TEMP:?}/ruyihttp-glibc231.XXXXXXXX")
docker_platform="linux/$docker_arch"
repo=docker.io/library/python
base="$repo@$digest"
old="$staging/0.9.3"
python3 -I "$root/ci/qualify_glibc231.py" fetch-old "$slot" 3.10 "$wheelhouse" "$evidence" "$staging" "$old" "$mode"
# Assert the recorded child really belongs to the official multi-arch index.
docker buildx imagetools inspect --raw "$repo@$index" > "$evidence/official-python-index.json"
python3 - "$evidence/official-python-index.json" "$docker_arch" "$digest" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
children = [m['digest'] for m in data['manifests'] if m.get('platform', {}).get('os') == 'linux'
            and m['platform'].get('architecture') == sys.argv[2]]
assert children == [sys.argv[3]], children
PY
docker pull --platform "$docker_platform" "$base"
[[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$base") == "$docker_platform" ]]
if [[ $endpoint == 3.14 || $endpoint == all ]]; then
  cp314="ruyihttp-glibc231-${docker_arch}-cp314:${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
  docker build --platform "$docker_platform" --build-arg "BASE_IMAGE=$base" --tag "$cp314" \
    "$root/ci/linux_floor" 2>&1 | tee "$evidence/cpython314-build.txt"
  [[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$cp314") == "$docker_platform" ]]
fi

qualify() {
  local py=$1 image=$2 executable=$3 state="$staging/$1" receipt="$evidence/$1"
  mkdir -p -- "$state" "$receipt"
  local image_id
  image_id=$(docker image inspect --format '{{.Id}}' "$image")
  python3 - "$receipt/image.json" "$index" "$digest" "$image_id" "$docker_platform" "$root" "$py" <<'PY'
import json, os, subprocess, sys
out, index, manifest, image, platform, checkout, endpoint = sys.argv[1:]
commit = subprocess.check_output(['git', '-C', checkout, 'rev-parse', 'HEAD'], text=True).strip()
run = os.environ['GITHUB_RUN_ID']
attempt = os.environ['GITHUB_RUN_ATTEMPT']
with open(out, 'w', encoding='utf-8') as fp:
    json.dump({'index': index, 'base_manifest': manifest, 'image_id': image, 'docker_platform': platform,
               'qualification_commit': commit, 'endpoint': endpoint, 'run_id': run, 'attempt': attempt,
               'producer_run_id': os.environ.get('FLOOR_PRODUCER_RUN_ID') or run,
               'producer_attempt': os.environ.get('FLOOR_PRODUCER_ATTEMPT') or attempt,
               'artifact_kind': os.environ.get('FLOOR_ARTIFACT_KIND') or 'local-release-directory'},
              fp, indent=2, sort_keys=True)
    fp.write('\n')
PY
  local -a common=(--rm --platform "$docker_platform" --user "$(id -u):$(id -g)"
    --cap-drop ALL --security-opt no-new-privileges --workdir /tmp --env HOME=/tmp --env LANG=C.UTF-8
    --mount "type=bind,source=$root/ci,target=/source/ci,readonly"
    --mount "type=bind,source=$root/tests,target=/source/tests,readonly"
    --mount "type=bind,source=$root/docs,target=/source/docs,readonly"
    --mount "type=bind,source=$root/pyproject.toml,target=/source/pyproject.toml,readonly"
    --mount "type=bind,source=$wheelhouse,target=/wheelhouse,readonly"
    --mount "type=bind,source=$old,target=/old,readonly"
    --mount "type=bind,source=$receipt,target=/evidence"
    --mount "type=bind,source=$state,target=/state")
  local -a tail=("$slot" "$py" /wheelhouse /evidence /state /old "$mode")
  docker run "${common[@]}" "$image_id" "$executable" -I /source/ci/qualify_glibc231.py install "${tail[@]}"
  docker run "${common[@]}" --network none "$image_id" "$executable" -I /source/ci/qualify_glibc231.py verify "${tail[@]}"
}

if [[ $endpoint == 3.10 || $endpoint == all ]]; then
  qualify 3.10 "$base" /usr/local/bin/python3.10
fi
if [[ $endpoint == 3.14 || $endpoint == all ]]; then
  qualify 3.14 "$cp314" /opt/cpython/bin/python3.14
fi

# The release job uploads these same bytes, not a second build. Bind both
# endpoint receipts to the exact wheel still present in the upload directory.
if [[ $endpoint == all && $mode != probe ]]; then
  python3 -I - "$wheelhouse" "$evidence" "$slot" "$mode" <<'PY'
import hashlib, json, sys
from pathlib import Path
wheelhouse, evidence, slot, mode = sys.argv[1:]
(wheel,) = Path(wheelhouse).glob('*.whl')
root = Path(evidence)
sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
receipts = {}
native = None
for endpoint in ('3.10', '3.14'):
    data = (root / endpoint / 'summary.json').read_bytes()
    receipt = json.loads(data)
    if (receipt['slot'] != slot or receipt['mode'] != mode or receipt['glibc'] != 'glibc 2.31'
            or receipt['container']['endpoint'] != endpoint or receipt['wheel']['filename'] != wheel.name
            or receipt['wheel']['sha256'] != sha or (mode == 'release' and receipt['masque_status'] != 'wire-passed')):
        raise SystemExit('endpoint receipt differs from the exact wheel being uploaded')
    if native is not None and native != receipt['native_sha256']:
        raise SystemExit('endpoint native file hashes differ')
    native = receipt['native_sha256']
    receipts[endpoint] = hashlib.sha256(data).hexdigest()
summary = {'slot': slot, 'mode': mode, 'filename': wheel.name, 'sha256': sha,
           'glibc': '2.31', 'cpython_runtime_endpoints': list(receipts), 'endpoint_receipt_sha256': receipts,
           'native_sha256': native}
(root / 'both-endpoints.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(f'glibc 2.31 both-endpoint wheel SHA256: {sha}')
PY
fi
