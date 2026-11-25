"""Give a disposable source rebuild a unique PEP 440 wheel identity."""

import json
import re
import sys
from pathlib import Path

run_id, attempt = sys.argv[1:3]
assert run_id.isdecimal() and attempt.isdecimal() and int(run_id) and int(attempt)
manifest_file = Path('ruyihttp/runtime-manifest.json')
manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
base = manifest['version']
assert re.fullmatch(r'\d+\.\d+\.\d+', base), base
version = f'{base}.dev{int(run_id)}+gha.{int(attempt)}'
for path, original in [(Path('pyproject.toml'), f'version = "{base}"'),
                       (Path('ruyihttp/__init__.py'), f'__version__ = "{base}"')]:
    source = path.read_text(encoding='utf-8')
    assert source.count(original) == 1, path
    path.write_text(source.replace(original, original.replace(f'"{base}"', f'"{version}"')), encoding='utf-8')
manifest['version'] = version
manifest_file.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(f'Native source candidate wheel version: {version}')
