# 07 · 维护手册与图件

[手册目录](README.md) · [维护路线图](06-maintenance-roadmap.md) · [图件校验记录](verification.json)

## 先选对基线

- **源码基线**：[9e88bfe](https://github.com/Facetomyself/ruyihttp/tree/9e88bfe023fd46a96254f8de66e8d72517339911) 是这套手册首版引用的源码提交。GitHub 源码链接、图中 Passport 的证据及分析报告以它为基准。
- **发行基线**：[v0.9.4](https://github.com/Facetomyself/ruyihttp/releases/tag/v0.9.4) 指向 [74953f7](https://github.com/Facetomyself/ruyihttp/tree/74953f70e87f5935a9ce4410c639727d26ea323e)。从该标签到源码基线只改了项目首页，可用 `git diff --name-only v0.9.4 9e88bfe` 核对；安装与上机验收仍以 Release 为准。
- **制品提交**：章节、可编辑 JSON、HTML、SVG 和校验记录所在的提交比源码基线晚。升级手册后，以校验记录中的 `sourceRevision` 和 `release` 为准；制品提交只是文档交付版本。

## 判断改动会影响哪里

先在仓库根目录运行以下命令。普通检查接受可验证的历史基线，并逐项列出变更的引用路径及受影响的图；`--strict-drift` 将这些变化视为失败。比较对象是已固定源码与当前工作树，包含已暂存及未暂存的改动；它按引用文件检查，并非语义差异分析。即使路径未漂移，增添新入口或改动图外依赖仍应人工追踪。

```sh
python3 tools/check_architecture_docs.py
python3 tools/check_architecture_docs.py --strict-drift
python3 -m unittest discover -s tests -p 'test_architecture*.py' -v
```

| 改动 | 优先核对 | 针对性检查（已配好项目依赖时） |
| --- | --- | --- |
| Session、租约、重定向、重试或 Alt-Svc | [请求路由](01-request-routing.md)及总览 | `python -m unittest discover -s tests -p test_retry_safety.py -v`；`python -m unittest discover -s tests -p test_alt_svc.py -v` |
| H2 流控、H3 owner、正文或关闭 | [协议引擎](02-protocol-engines.md)中对应图 | `python -m unittest discover -s tests -p test_http2_flow.py -v`；`python -m unittest discover -s tests -p test_h3_body_abi.py -v` |
| MASQUE 隧道、代理校验或目标约束 | [MASQUE](03-masque.md)和[信任与配置](04-trust-profiles.md) | `python -m pytest -q --import-mode=importlib tests/test_masque_codec.py tests/test_masque_transport.py tests/test_masque_routing.py`；另用已安装 wheel 的解释器执行 `python -I /path/to/checkout/ci/smoke_masque.py --json-output masque-wire.json` |
| 信任材料、浏览器配置或原生交付 | [信任与配置](04-trust-profiles.md)、[原生交付](05-native-delivery.md) | `python -m unittest discover -s tests -p test_trust_and_buffers.py -v`；`python tools/build_native.py --check`；`python tools/verify_runtime.py` |

[文档专用 CI](../../.github/workflows/architecture-docs.yml) 在日常构建中校验内容和摘要，报告源码漂移；手动运行时可启用 `strict_drift`。浅克隆先补齐源码提交和发行标签。CI 使用 Python 标准库和 Git，浏览器由重制图件的人运行；文档校验与协议测试、目标平台 wheel 验收各自负责不同的证据。

## 重制图件

1. **先核对代码，再编辑图源。** 从干净的源码提交读取涉及分支、所有权、回退或关闭的代码；给每个关键元素记录仓库相对路径和行号。修改 [`diagrams/overview.json`](diagrams/overview.json) 等图源及对应章节，以 JSON 为准；同时检查总览的钻取目标、子图的返回链接和正文图注。`meta.output` 保留公开 HTML 的仓库相对路径。
2. **保留一致的源码快照。** 纯文档修订可以沿用 `sourceRevision`。更新源码基线时，先确认新提交可获取，再核对七张图的引用；把 `meta.repository.revision`、章节中的源码链接和校验记录的 `sourceRevision` 一起更新，并重制两份分析。只有发行版改变时才同步更新 `release.tag` 与对应的 peeled commit。运行 `git status --short`，明确区分制品编辑与源码改动。
3. **使用 Archify 3.3.2 的真实交付和浏览器导出。** 安装 Node.js、Chrome 或 Chromium，准备相同版本的 Archify 开源包。`ARCHIFY_HOME` 取包目录（包含 `bin/archify.mjs` 和 `bin/export-svg.mjs`），可选 `ARCHIFY_CHROME` 指向浏览器可执行文件。以下在仓库根目录用 Bash 运行；暂存目录每次新建，保留真实摘要及浏览器证据。

```bash
set -euo pipefail
: "${ARCHIFY_HOME:?Set ARCHIFY_HOME to the Archify package directory}"
repo=$(git rev-parse --show-toplevel)
cd "$repo"
scratch=$(mktemp -d)
figures=docs/architecture/diagrams

archify_run() {
  if command -v archify >/dev/null 2>&1; then
    archify "$@"
  else
    node "$ARCHIFY_HOME/bin/archify.mjs" "$@"
  fi
}

while read -r id type; do
  evidence="$scratch/$id"
  mkdir "$evidence"
  archify_run finalize "$type" "$figures/$id.json" "$evidence/$id.html" \
    --repo-root "$repo" --quality showcase --out-dir "$evidence" --json
  node "$ARCHIFY_HOME/bin/export-svg.mjs" "$evidence/$id.html" "$evidence/$id.svg" auto
  cp "$evidence/$id.html" "$figures/$id.html"
  cp "$evidence/$id.svg" "$figures/$id.svg"
done <<'DIAGRAMS'
overview architecture
request-route workflow
h2-flow sequence
h3-owner lifecycle
masque-tunnel sequence
trust-path dataflow
native-delivery workflow
DIAGRAMS
```

4. **用读者的宽度浏览。** 在浏览器中打开同目录下的最终 HTML，检查总览跳转、子图返回和 Passport 源码链接。按章节正文约 720–900 CSS 像素的阅读宽度检查 SVG，沿主路径走到分支、失败和返回，确认文字与箭头在正常缩放下可读。`finalize` 自动跑 `validate`、`deliver`、严格 `check` 和 `browser-check`，这四个门禁与人工读图是两件事。有调整时，从新的 `scratch` 目录重跑；旧浏览器凭证只对应旧 HTML。

## 更新分析与公开证据

只在分析基线或方法变更时重建 [运行时分析](analysis/runtime.html) 和 [全仓分析](analysis/repository.html)。生成器在独立的干净源码工作树运行 Archify 的 Python 分析，产出两份 HTML 与 [覆盖范围和测量记录](analysis/metrics.json)。报告要公开入库，取证工作树的 `origin` 应为本项目的无凭据 HTTPS 地址。源码 tarball 可用于离线阅读；固定提交和漂移校验需要带 Git 历史、标签的检出。运行时报告仅覆盖 `ruyihttp/`；全仓报告是更广的 Python 静态视角。它们记录了分析范围内的维护线索，不能替代对运行行为、原生 ABI 或性能的验证。

```bash
# 在上面同一个 Bash 会话中执行；用校验记录中的完整 sourceRevision。
pin=$(python3 -c 'import json; print(json.load(open("docs/architecture/verification.json"))["sourceRevision"])')
git worktree add --detach "$scratch/source" "$pin"
export ARCHIFY_BIN="${ARCHIFY_BIN:-$(command -v archify || printf '%s' "$ARCHIFY_HOME/bin/archify.mjs")}"
python3 tools/refresh_architecture_analysis.py --source "$scratch/source" \
  --revision "$pin" --evidence-dir "$scratch/analysis-evidence"
```

用生成器打印的 `publishedHtmlSha256`（也在 `analysis/metrics.json` 中）更新校验记录的两项 `analysis.*.sha256`。若更换 Archify 版本，同时更新 `tool.version`。最后从本次真实交付摘要刷新图件记录：

```bash
python3 tools/check_architecture_docs.py --refresh-diagrams "$scratch"
python3 tools/check_architecture_docs.py --strict-drift
python3 -m unittest discover -s tests -p 'test_architecture*.py' -v
git diff --check
git status --short
```

刷新命令只接受七份已完成的 `*.finalize-summary.json`，核对图源和 HTML 的哈希、字节数、源码提交与浏览器门禁，并为本次浏览器导出的 SVG 记录哈希。审查 `git status`，提交有意修改的章节、图件、分析和校验记录。完整摘要、交付 sidecar 及浏览器输出留在本地暂存目录；公开仓库只收可移植的结果和摘要，以免把本机路径写进制品。
