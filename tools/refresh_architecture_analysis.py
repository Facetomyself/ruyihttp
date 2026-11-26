"""Publish two portable Archify Code Analysis snapshots from a clean Git checkout.

The reports are static evidence, not a benchmark or a native-call graph. Only
Archify's machine-local resume.command is replaced for distribution. Use a
separate source worktree so generated files never become analyzer inputs.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SCOPES = {"repository": ".", "runtime": "ruyihttp"}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def require(test, message):
    if not test:
        raise ValueError(message)


def hexhash(data):
    return hashlib.sha256(data).hexdigest()


def portable_html(raw, old_command, new_command):
    # Verify the one changed JSON string belongs to the UI resume control.
    # No search/replace on captured source, diagnostics, tasks or chart data.
    ident = re.compile(
        r'<script\b(?=[^>]*\bid="bauify-analysis")[^>]*>(.*?)</script>', re.S
    )
    match = ident.search(raw)
    require(match is not None, "Archify analysis payload is missing")
    old = json.loads(match[1])
    cfg = old["ui"]["resume"]
    require(old_command == cfg["command"] and old_command, "unexpected resume command")
    literal = json.dumps(old_command, ensure_ascii=False)
    require(
        raw.count(literal) == 1 and literal in match[1], "resume string is not unique"
    )
    result = raw.replace(literal, json.dumps(new_command, ensure_ascii=False), 1)
    cfg["command"] = new_command
    require(old == json.loads(ident.search(result)[1]), "analysis content changed")
    return result.encode("utf-8")


def one(name, path, source, revision, tool, work):
    run = work / name
    started = time.monotonic()
    completed = subprocess.run(
        [
            tool,
            "code-analysis",
            "prepare",
            path,
            "--out",
            str(run),
            "--language",
            "py",
            "--locale",
            "zh-CN",
        ],
        cwd=source,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    seconds = round(time.monotonic() - started, 2)
    (work / (name + "-prepare.json")).write_text(completed.stdout, encoding="utf-8")
    receipt = json.loads(completed.stdout)
    require(receipt["status"] == "ok", f"{name}: prepare did not succeed")
    area = run / "analysis"
    page = area / "repo.analysis.html"
    require(
        Path(receipt["html"]).resolve() == page and not page.is_symlink(),
        "HTML outside result",
    )
    finding = read_json(area / "findings.json")
    graph = read_json(area / "module-graph.json")
    repo = finding["repository"]
    coverage = receipt["summary"]["coverage"]
    require(
        repo["sourceKind"] == "working-tree"
        and repo["baseRevision"] == revision
        and repo["root"] == SCOPES[name]
        and coverage["language"] == "py",
        f"{name}: unexpected source binding or language",
    )
    require(
        not coverage["files"]["parseErrors"],
        f"{name}: Python parser did not cover every selected file",
    )
    require(
        repo["url"]
        in (
            "https://github.com/Facetomyself/ruyihttp",
            "https://github.com/Facetomyself/ruyihttp.git",
        ),
        "use a clean checkout with the public HTTPS repository as origin",
    )
    raw = page.read_bytes()
    replacement = (
        f"archify start {path} --out .archify/analysis-{name} "
        "--locale zh-CN --language py --quality standard"
    )
    public = portable_html(
        raw.decode("utf-8"), receipt["resume"]["command"], replacement
    )
    require(
        str(source).encode() not in public and str(work).encode() not in public,
        "host-specific path remains in report",
    )
    diagnostics = finding["diagnostics"]
    metrics = dict(
        scope=path,
        cleanGitHead=revision,
        sourceKind=repo["sourceKind"],
        snapshotId=repo["snapshotId"],
        adapter=repo["adapter"],
        preparationSeconds=seconds,
        coverage=coverage,
        counts=receipt["summary"]["counts"],
        countsByRule=dict(sorted(Counter(d["code"] for d in diagnostics).items())),
        modules=len(graph["modules"]),
        groupedImportEdges=len(graph["edges"]),
        topFanOut=[
            {k: m[k] for k in ("label", "files", "loc", "fanIn", "fanOut")}
            for m in sorted(graph["modules"], key=lambda m: (-m["fanOut"], m["label"]))[
                :6
            ]
        ],
        complexityWarnings=[
            dict(
                subject=d["subject"],
                **{k: d["evidence"][k] for k in ("complexity", "nesting", "length")},
            )
            for d in diagnostics
            if d["code"] == "complexity/function" and d["severity"] == "warning"
        ],
        internalImportContext=[
            d["evidence"] for d in diagnostics if d["code"] == "coupling/internal-leak"
        ],
        rawHtmlSha256=hexhash(raw),
        publishedHtmlSha256=hexhash(public),
    )
    return public, metrics


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--source",
        required=True,
        type=Path,
        help="clean, separate checkout of the pinned public revision",
    )
    ap.add_argument("--revision", required=True, help="expected full Git commit")
    ap.add_argument("--out", type=Path, default=ROOT / "docs/architecture/analysis")
    ap.add_argument(
        "--archify",
        default=os.environ.get("ARCHIFY_BIN", "archify"),
        help="Archify executable or wrapper",
    )
    ap.add_argument(
        "--evidence-dir",
        type=Path,
        help="optional new directory for original, machine-local analyzer output",
    )
    args = ap.parse_args()
    source = args.source.resolve(strict=True)
    out = args.out.resolve()
    require(
        str(source) == git(source, "rev-parse", "--show-toplevel"),
        "--source must be the repository root",
    )
    require(
        re.fullmatch("[0-9a-f]{40}", args.revision)
        and git(source, "rev-parse", "HEAD") == args.revision,
        "source revision does not match",
    )
    require(
        not git(source, "status", "--porcelain") and not out.is_relative_to(source),
        "use a clean source tree separate from the report output",
    )
    tool = shutil.which(args.archify)
    require(tool, "could not locate Archify executable")
    with tempfile.TemporaryDirectory(prefix="ruyi-architecture-analysis-") as tmp:
        work = Path(tmp).resolve()
        if args.evidence_dir:
            work = args.evidence_dir.resolve()
            require(
                not work.is_relative_to(source), "evidence would contaminate source"
            )
            work.mkdir(parents=True, exist_ok=False)
        rows = {
            name: one(name, scope, source, args.revision, tool, work)
            for name, scope in SCOPES.items()
        }
        require(
            not git(source, "status", "--porcelain"), "source changed during analysis"
        )
        out.mkdir(parents=True, exist_ok=True)
        for name, (html, _) in rows.items():
            (out / (name + ".html")).write_bytes(html)
        summary = {
            "schema": 1,
            "sourceRevision": args.revision,
            "method": "Two working-tree Python prepare runs on the same clean checkout. Only the embedded resume command is made checkout-relative; all captured analysis evidence is unchanged.",
            "reports": {name: data for name, (_, data) in rows.items()},
        }
        (out / "metrics.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        for name, (_, m) in rows.items():
            print(
                f"{name}: {m['coverage']['files']['analyzed']} Python files, {m['preparationSeconds']}s, {m['publishedHtmlSha256']}"
            )


if __name__ == "__main__":
    main()
