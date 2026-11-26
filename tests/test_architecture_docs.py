from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from html import escape
from io import StringIO
import json
from pathlib import Path
from shutil import which
import subprocess
from tempfile import TemporaryDirectory
import unittest

from tools import check_architecture_docs as check


@unittest.skipUnless(which("git"), "architecture checker fixtures require Git")
class ArchitectureDocsTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "docs-fixture@example.invalid")
        self.git("config", "user.name", "Architecture Fixture")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.git("remote", "add", "origin", check.REPOSITORY.removesuffix(".git"))
        self.write("ruyihttp/client.py", "first\nsecond\nlast")
        self.write("README.md", "# Project\n")
        self.write("docs/public.md", "# Public reference\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Release fixture")
        self.release = self.git("rev-parse", "HEAD")
        self.git("tag", "v0.9.4")
        self.write("README.md", "# Fixture baseline\n")
        self.git("commit", "-qam", "Source baseline fixture")
        self.pin = self.git("rev-parse", "HEAD")
        self.source_link = f"{check.REPOSITORY.removesuffix('.git')}/blob/{self.pin}/ruyihttp/client.py"
        self.write("README.md", "# Project\n\n[Handbook](docs/architecture/)\n")
        self.ledger = {
            "schema": 1,
            "repository": check.REPOSITORY,
            "sourceRevision": self.pin,
            "release": {"tag": "v0.9.4", "commit": self.release},
            "tool": {"name": "Archify", "version": "3.3.2"},
            "diagrams": [],
            "analysis": {},
        }
        chapters = {name: "# Fixture chapter\n\n" for name in check.CHAPTERS}
        for stem, (kind, chapter) in check.DIAGRAMS.items():
            chapters[chapter] += f"[![{stem}](diagrams/{stem}.svg)](diagrams/{stem}.html)\n"
            base = f"{check.FIGURES}/{stem}"
            meta = {"output": f"{base}.html", "quality_profile": "showcase",
                    "repository": {"url": check.REPOSITORY, "revision": self.pin}}
            node = {"id": "client", "sources": [{"path": "ruyihttp/client.py", "line": 2, "end_line": 3}]}
            svg_parent, node_drilldowns = "", ""
            if stem == "overview":
                links = [{"href": f"{other}.html?from=overview#focus=client", "label": other}
                         for other in check.DIAGRAMS if other != stem]
                node["drilldowns"] = links
                node_drilldowns = f' data-node-drilldowns="{escape(json.dumps(links), quote=True)}"'
            else:
                meta["parentHref"] = "overview.html"
                svg_parent = ' data-parent-href="overview.html"'
            collection, supported_versions = check.NATIVE_SCHEMA[kind]
            spec = {"schema_version": max(supported_versions), "diagram_type": kind, "meta": meta, collection: [node]}
            evidence = {"verified": True, "referenceCount": 1,
                        "repository": {"url": check.REPOSITORY, "revision": self.pin},
                        "nodes": {"client": [{"path": "ruyihttp/client.py", "line": 2, "endLine": 3,
                                              "href": self.source_link + "#L2-L3"}]}}
            svg = (f'<svg xmlns="http://www.w3.org/2000/svg" aria-labelledby="{check.DIAGRAM_TITLE}" '
                   f'viewBox="0 0 50 50"{svg_parent}><g data-node-id="client"{node_drilldowns}>'
                   '<rect x="0" y="0" width="10" height="10"/><text>Client</text></g></svg>')
            html = (f'<!DOCTYPE html><html><script id="archify-source-evidence-data" type="application/json">'
                    f'{json.dumps(evidence)}</script>{svg}</html>')
            self.write(f"{base}.json", json.dumps(spec))
            self.write(f"{base}.html", html)
            self.write(f"{base}.svg", svg)
            self.ledger["diagrams"].append({"id": stem, "type": kind, "chapter": chapter,
                                            "sourcesVerified": 1, "gates": dict(check.GATES),
                                            "sha256": {ext: self.digest(f"{base}.{ext}") for ext in check.EXTENSIONS}})
        chapters["README.md"] += (f"[Pinned source]({self.source_link}#L2-L3)\n"
                                  "[Local doc](../public.md#public-reference)\n"
                                  "```sh\n[Sample ignored](missing.txt)\n```\n")
        for name, md in chapters.items():
            self.write(f"{check.ARCH}/{name}", md)
        for report, scope in check.ANALYSIS.items():
            page = f"analysis/{report}.html"
            payload = {"repository": {"url": check.REPOSITORY, "root": scope, "language": "py",
                                      "baseRevision": self.pin, "sourceKind": "working-tree"}}
            self.write(f"{check.ARCH}/{page}",
                       '<html><script id="bauify-analysis" type="application/json">'
                       f'{json.dumps(payload)}</script><script id="bauify-atlas-data">{{}}</script></html>')
            self.ledger["analysis"][report] = {"html": page, "scope": scope,
                                              "sha256": self.digest(f"{check.ARCH}/{page}")}
        self.save_ledger()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, path, text):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(text.encode("utf-8"))

    def digest(self, path):
        return sha256((self.root / path).read_bytes()).hexdigest()

    def save_ledger(self):
        self.write(check.LEDGER, json.dumps(self.ledger))

    def append_chapter(self, chapter, text):
        path = f"{check.ARCH}/{chapter}"
        self.write(path, (self.root / path).read_text(encoding="utf-8") + text + "\n")

    def mutate(self, stem, change):
        path = f"{check.FIGURES}/{stem}.json"
        diagram = json.loads((self.root / path).read_bytes())
        change(diagram)
        self.write(path, json.dumps(diagram))
        row = next(row for row in self.ledger["diagrams"] if row["id"] == stem)
        row["sha256"]["json"] = self.digest(path)
        self.save_ledger()

    def invoke(self, *args):
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = check.main(["--root", str(self.root), *args])
        return code, output.getvalue()

    def assert_result(self, status, message, *args):
        code, output = self.invoke(*args)
        self.assertEqual(code, status, output)
        self.assertIn(message, output)

    def test_historical_pin_with_docs_only_commit_is_current(self):
        self.git("add", ".")
        self.git("commit", "-qm", "Publish fixture handoff")
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.pin)
        self.assert_result(0, "No cited source drift", "--strict-drift")

    def test_source_drift_is_advisory_or_strict(self):
        self.write("ruyihttp/client.py", "first\nactual source changed\nlast")
        self.assert_result(0, "ruyihttp/client.py: h2-flow, h3-owner")
        self.assert_result(1, "Source drift", "--strict-drift")

    def test_artifact_hash_mismatch(self):
        self.write(f"{check.FIGURES}/overview.svg", "changed artifact")
        self.assert_result(1, "SHA-256 mismatch")

    def test_rehashed_svg_placeholder(self):
        path = f"{check.FIGURES}/overview.svg"
        self.write(path, '<svg xmlns="http://www.w3.org/2000/svg"></svg>')
        self.ledger["diagrams"][0]["sha256"]["svg"] = self.digest(path)
        self.save_ledger()
        self.assert_result(1, "missing Archify export")

    def test_source_path_cannot_escape(self):
        self.mutate("overview", lambda d: d["components"][0]["sources"][0].update(path="../outside"))
        self.assert_result(1, "invalid repository-relative source path")

    def test_source_must_exist_at_pin(self):
        self.write("ruyihttp/new.py", "first\nsecond\nthird")
        self.mutate("overview", lambda d: d["components"][0]["sources"][0].update(path="ruyihttp/new.py"))
        self.assert_result(1, "is missing or is not a matching Git file")

    def test_source_range_cannot_exceed_pinned_blob(self):
        self.write("ruyihttp/client.py", "first\nsecond\nlast\nnew worktree line")
        self.mutate("overview", lambda d: d["components"][0]["sources"][0].update(end_line=4))
        self.assert_result(1, "invalid line range 2–4")

    def test_parent_cannot_escape_figures(self):
        self.mutate("h2-flow", lambda d: d["meta"].update(parentHref="../diagrams/overview.html"))
        self.assert_result(1, "same-directory diagram HTML link")

    def test_other_valid_revision_is_not_a_matching_pin(self):
        self.mutate("h2-flow", lambda d: d["meta"]["repository"].update(revision=self.release))
        self.assert_result(1, "repository must match the public sourceRevision")

    def test_credentials_are_rejected_without_echoing_them(self):
        self.git("remote", "set-url", "origin", "https://example-auth@github.com/Facetomyself/ruyihttp.git")
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("credential-free URL", output)
        self.assertNotIn("example-auth", output)

    def test_markdown_destination_and_pinned_lines_checked(self):
        self.append_chapter("README.md", f"[Out of range]({self.source_link}#L2-L4)")
        self.assert_result(1, "invalid line range 2–4")

    def test_markdown_escape_rejected(self):
        self.append_chapter("07-keeping-current.md", "[Outside](%2e%2e/%2e%2e/%2e%2e/README.md)")
        self.assert_result(1, "escapes repository")

    def write_receipts(self):
        parent = self.directory / "receipts"
        for row in self.ledger["diagrams"]:
            stem = row["id"]
            base = f"{check.FIGURES}/{stem}"
            receipt = {"schemaVersion": 1, "command": "finalize", "ok": True, "status": "pass",
                       "type": row["type"], "quality": "showcase", "gates": check.GATES,
                       "browserCheck": {"requested": True, "ran": True},
                       "repositoryReferences": {"status": "verified", "revision": self.pin, "count": 1}}
            for field, ext in (("specification", "json"), ("artifact", "html")):
                receipt[field] = {"sha256": self.digest(f"{base}.{ext}"),
                                  "bytes": (self.root / f"{base}.{ext}").stat().st_size}
            path = parent / stem / f"{stem}.finalize-summary.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(receipt), encoding="utf-8")
        return parent

    def test_refresh_uses_receipt_bound_current_bytes(self):
        receipts = self.write_receipts()
        self.ledger["diagrams"][0]["sha256"]["json"] = "0" * 64
        self.save_ledger()
        self.assert_result(0, "Architecture handbook checked", "--refresh-diagrams", str(receipts))
        self.assert_result(0, "Architecture handbook checked")

    def test_refresh_with_stale_receipt_does_not_write_ledger(self):
        receipts = self.write_receipts()
        before = self.digest(check.LEDGER)
        path = f"{check.FIGURES}/overview.html"
        self.write(path, (self.root / path).read_text(encoding="utf-8") + "\n")
        self.assert_result(1, "artifact differs from checked-in bytes", "--refresh-diagrams", str(receipts))
        self.assertEqual(self.digest(check.LEDGER), before)


if __name__ == "__main__":
    unittest.main()
