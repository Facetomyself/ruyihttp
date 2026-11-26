#!/usr/bin/env python3
"""Check the architecture handbook's portable evidence, using only Python and Git."""

import argparse
from collections import defaultdict
from functools import lru_cache
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
from posixpath import normpath
import re
import subprocess
import sys
from urllib.parse import quote, unquote, urlsplit
from xml.etree import ElementTree


REPOSITORY = "https://github.com/Facetomyself/ruyihttp.git"
ARCH = "docs/architecture"
FIGURES = f"{ARCH}/diagrams"
LEDGER = f"{ARCH}/verification.json"
DIAGRAMS = {
    "overview": ("architecture", "README.md"),
    "request-route": ("workflow", "01-request-routing.md"),
    "h2-flow": ("sequence", "02-protocol-engines.md"),
    "h3-owner": ("lifecycle", "02-protocol-engines.md"),
    "masque-tunnel": ("sequence", "03-masque.md"),
    "trust-path": ("dataflow", "04-trust-profiles.md"),
    "native-delivery": ("workflow", "05-native-delivery.md"),
}
CHAPTERS = {chapter for _, chapter in DIAGRAMS.values()} | {
    "06-maintenance-roadmap.md", "07-keeping-current.md",
}
NATIVE_SCHEMA = {
    "architecture": ("components", (1,)),
    "workflow": ("nodes", (1, 2)),
    "sequence": ("participants", (1,)),
    "lifecycle": ("states", (3,)),
    "dataflow": ("nodes", (1,)),
}
ANALYSIS = {"repository": ".", "runtime": "ruyihttp"}
GATES = dict.fromkeys(("validate", "deliver", "check", "browser-check"), "pass")
EXTENSIONS = ("json", "html", "svg")
COMMIT = re.compile(r"[0-9a-f]{40}")
LINE_RANGE = re.compile(r"L([1-9][0-9]*)(?:-L([1-9][0-9]*))?")
NEIGHBOR = re.compile(r"[\w.-]+\.html(?:\?[^#\s\\]*)?(?:#[^\s\\]*)?", re.ASCII)
SVG_NS = "{http://www.w3.org/2000/svg}"
DIAGRAM_TITLE = "archify-diagram-title archify-diagram-description"


class CheckError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def keys(value, names, where):
    require(isinstance(value, dict) and value.keys() == set(names.split()),
            f"{where}: expected fields {names}")


def unique_object(pairs):
    obj = dict(pairs)
    require(len(obj) == len(pairs), "duplicate JSON object key")
    return obj


def read_json(data, where):
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, CheckError) as error:
        raise CheckError(f"{where}: {error}") from error


def github_repository(url):
    """Accept canonical HTTPS identities plus GitHub's credential-free SSH origin."""
    if not isinstance(url, str):
        return None
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
        r"([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?", url, re.IGNORECASE)
    return match[1].lower() if match else None


def public_repository(url):
    return isinstance(url, str) and url.startswith("https://") and (
        github_repository(url) == github_repository(REPOSITORY))


def clean_path(value):
    return isinstance(value, str) and not re.search(r"[:\\\x00-\x1f\x7f]", value) and (
        value == "." or all(part not in ("", ".", "..") for part in value.split("/")))


class Artifact(HTMLParser):
    """Collect generated markup and specific embedded JSON, not script literals."""
    def __init__(self, payload_id=None):
        super().__init__()
        self.payload_id = payload_id
        self.current_payload = False
        self.payload = []
        self.ids = set()
        self.nodes = {}
        self.svg = None

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if attrs.get("data-node-id"):
            self.nodes[attrs["data-node-id"]] = attrs.get("data-node-drilldowns")
        if tag == "svg" and attrs.get("aria-labelledby") == DIAGRAM_TITLE:
            self.svg = attrs
        if tag == "script" and attrs.get("type") == "application/json":
            self.current_payload = self.payload_id is not None and attrs.get("id") == self.payload_id

    def handle_endtag(self, tag):
        if tag == "script":
            self.current_payload = False

    def handle_data(self, data):
        if self.current_payload:
            self.payload.append(data)


def markdown_text(text):
    """Discard fenced code and comments before checking document links and headings."""
    fence = None
    for line in re.sub(r"<!--.*?-->", "", text, flags=re.S).splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if marker:
            if fence is None:
                fence = marker[1]
                continue
            if marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                fence = None
                continue
        if fence is None and not line.startswith(("    ", "\t")):
            yield line


DESTINATION = r"(?:<([^<>\n]+)>|((?:\\.|[^()\s\\<>]|\([^()\n]*\))+))"
INLINE_LINK = re.compile(r"(?<!\\)\]\(\s*" + DESTINATION + r"(?:\s+[\"'][^\n]*?[\"'])?\s*\)")
REFERENCE_LINK = re.compile(r"^ {0,3}\[[^\]]+\]:\s*" + DESTINATION)
CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)")


def markdown_links(text):
    for line in markdown_text(text):
        reference = REFERENCE_LINK.match(line)
        for match in (reference,) if reference else INLINE_LINK.finditer(CODE_SPAN.sub("", line)):
            yield unescape(re.sub(r"\\([()])", r"\1", match[1] or match[2]))


def markdown_anchors(text):
    anchors = set()
    for line in markdown_text(text):
        heading = re.match(r"^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$", line)
        if heading:
            title = unescape(re.sub(r"<[^>]*>", "", INLINE_LINK.sub("]", heading[1]))).lower()
            slug = "".join(ch for ch in title if ch.isalnum() or ch in " _-").replace(" ", "-")
            anchor, suffix = slug, 1
            while anchor in anchors:
                anchor = f"{slug}-{suffix}"
                suffix += 1
            anchors.add(anchor)
        for match in re.finditer(r"<\w+[^>]*\b(?:id|name)=[\"']([^\"']+)[\"']", line):
            anchors.add(unescape(match[1]))
    return anchors


class Handbook:
    def __init__(self, root):
        self.root = root.resolve()
        self.refs = defaultdict(set)
        self.parents = {}
        self.children = defaultdict(set)
        self.chapter_links = {}
        self.artifacts = {}
        self.ledger = None

    def git(self, *args):
        process = subprocess.run(["git", "--no-replace-objects", "--literal-pathspecs", *args],
                                 cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(process.returncode == 0,
                f"git {args[0]}: {process.stderr.decode(errors='replace').strip()}")
        return process.stdout

    def local(self, path):
        result = self.root / path
        require(result.resolve().is_relative_to(self.root), f"local path escapes repository: {path}")
        return result

    @lru_cache(maxsize=None)
    def load(self, path):
        file = self.local(path)
        require(file.is_file(), f"missing repository file: {path}")
        return file.read_bytes()

    @lru_cache(maxsize=None)
    def require_commit(self, revision):
        require(self.git("cat-file", "-t", revision).strip() == b"commit",
                f"{revision}: expected a locally available Git commit")

    @lru_cache(maxsize=None)
    def object_info(self, revision, path):
        self.require_commit(revision)
        if path == ".":
            return "tree", 0
        entry = self.git("ls-tree", "-z", revision, "--", path).split(b"\0", 1)[0]
        mode = entry.split(b" ", 1)[0]
        if mode == b"040000":
            return "tree", 0
        if mode in (b"100644", b"100755"):
            blob = self.git("cat-file", "blob", f"{revision}:{path}")
            return "blob", blob.count(b"\n") + bool(blob and not blob.endswith(b"\n"))
        return None, 0

    def check_range(self, revision, path, start, end, where, kind=None):
        require(clean_path(path), f"{where}: invalid repository-relative source path {path!r}")
        actual_kind, lines = self.object_info(revision, path)
        require(actual_kind is not None and kind in (None, actual_kind),
                f"{where}: {path!r} is missing or is not a matching Git file or directory at {revision}")
        if start is not None or end is not None:
            require(actual_kind == "blob" and type(start) is int and type(end) is int and
                    1 <= start <= end <= lines,
                    f"{where}: invalid line range {start}–{end} for {path} ({lines} lines at {revision})")
        return actual_kind

    def check_link(self, document, target):
        where = f"{document}: link {target!r}"
        require(not re.search(r"[\\\x00-\x1f\x7f]", target), f"{where}: invalid link path")
        url = urlsplit(target)
        if url.scheme or url.netloc:
            require(url.username is None and url.password is None, f"{document}: link contains credentials")
            require(url.scheme in ("https", "http", "mailto"), f"{where}: unsupported public link scheme")
            segments = url.path.lstrip("/").split("/", 4)
            if (url.netloc.lower() == "github.com" and len(segments) >= 4 and
                    "/".join(segments[:2]).lower() == github_repository(REPOSITORY) and
                    segments[2] in ("blob", "tree")):
                kind, revision = segments[2:4]
                fragment = unquote(url.fragment)
                release = self.ledger["release"]
                if revision == release["tag"]:
                    revision = release["commit"]
                if matches(COMMIT, revision):
                    path = unquote(segments[4]) if len(segments) == 5 else "."
                    match = LINE_RANGE.fullmatch(fragment)
                    require(not (kind == "blob" and re.match(r"L\d", fragment)) or match,
                            f"{where}: invalid GitHub line anchor")
                    start = int(match[1]) if match else None
                    end = int(match[2] or match[1]) if match else None
                    self.check_range(revision, path, start, end, where, kind=kind)
                elif kind == "blob" and re.match(r"L\d", fragment):
                    raise CheckError(f"{where}: use a full commit SHA for GitHub source lines")
            return None
        path = unquote(url.path)
        require(not path.startswith(("/", "~")) and not re.search(r"[:\\\x00-\x1f\x7f]", path),
                f"{where}: expected a relative repository link")
        parent = PurePosixPath(document).parent
        resolved = normpath(parent / path) if path else document
        require(resolved != ".." and not resolved.startswith("../"), f"{where}: escapes repository")
        file = self.local(resolved)
        if file.is_dir() and (file / "README.md").is_file():
            resolved = (PurePosixPath(resolved) / "README.md").as_posix()
            file = self.local(resolved)
        require(file.is_file() or file.is_dir(), f"{where}: missing local destination")
        fragment = unquote(url.fragment)
        if file.is_file() and (span := LINE_RANGE.fullmatch(fragment)):
            lines = len(self.load(resolved).splitlines())
            require(int(span[1]) <= int(span[2] or span[1]) <= lines,
                    f"{where}: invalid local line anchor ({lines} lines)")
        elif fragment and file.suffix.lower() == ".md":
            require(fragment in markdown_anchors(self.load(resolved).decode("utf-8")),
                    f"{where}: missing Markdown anchor")
        return resolved

    def check_chapters(self):
        base = self.local(ARCH)
        chapters = {f"{ARCH}/{name}" for name in CHAPTERS} | {
            file.relative_to(self.root).as_posix() for file in base.rglob("*.md")}
        for chapter in sorted(chapters):
            self.chapter_links[chapter] = {self.check_link(chapter, target) for target in
                                           markdown_links(self.load(chapter).decode("utf-8"))}
        entry_links = {self.check_link("README.md", target) for target in
                       markdown_links(self.load("README.md").decode("utf-8"))
                       if unquote(target).removeprefix("./").startswith(ARCH)}
        require(f"{ARCH}/README.md" in entry_links, "README.md: missing local architecture handbook entry")

    def check_ledger_header(self):
        data = self.ledger
        keys(data, "schema repository sourceRevision release tool diagrams analysis", LEDGER)
        require(type(data["schema"]) is int and data["schema"] == 1, f"{LEDGER}: expected schema 1")
        require(public_repository(data["repository"]), f"{LEDGER}: expected credential-free public repository URL")
        expected = github_repository(data["repository"])
        require(github_repository(self.git("remote", "get-url", "origin").decode().strip()) == expected,
                "origin: expected the same public GitHub repository, with a credential-free URL")
        revision = data["sourceRevision"]
        require(matches(COMMIT, revision), f"{LEDGER}: sourceRevision must be a full commit SHA")
        self.require_commit(revision)
        release = data["release"]
        keys(release, "tag commit", f"{LEDGER} release")
        require(matches(r"v\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.-]+)?", release["tag"]) and
                matches(COMMIT, release["commit"]), f"{LEDGER}: invalid release tag or commit")
        tag = self.git("rev-parse", "--verify", f"refs/tags/{release['tag']}^{{commit}}").decode().strip()
        require(tag == release["commit"], f"{LEDGER}: {release['tag']} peels to {tag}, not {release['commit']}")
        keys(data["tool"], "name version", f"{LEDGER} tool")
        require(data["tool"]["name"] == "Archify" and matches(r"\d+\.\d+\.\d+", data["tool"]["version"]),
                f"{LEDGER}: expected a versioned Archify tool")

    def neighbor(self, current, value, where):
        require(matches(NEIGHBOR, value), f"{where}: expected a same-directory diagram HTML link")
        other = PurePosixPath(urlsplit(value).path).stem
        require(other in DIAGRAMS and other != current, f"{where}: unknown or self-linked diagram {value!r}")
        return other

    def check_diagram(self, stem, row):
        kind, chapter = DIAGRAMS[stem]
        base = f"{FIGURES}/{stem}"
        keys(row, "id type chapter sourcesVerified sha256 gates", f"{LEDGER} {stem}")
        require((row["type"], row["chapter"]) == (kind, chapter), f"{LEDGER}: wrong type or chapter for {stem}")
        keys(row["sha256"], "json html svg", f"{LEDGER} {stem} sha256")
        require(row["gates"] == GATES, f"{LEDGER}: {stem} requires all four passing Archify gates")
        figures = self.chapter_links[f"{ARCH}/{chapter}"]
        blobs = {ext: self.load(f"{base}.{ext}") for ext in EXTENSIONS}
        for ext, blob in blobs.items():
            require(row["sha256"][ext] == sha256(blob).hexdigest(), f"{base}.{ext}: SHA-256 mismatch")
        require({f"{base}.html", f"{base}.svg"} <= figures,
                f"{chapter}: link both the {stem} HTML and SVG")
        spec = read_json(blobs["json"], f"{base}.json")
        collection, versions = NATIVE_SCHEMA[kind]
        require(isinstance(spec, dict) and type(spec.get("schema_version")) is int and
                spec["schema_version"] in versions and spec.get("diagram_type") == kind,
                f"{base}.json: wrong Archify schema or diagram type")
        meta = spec.get("meta")
        require(isinstance(meta, dict) and meta.get("output") == f"{base}.html" and
                meta.get("quality_profile") == "showcase", f"{base}.json: wrong meta.output or quality profile")
        repo = meta.get("repository")
        revision = self.ledger["sourceRevision"]
        require(isinstance(repo, dict) and public_repository(repo.get("url")) and
                repo.get("revision") == revision and repo.get("provider", "github") == "github" and
                repo.get("link_mode", "web") == "web" and "base_revision" not in repo,
                f"{base}.json: repository must match the public sourceRevision {revision}")
        parent_href = meta.get("parentHref")
        if stem == "overview":
            require("parentHref" not in meta, f"{base}.json: overview must be the navigation root")
        else:
            self.parents[stem] = self.neighbor(stem, parent_href, f"{base}.json meta.parentHref")

        nodes = spec.get(collection)
        require(isinstance(nodes, list) and nodes, f"{base}.json: missing semantic {collection}")
        expected_sources, expected_hrefs = {}, {}
        for node in nodes:
            require(isinstance(node, dict) and matches(r"[A-Za-z0-9_-]+", node.get("id")),
                    f"{base}.json: missing semantic element ID")
            node_id = node["id"]
            where = f"{base}.json element {node_id}"
            require(node_id not in expected_sources, f"{where}: duplicate element ID")
            sources = node.get("sources")
            require(isinstance(sources, list) and 1 <= len(sources) <= 3,
                    f"{where}: expected one to three pinned source references")
            expected_sources[node_id] = []
            for source in sources:
                require(isinstance(source, dict), f"{where}: each source must be an object")
                path, start = source.get("path"), source.get("line")
                end = source.get("end_line", start)
                require(("line" not in source or type(start) is int) and
                        ("end_line" not in source or type(end) is int), f"{where}: source lines must be integers")
                entry_type = self.check_range(revision, path, start, end, where)
                self.refs[path].add(stem)
                source_kind = "tree" if entry_type == "tree" else "blob"
                encoded_path = "" if path == "." else f"/{quote(path)}"
                fragment = f"#L{start}" if start is not None else ""
                if end != start:
                    fragment += f"-L{end}"
                plain = "?plain=1" if start is not None and re.search(r"\.(?:md|markdown)$", path, re.I) else ""
                origin = re.sub(r"\.git$", "", repo["url"].rstrip("/"), flags=re.I)
                href = f"{origin}/{source_kind}/{revision}{encoded_path}{plain}{fragment}"
                expected_sources[node_id].append((path, start, end, href))
            if "href" in node:
                self.neighbor(stem, node["href"], f"{where} href")
            drilldowns = node.get("drilldowns", [{"href": node["href"]}] if "href" in node else [])
            require(isinstance(drilldowns, list) and (drilldowns or "drilldowns" not in node),
                    f"{where}: invalid drilldowns list")
            expected_hrefs[node_id] = []
            for link in drilldowns:
                require(isinstance(link, dict), f"{where}: invalid drilldown")
                other = self.neighbor(stem, link.get("href"), f"{where} drilldown")
                target_type = DIAGRAMS[other][0]
                require(link.get("diagram_type", target_type) == target_type, f"{where}: wrong drilldown type")
                self.children[stem].add(other)
                expected_hrefs[node_id].append(link["href"])

        count = sum(map(len, expected_sources.values()))
        require(type(row["sourcesVerified"]) is int and row["sourcesVerified"] == count,
                f"{LEDGER}: {stem} sourcesVerified must match {count} authored references")
        html = Artifact("archify-source-evidence-data")
        html.feed(blobs["html"].decode("utf-8"))
        html.close()
        require(html.svg and html.svg.get("viewbox") and html.svg.get("data-parent-href") == parent_href and
                html.nodes.keys() == expected_sources.keys(), f"{base}.html: missing Archify diagram or mismatched nodes/parent")
        for node_id, payload in html.nodes.items():
            actual = read_json(payload, f"{base}.html {node_id} drilldowns") if payload else []
            require(isinstance(actual, list) and all(isinstance(link, dict) for link in actual) and
                    [link.get("href") for link in actual] == expected_hrefs[node_id],
                    f"{base}.html: mismatched drilldowns on {node_id}")
        evidence = read_json("".join(html.payload), f"{base}.html embedded source evidence")
        require(isinstance(evidence, dict) and evidence.get("verified") is True and
                isinstance(evidence.get("repository"), dict) and public_repository(evidence["repository"].get("url")) and
                evidence["repository"].get("revision") == revision and evidence.get("referenceCount") == count and
                isinstance(evidence.get("nodes"), dict) and evidence["nodes"].keys() == expected_sources.keys(),
                f"{base}.html: embedded source evidence must match the pin and authored elements")
        for node_id, expected in expected_sources.items():
            rendered = evidence["nodes"][node_id]
            require(isinstance(rendered, list) and all(isinstance(ref, dict) for ref in rendered) and
                    [(ref.get("path"), ref.get("line"), ref.get("endLine", ref.get("line")), ref.get("href"))
                     for ref in rendered] == expected, f"{base}.html: mismatched rendered sources on {node_id}")

        try:
            svg = ElementTree.fromstring(blobs["svg"])
        except ElementTree.ParseError as error:
            raise CheckError(f"{base}.svg: {error}") from error
        require(svg.tag == f"{SVG_NS}svg" and svg.get("viewBox") and
                svg.get("aria-labelledby") == DIAGRAM_TITLE and svg.get("data-parent-href") == parent_href and
                {el.get("data-node-id") for el in svg.iter() if el.get("data-node-id")} == set(expected_sources),
                f"{base}.svg: missing Archify export or mismatched nodes/parent")
        self.artifacts[stem] = (blobs, count)

    def check_analysis(self):
        analysis = self.ledger["analysis"]
        keys(analysis, "repository runtime", f"{LEDGER} analysis")
        for report, scope in ANALYSIS.items():
            data = analysis[report]
            relative = f"analysis/{report}.html"
            require(isinstance(data, dict) and data.get("html") == relative and data.get("scope") == scope,
                    f"{LEDGER}: expected analysis {report} as {relative} for scope {scope}")
            blob = self.load(f"{ARCH}/{relative}")
            require(data.get("sha256") == sha256(blob).hexdigest(), f"{relative}: SHA-256 mismatch")
            html = Artifact("bauify-analysis")
            html.feed(blob.decode("utf-8"))
            html.close()
            require("bauify-atlas-data" in html.ids, f"{relative}: missing standalone Code Analysis content")
            payload = read_json("".join(html.payload), f"{relative} embedded analysis")
            repo = payload.get("repository") if isinstance(payload, dict) else None
            require(isinstance(repo, dict) and public_repository(repo.get("url")) and repo.get("root") == scope and
                    repo.get("language") == "py" and repo.get("sourceKind") == "working-tree" and
                    repo.get("baseRevision") == self.ledger["sourceRevision"],
                    f"{relative}: analysis scope or source revision differs from verification.json")

    def validate(self, ledger):
        self.ledger = ledger
        self.check_ledger_header()
        self.check_chapters()
        rows = ledger["diagrams"]
        require(isinstance(rows, list) and
                all(isinstance(row, dict) and isinstance(row.get("id"), str) for row in rows) and
                sorted(row["id"] for row in rows) == sorted(DIAGRAMS), f"{LEDGER}: expected the seven named diagrams")
        for row in rows:
            self.check_diagram(row["id"], row)
        for stem, parent in self.parents.items():
            require(stem in self.children[parent], f"{stem}: parent {parent} has no drilldown back to it")
            seen, cursor = {stem}, parent
            while cursor != "overview":
                require(cursor not in seen, f"{stem}: parent cycle through {cursor}")
                seen.add(cursor)
                cursor = self.parents[cursor]
        self.check_analysis()

    def drift(self):
        paths = sorted(self.refs)
        revision = self.ledger["sourceRevision"]
        changed = self.git("diff", "--name-only", "--no-ext-diff", "--no-renames", "-z", revision, "--", *paths)
        added = self.git("ls-files", "--others", "--exclude-standard", "-z", "--", *paths)
        for raw in sorted(set((changed + added).split(b"\0")) - {b""}):
            path = os.fsdecode(raw)
            diagrams = set().union(*(users for ref, users in self.refs.items()
                                     if ref == "." or path == ref or path.startswith(ref + "/")))
            if diagrams:
                yield path, sorted(diagrams)

    def refresh(self, ledger, receipt_dir):
        """Bind compact public rows to completed local Archify finalize summaries."""
        self.ledger = ledger
        self.check_ledger_header()
        updated = []
        for stem, (kind, chapter) in DIAGRAMS.items():
            path = receipt_dir / stem / f"{stem}.finalize-summary.json"
            label = f"finalize summary for {stem}"
            receipt = read_json(path.read_bytes(), label)
            require(isinstance(receipt, dict) and receipt.get("schemaVersion") == 1 and
                    receipt.get("command") == "finalize" and receipt.get("type") == kind and
                    receipt.get("quality") == "showcase" and receipt.get("ok") is True and
                    receipt.get("status") == "pass" and receipt.get("gates") == GATES and
                    receipt.get("browserCheck") == {"requested": True, "ran": True},
                    f"{label}: expected completed showcase finalize and browser gates")
            base = f"{FIGURES}/{stem}"
            blobs = {ext: self.load(f"{base}.{ext}") for ext in EXTENSIONS}
            hashes = {ext: sha256(blob).hexdigest() for ext, blob in blobs.items()}
            for field, ext in (("specification", "json"), ("artifact", "html")):
                bound = receipt.get(field)
                require(isinstance(bound, dict) and bound.get("sha256") == hashes[ext] and
                        bound.get("bytes") == len(blobs[ext]), f"{label}: {field} differs from checked-in bytes")
            refs = receipt.get("repositoryReferences")
            require(isinstance(refs, dict) and refs.get("status") == "verified" and
                    refs.get("revision") == ledger["sourceRevision"] and type(refs.get("count")) is int,
                    f"{label}: missing pinned repository evidence")
            updated.append({"id": stem, "type": kind, "chapter": chapter, "sourcesVerified": refs["count"],
                            "sha256": hashes, "gates": receipt["gates"]})
        ledger["diagrams"] = updated


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="repository root (defaults to this script's repository)")
    policy = parser.add_mutually_exclusive_group()
    policy.add_argument("--strict-drift", action="store_true", help="fail on changes to cited paths versus the pin")
    policy.add_argument("--refresh-diagrams", type=Path, metavar="RECEIPT_ROOT",
                        help="refresh diagram rows from seven complete Archify finalize summaries")
    args = parser.parse_args(argv)
    try:
        handbook = Handbook(args.root)
        top = Path(os.fsdecode(handbook.git("rev-parse", "--show-toplevel").strip())).resolve()
        require(top == handbook.root, "--root must name the checkout root")
        ledger = read_json(handbook.load(LEDGER), LEDGER)
        if args.refresh_diagrams:
            handbook.refresh(ledger, args.refresh_diagrams)
        handbook.validate(ledger)
        drift = list(handbook.drift())
        if drift:
            print(f"Source drift from {ledger['sourceRevision']} (working tree):")
            for path, ids in drift:
                print(f"  {path}: {', '.join(ids)}")
            print("The published evidence still describes its pinned revision; review the affected diagrams.")
            if args.strict_drift:
                return 1
        else:
            print(f"No cited source drift from {ledger['sourceRevision']}.")
        if args.refresh_diagrams:
            handbook.local(LEDGER).write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Architecture handbook checked: {len(DIAGRAMS)} diagram triplets, "
              f"{len(handbook.refs)} cited paths, {len(ANALYSIS)} analysis reports.")
        return 0
    except (CheckError, OSError, ValueError, RuntimeError) as error:
        print(f"Architecture handbook: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
