"""Build the preceding fork release in a separate hosted checkout, once per target."""

import os
from pathlib import Path
import subprocess
import sys

BASELINE = "fae13b0a9eabbafbcdbf5c59438875525fcc0d0b"


def main():
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = runner / "ruyihttp-fork-091"
    root.mkdir()  # Refuse stale wheels from a different run.
    checkout = root / "source"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "fetch",
            "--depth=1",
            "--no-tags",
            "https://github.com/Facetomyself/ruyihttp.git",
            BASELINE,
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "checkout", "-q", "--detach", "FETCH_HEAD"],
        check=True,
    )
    actual = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != BASELINE:
        raise SystemExit("Unexpected previous fork source: " + actual)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "-w",
            str(root / "wheels"),
            str(checkout),
        ],
        check=True,
    )
    (previous,) = (root / "wheels").glob("ruyihttp-0.9.1-*.whl")
    print("Previous fork:", actual, previous.name)
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as env:
        print("RUYIHTTP_FORK_091_BUILD=" + str(root), file=env)


if __name__ == "__main__":
    main()
