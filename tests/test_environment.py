"""Is the suite testing THIS checkout?

One test, because a whole green suite can be meaningless without it. `pip install -e .` records
an absolute path, so a second clone of sopack (a `-tmp` working copy, a bisect worktree) runs its
own `tests/` against the FIRST clone's `sopack/` package - and how that resolves depends on how
pytest was started:

  python3 -m pytest tests/    # `-m` prepends CWD to sys.path -> this checkout wins
  pytest                      # no CWD entry -> the editable install wins, i.e. the other clone

So `./scripts/build_wbaes.sh` (which uses `python3 -m pytest`) exercised the edited code while a
bare `pytest` in the same directory imported the other checkout and failed with ImportError on
every new symbol. The two disagreeing is the confusing part, and it is invisible without a check
like this one.

`artifact_generation.sh`'s generated `install.sh` already probes exactly this for the portable
bundle - "an old editable checkout would shadow it" (CLAUDE.md, artifacts/). This is the same
check for the repo, where the same mistake costs a debugging session instead of a bad bundle.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_the_imported_sopack_is_the_one_in_this_checkout():
    # Imported INSIDE the test, not at module scope: on a fresh clone with no `pip install -e .`
    # a module-scope import turns this into a collection ERROR for the whole file, which is
    # noisier than the problem and buries the message below.
    import sopack
    imported = Path(sopack.__file__).resolve().parent
    expected = REPO / "sopack"
    assert imported == expected, (
        f"these tests are in {REPO}\n"
        f"but `import sopack` resolved to {imported}\n"
        "so the suite is testing a DIFFERENT checkout and its results say nothing about this "
        "one. Fix with one of:\n"
        f"  pip install -e {REPO}        # point the editable install at this checkout\n"
        "  python3 -m pytest tests/     # -m prepends CWD, which build_wbaes.sh relies on")
