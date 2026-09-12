# CLAUDE.md — adaricorp/faucet

Instructions for an agent working in this repo. The *why* is in
[`README.adari.md`](README.adari.md); this file is the rules.

This is a fork of `faucetsdn/faucet` carrying adari's patches. It is
**public**, and adari installs from it by tag.

## Never do these

- **Never open a pull request, issue or discussion on `faucetsdn/faucet`.**
  Sending a patch upstream is a person's decision and a person's click.
  Preparing an `upstream/<topic>` branch is the whole of an agent's job
  here.
- **Never commit to `main`.** It is a pure mirror of `upstream/main`, and
  one local commit there breaks `git merge --ff-only upstream/main` on the
  next sync. adari-only files (this file, `README.adari.md`) live on
  `adari`.
- **Never merge into `adari` — rebase it.** A merge destroys the
  patch-id match that makes an upstream-accepted patch drop out of the
  stack automatically on the next sync.
- **Never delete or move a tag.** adari's `poetry.lock` pins one; a lock
  whose tag has moved installs different code, and one whose tag is gone
  fails to clone on a fresh host. Cut a new `devN` instead.
- **Never put adari in a file destined for upstream.** No adari names, no
  site names, no issue numbers, no internal hostnames — in code, comments,
  commit messages or test names on an `upstream/<topic>` branch. This repo
  is public and those branches are what a faucet maintainer reads.

## Branches

| Branch | Rule |
|---|---|
| `main` | mirror only. `git merge --ff-only upstream/main`, nothing else. |
| `adari` | `main` + the carried stack + adari-only docs. Rebased, so force-pushed. What adari installs. |
| `upstream/<topic>` | one change, in faucet's voice, off `main` — or off the topic branch it builds on (`reset-refs-by-vid` is off `reset-ports-by-vid`: it calls `VLAN.is_same_vlan()`, which only that change adds). The source of an upstream PR. |

**Every topic branch must pass faucet's suite on its own**, checked out
by itself, not only once `adari` is assembled. A branch that only works
inside the stack is not a PR source; the reset-refs branch was first cut
off `main` and failed 122 config tests there, unnoticed because only the
stack was ever tested. Run `test_config.py`, `test_vlan.py`,
`test_valve_packet.py` and `test_valve_route.py` on each branch before
pushing it.

## Pushing

`adari` is rebased, so it needs a force push — and `--force-with-lease`
**only works against a remote name**, never a bare URL (there is no
remote-tracking ref to lease against, and it fails with "stale info"):

```sh
git push origin adari --force-with-lease     # correct
git push https://github.com/... adari --force-with-lease   # always rejected
```

## Upstream's tags are already here

Forking copied 100+ upstream tags in, including the bare `1.10.x`
releases; no fetch option removes them. Under PEP 440 a bare `1.10.13`
sorts above our `1.10.13.dev1`, so adarigod's Renovate rule carries an
`allowedVersions` constraint admitting only `.devN`. That constraint is
the only thing standing between an upstream release and a green-looking
PR that reverts every carried patch. Do not weaken it.

## Faucet's gates, not adari's

Anything on a topic branch is judged by faucet's CI, which differs from
adarigod's:

- `black --check` at **88 columns** (faucet has no `pyproject.toml`, so
  black's default applies — not the 120 in `.flake8`/`.pylintrc`)
- per-file `pylint --fail-under=9.50`
- tests run under **`unittest`**, not pytest: `PYTHONPATH=. python
  tests/unit/faucet/test_vlan.py`
- 91 % coverage floor over `faucet/`

Tests for a patch belong in the same commit as the patch, in faucet's
existing test classes, named in faucet's style. A differential test
keeps the code the patch replaces **verbatim in the test file** as its
oracle (a fork has no unpatched copy to compare against) and says so in
the docstring; see `replaced_reset_refs` in `test_config.py`. Prove a
new test discriminates before committing it: break the patch the way a
regression would and watch the test fail.
