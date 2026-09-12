# adaricorp/faucet

A fork of [`faucetsdn/faucet`](https://github.com/faucetsdn/faucet) carrying
the patches adari runs in production, and the place upstream PRs are sent
from. Upstream's own `README.rst` is untouched; this file is the fork's.

## Why a fork

adari used to apply these changes at runtime, monkeypatching faucet from a
launcher. Upstream ships a release roughly every two years (1.10.11 in Apr
2024, 1.10.12 in Mar 2026) and a core maintainer's own PRs have sat
unmerged for months, so *something* was going to carry them for years
either way. A fork is one copy of the code with faucet's own CI on it; the
launcher was two copies kept in agreement by behaviour rather than by text.

A fork is also the only way to open a PR upstream.

## Branches

| Branch | What it is |
|---|---|
| `main` | mirror of `upstream/main`. Never carries a local commit. |
| `adari` | `main` + the carried stack. Rebased on every sync, so it is force-pushed. **What adari installs, via a tag.** |
| `upstream/<topic>` | one per change, holding only that change, off `main` — or off the topic branch it builds on. What a PR to `faucetsdn/faucet` is opened from. |

## Carried patches

Four changes, four PRs. They touch disjoint files, but they are not all
independent: `reset-refs-by-vid` calls `VLAN.is_same_vlan()`, which
`reset-ports-by-vid` adds, so its branch is stacked on that one and its
PR opens after (or on top of) the reset-ports PR. The other three stand
alone. A topic branch must pass faucet's suite **on its own**, not only
once the stack is assembled — the reset-refs branch was first cut off
`main` and failed 122 config tests there.

| Topic branch | Off | Changes | Upstream issue tracked in adarigod |
|---|---|---|---|
| `upstream/reset-ports-by-vid` | `main` | `VLAN.reset_ports` compares VIDs instead of hashing whole VLAN configs | adarigod#2735 |
| `upstream/reset-refs-by-vid` | `upstream/reset-ports-by-vid` | `DP.reset_refs` groups ports by VID and port number | adarigod#2736 |
| `upstream/arp-padding` | `main` | `PacketMeta.packet_complete` accepts a fixed-size protocol whose padding was discarded | adarigod#2737 |
| `upstream/routed-vlans-by-vid` | `main` | `ValveRouteManager` looks a VLAN's routers up by VID | adarigod#2760 |

The parse and route-manager changes carry differential tests: the code
they replace is kept verbatim in the test file as the oracle, since a fork
has no unpatched copy to compare against, and a seeded sample of generated
configs (or router sets) must give the same answer either way. The parse
one also pins the number of `Conf.__hash__` calls, the quantity the change
exists to remove — every membership result stays identical when the VID
short-circuit is lost, so the count is the only thing that notices.

Measured on a rendered config with 1,717 VLANs, 3,426 routers, 7,735 ACLs:
parse **421 s → 14 s** (the two parse patches), cold-start flow-table build
**4.1 s → 2.1 s** (the routed-VLAN one). The cold-start flow table is
byte-identical throughout — 124,715 lines, SHA-256
`911c29b5c2a01e35a67207d87670753a503dd66f13b62f9f3c65e8cfeda572cd`.

Verified on faucet `main` (160fbc34): all four apply cleanly, and faucet's
own suite goes `test_vlan` 12 → 16, `test_config` 204 → 213,
`test_valve_packet` 0 → 4, `test_valve_route` 0 → 7, all passing.

## Tags are the contract

adari depends on this fork **by tag**, never by branch:

```toml
faucet = { git = "https://github.com/adaricorp/faucet.git", tag = "v1.10.13.devN" }
```

- A tag is immutable, and `adari` is force-pushed on every rebase. A
  `poetry.lock` pinning a branch SHA that no ref reaches any more fails to
  clone on a fresh host — silently, and only on the hosts that install
  after the rebase.
- **Never delete a tag any shipped adarigod lock references.**
- Ours are `v`-prefixed and carry a `.devN` segment. pbr reads the tag, so
  `v1.10.13.dev1` installs as `1.10.13.dev1` — verified through a real
  `poetry lock && poetry install`.

### Upstream's tags are already here, and that is the hazard

Forking copied **all** of upstream's tags into this repo (100+, including
the bare `1.10.x` releases). They arrived at fork creation, so no fetch
option keeps them out.

That matters because adari's Renovate watches this repo with the
`github-tags` datasource. Under PEP 440 a bare `1.10.13` sorts **above**
our `1.10.13.dev1`, so the day upstream cuts a release, Renovate would
propose moving adari onto it — a green-looking PR that quietly reverts
every carried patch.

The protection is the `allowedVersions` constraint on adarigod's `faucet`
Renovate rule, which only admits `.devN` tags. `git fetch upstream
--no-tags` is still the right habit for the sync below, but it is hygiene,
not the guard.

## Syncing with upstream

```sh
git fetch upstream --no-tags
git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout adari && git rebase main          # conflicts = upstream touched what we patch
# fork CI runs faucet's own suite here
git tag -a v1.10.13.devN -m '...' && git push origin adari --force-with-lease
git push origin v1.10.13.devN
# then bump the tag in adarigod's pyproject.toml and re-lock
```

Rebase rather than merge: a patch upstream has taken is **dropped
automatically** on the next rebase (patch-id match), so `git log
main..adari` is always exactly what we still carry.

When upstream cuts a real `1.10.13`, rebase onto it deliberately and retag
`v1.10.14.dev1`.

## Sending a patch upstream

PRs to `faucetsdn/faucet` are opened **by a person**, from an
`upstream/<topic>` branch, and never automatically. Once a PR is open, fix
the commit *through* that PR rather than amending here, or the patch-ids
diverge and the auto-drop above stops working. When upstream merges a
modified version, drop ours and re-add only the delta still wanted.

Faucet's gates, for anything sent: `black --check` at 88 columns (it has no
`pyproject.toml`, so black's default applies, not the 120 in `.flake8`),
per-file pylint at `--fail-under=9.50`, `unittest`, and a 91 % coverage
floor over `faucet/`.
