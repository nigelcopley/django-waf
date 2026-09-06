# Plan: django-waf next session (from 2.9.0)

**Status:** proposed. Not accepted, not started.
**Written:** 2026-09-06, against `origin/main` at `69c9986` (tag `v2.9.0`,
PyPI serves 2.9.0, no open PRs).
**Size:** one work item at multi-phase size (#153 adds a constraint and a
data migration), plus three items that are blocked or parked.

Everything under "Current state" was checked on disk, on origin, or on the
tracker when this plan was written. Re-check before acting: a plan is a
claim from when it was written.

---

## Current state

| Item | State on 2026-09-06 |
|---|---|
| Open issues | #153 (untriaged, filed 2026-09-05), #63, #40, #37 |
| #153 | Defect, low. Duplicate `source=auto` `BlockRule` rows render duplicate nginx `geo` entries. Claims hold on 2.9.0 source (see below). |
| #63 | Next major only. `triage:accepted`, `size:multi-phase`. Do not start. |
| #40 | Umbrella spec drift. Waits on umbrella #621. Nothing to do here. |
| #37 | `triage:needs-info`. Parked until the reporter answers. |
| Local repo | `main` only, working tree clean, worktree list is `main` only, `build/` and `dist/` removed. |
| Stash | `stash@{0}` ("teeth-check: temporarily revert source fix", sha `fa0a60f`) is still present: a repo hook blocks stash dropping from an agent session. Its two settings and their detector uses are on `main` (PR #110), so it holds nothing unmerged. Owner drops it. |
| Session URLs on `main` | Seven commits carry a `claude.ai/code` link in the body: `69c9986`, `99d1a9b`, `338944e`, `ce7e92e`, `db1e178`, `5c0e29a`, `3f5c49f`. Removing them rewrites tagged, published history. Owner decision; the recommendation is to leave them. |

### What was proven for #153 on 2.9.0, not assumed

- `src/django_waf/models.py:294-310`: `BlockRule.Meta` declares five
  indexes and no `constraints`. The only `UniqueConstraint` in the module
  (line 640) is on `RequestLog`.
- `src/django_waf/services/blocklist_generator.py:147-156`: `_render_ip_geo`
  writes one `    <pattern> 1;` line per rule with no seen-set.
  `_render_ua_map` (136-144) has the same shape.
- `src/django_waf/services/anomaly_detector.py:1844` onwards:
  `_update_or_create_auto_rule` does `filter(**lookup).select_for_update().first()`
  then `update_or_create`. `select_for_update` on an empty result locks no
  rows, so two first-time detections of the same key can both insert. The
  `MultipleObjectsReturned` path orders by `-created_at`, keeps one pk and
  deletes the rest, but only runs when the same key is detected again.
  Nothing catches `IntegrityError`, and without a constraint there is none.
- Spec: umbrella `docs/specs/django-waf/02-business-rules.md` BR-ANOM-004
  ("Auto-generated rules do not duplicate existing rules") states the
  intent the race violates. No BR-BL rule says the rendered blocklist is
  free of duplicate entries. Both need amending, and the umbrella spec is
  edited from an umbrella session, not from here (workspace rule).

---

## Goal

A consumer's `nginx -t` never warns about a duplicate network or UA entry
from the generated blocklist, whatever the `BlockRule` table holds, and a
concurrent pair of detector runs cannot persist two `source=auto` rows for
one key. Closes #153.

---

## Steps

### 1. Triage #153

- **Owner:** session. **Reversibility:** cheap.
- Apply the tracker verdict per the `issue-triage` skill. Expected labels:
  `bug`, `P3`, `triage:accepted`, `size:multi-phase` (this repo has no
  `type:*` labels).
- **Done:** labels applied, verdict comment posted, citing the file and
  line findings above.

### 2. Renderer dedupe (blocklist_generator)

- **Owner:** implementer agent, briefed to load the `django` skill.
  **Reversibility:** cheap.
- In `_render_ip_geo` and `_render_ua_map`, dedupe on the rendered key
  (stripped pattern for geo, escaped pattern for the UA map). First
  occurrence wins; the rule list arrives ordered by `Meta.ordering`
  (`priority`, `-created_at`), so first is highest priority then newest.
- Tests in `tests/test_nginx_export.py`: two active auto rules with the
  same IP pattern produce one `geo` line; same for two UA rules; a block
  and a throttle rule for the same IP still land in their own variables
  (BR-BL-001 unchanged).
- **Done:** tests pass, and output for a table with no duplicates is
  byte-identical to before (assert this in a test so the change is
  provably additive).

### 3. Partial unique constraint plus data migration (models, migration 0008)

- **Owner:** implementer agent. **Reversibility:** costly. The data
  migration deletes rows.
- Add a `UniqueConstraint` on `(rule_type, match_type, pattern, action)`
  with `condition=Q(source=<auto>)` and name `django_waf_br_auto_key_uniq`
  to `BlockRule.Meta.constraints`. Confirm the enum name for the auto
  source in `models.py` before writing it; do not guess it.
- Migration `0008`: a `RunPython` that, per key, keeps the newest row by
  `created_at` and deletes the rest (the policy the
  `MultipleObjectsReturned` branch already applies in
  `anomaly_detector.py` after line 1844), then `AddConstraint`. Reverse:
  `RemoveConstraint`; deleted rows are not restored.
- Regression test in `tests/test_migrations.py` following the file's
  existing pattern: seed two duplicate auto rows and one manual duplicate
  pair, migrate forward, assert one auto row (the newer) survives and both
  manual rows survive.
- **Done:** `makemigrations --check` is clean, the migration test passes
  on every backend leg `ci.yml` runs.

### 4. Losing side of the race re-reads (anomaly_detector)

- **Owner:** implementer agent. **Reversibility:** cheap.
- In `_update_or_create_auto_rule`, wrap the `update_or_create` in a
  nested `transaction.atomic()` savepoint, catch `IntegrityError`, then
  re-run the merge-and-update path against the row that won. Preserve the
  `created=False` semantics the docstring from line 1650 documents for a
  refreshed row.
- Test in `tests/test_detector_outcomes.py` or a new
  `tests/test_auto_rule_race.py`: simulate the race by inserting the
  winning row from a side effect just before the losing `update_or_create`
  runs; assert one row, `created=False`, and no `IntegrityError` escaping.
- **Done:** tests pass; the `MultipleObjectsReturned` branch stays (it
  still covers a consumer whose migration has not run, and manual rows the
  constraint does not cover).

### 5. Spec, changelog, release

- **Owner:** session (changelog, release), umbrella session (spec).
  **Reversibility:** tagging is irreversible.
- Changelog entry under a new `[2.10.0]` heading, dated on the day of
  tagging. Minor, not patch: `RELEASING.md:59` says any behaviour change is
  minor, and a data migration that deletes rows is one. Name the
  consumer-visible change in the consumer's terms: "upgrading deletes
  duplicate auto rules, keeping the newest per key; the generated
  blocklist no longer repeats an entry".
- File an umbrella issue for the spec amendment (BR-ANOM-004 gains the
  constraint as its mechanism; a new BR-BL rule states the rendered
  blocklist carries each key once) and cross-link it from #153. Do not
  edit the umbrella spec from a django-waf session.
- Release per the six-gate order in umbrella `CLAUDE.md` and this repo's
  `RELEASING.md`. Simulate `publish.yml`'s install list in a clean venv
  before tagging.
- **Done:** tag `v2.10.0` pushed, publish run green on the tagged commit,
  PyPI serves 2.10.0, install by name from PyPI imports the new migration.

---

## Sequencing

Step 1 gates everything: an untriaged defect is not authorised work.
Step 2 is independent of 3 and 4 and ships the consumer-visible relief
(the nginx warning) on its own; land it first so it is never held hostage
to the migration. Step 4 depends on step 3: there is no `IntegrityError`
to catch until the constraint exists. Step 5 follows all of 2 to 4 and
must not be split across releases, because a release that ships the
constraint without step 4 turns a warning into a raised exception on the
losing detector run.

---

## Risks

| Risk | Response |
|---|---|
| A consumer has manual rows that duplicate an auto row | Constraint is scoped to `source=auto`, so manual rows are untouched; step 2 handles the rendering for both. Test this explicitly in step 3. |
| The data migration deletes a row an operator was relying on | Keep-newest matches the policy the code already applies at re-detection, so it removes nothing the next detection would not have removed. Name it in the changelog. |
| Constraint name collides or exceeds a backend's identifier limit | Follow the `django_waf_br_*` naming already used for indexes; 30 characters or fewer for the Oracle-safe limit Django checks. |
| `select_for_update` semantics differ on SQLite (CI leg) | Existing code already calls it; the race test must not depend on real concurrency, hence the side-effect simulation in step 4. |
| A partial `UniqueConstraint` with a condition is not enforced on a backend CI does not run | CI runs the backends `ci.yml` lists; check that list during step 3 and state any backend the constraint is untested on in the changelog. |

---

## Rollback

- Steps 2 and 4: revert the PR.
- Step 3: `migrate django_waf 0007` removes the constraint. Deleted
  duplicate rows are not restored; the surviving row for each key is the
  one the detector would have kept anyway.
- Step 5: a published version cannot be withdrawn. If a defect is found
  after tagging, tag a fix release; never move a tag.

---

## Non-goals

- #63 (next-major template triage): not started, per its own label.
- #40: waits on umbrella #621.
- #37: waits on the reporter.
- Rewriting `main` to strip the seven session URLs: owner decision, not
  session work.
- A unique constraint over manual rules: no defect reported, and an
  operator may deliberately hold overlapping manual rules.

---

## Owner decisions requested

1. Drop the stale stash `stash@{0}` (a hook blocks it from an agent
   session). It holds nothing unmerged.
2. Leave or rewrite the seven session-URL commits on `main`. Rewriting
   moves `v2.9.0` and every earlier tag on the affected range; the
   recommendation is to leave them.
