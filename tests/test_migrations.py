"""Tests that the django_waf app has no un-migrated model changes (#105).

BlockRule.detectors was declared without a ``default=`` kwarg while the
migration that added it recorded ``default=""``, so model state and
migration-graph state disagreed. A consumer running
``manage.py makemigrations --check --dry-run`` (a standard merge-blocking CI
gate) got a spurious AlterField diff for a field they do not own, with no
local fix available.

No test in this suite ran the migration autodetector at all, so nothing
caught it. tests/settings.py sets ``MIGRATION_MODULES`` to disable migrations
for the rest of the suite (fast, migration-free test databases), which means
this check must explicitly re-enable them for django_waf rather than relying
on the ambient setting, or it would either raise ("migrations have been
disabled") or silently compare against nothing.

TestDedupeAutoBlockRules covers migration 0008's data step (#153) and works
around the same setting differently: because the test database is built
straight from the models, the partial unique constraint 0008 adds is already
present, so duplicates cannot even be inserted. The shared
``_auto_key_constraint_dropped`` fixture (tests/conftest.py) drops it, the
test seeds the pre-migration state and runs the migration's real forward
callable, and test_constraint_applies_cleanly_after_dedupe then re-adds the
constraint itself, which is the assertion that the data step left the table
clean enough to constrain.
"""

from __future__ import annotations

import datetime

import django
from django.db import connections
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState
from django.test import override_settings
from django.utils import timezone


class TestNoPendingMigrations:
    def test_django_waf_has_no_pending_model_changes(self, db):
        """The django_waf app's models match its committed migrations.

        Builds a real MigrationLoader (with MIGRATION_MODULES temporarily
        cleared so django_waf's actual migration files are read, not the
        None sentinel tests/settings.py normally installs) and asks the
        MigrationAutodetector whether current model state diverges from
        what the migration graph records. A single un-migrated field
        default is enough to trip this: it is exactly the class of drift
        that a `makemigrations --check --dry-run` CI gate would catch for
        this app, and exactly what shipped un-caught in 2.2.0 (#105).
        """
        with override_settings(MIGRATION_MODULES={}):
            connection = connections["default"]
            loader = MigrationLoader(connection, ignore_no_migrations=True)
            autodetector = MigrationAutodetector(
                loader.project_state(),
                ProjectState.from_apps(django.apps.apps),
            )
            changes = autodetector.changes(graph=loader.graph)

        pending = changes.get("django_waf", [])
        descriptions = [f"{migration.name}: {[op.describe() for op in migration.operations]}" for migration in pending]
        assert not pending, (
            "django_waf has model changes with no matching migration. "
            "Run `makemigrations django_waf` and commit the result. "
            f"Detected operations: {descriptions}"
        )


MIGRATION_0008 = ("django_waf", "0008_dedupe_auto_block_rules")
PREVIOUS_MIGRATION = ("django_waf", "0007_alter_requestlog_http_fingerprint_and_more")


class TestDedupeAutoBlockRules:
    """Migration 0008's RunPython step clears duplicate auto rules (#153)."""

    @staticmethod
    def _forward_callable():
        """Return migration 0008's real forward RunPython callable.

        Read off the migration graph rather than imported directly, so the
        test exercises the operation as the migration actually declares it:
        if the RunPython were dropped, reordered after AddConstraint, or
        replaced, this lookup changes with it.
        """
        from django.db.migrations import RunPython

        with override_settings(MIGRATION_MODULES={}):
            loader = MigrationLoader(connections["default"], ignore_no_migrations=True)
            migration = loader.disk_migrations[MIGRATION_0008]
            run_pythons = [op for op in migration.operations if isinstance(op, RunPython)]

        assert len(run_pythons) == 1, "0008 should declare exactly one RunPython data step"
        return run_pythons[0].code

    @staticmethod
    def _historical_apps():
        """Historical model registry as of the migration before 0008."""
        with override_settings(MIGRATION_MODULES={}):
            loader = MigrationLoader(connections["default"], ignore_no_migrations=True)
            return loader.project_state(PREVIOUS_MIGRATION).apps

    def test_keeps_newest_auto_rule_and_leaves_admin_duplicates(self, _auto_key_constraint_dropped):
        """Duplicate auto rules collapse to the newest; admin duplicates survive.

        The constraint is partial (condition source=auto), so manually
        curated admin rules are deliberately not covered by it and the data
        step must not touch them. Asserting on ``name`` rather than a bare
        count is what distinguishes "kept the newest" from "kept whichever
        row the database happened to return first".
        """
        from django_waf.models import BlockRule

        now = timezone.now()

        # Two auto rows sharing one (rule_type, pattern, action) key. created_at
        # is auto_now_add, so it has to be forced with an UPDATE after creation.
        older_auto = BlockRule.objects.create(
            name="auto older",
            rule_type="ip",
            match_type="exact",
            pattern="203.0.113.7",
            action="block",
            source="auto",
        )
        newer_auto = BlockRule.objects.create(
            name="auto newer",
            rule_type="ip",
            # Differs only in match_type, which is in the detector's defaults
            # rather than its lookup, so these two really are one key.
            match_type="regex",
            pattern="203.0.113.7",
            action="block",
            source="auto",
        )
        BlockRule.objects.filter(pk=older_auto.pk).update(created_at=now - datetime.timedelta(days=5))
        BlockRule.objects.filter(pk=newer_auto.pk).update(created_at=now)

        # Two admin rows sharing a different key. Not covered by the partial
        # constraint, so both must survive the data step untouched.
        first_admin = BlockRule.objects.create(
            name="admin first",
            rule_type="ip",
            match_type="exact",
            pattern="198.51.100.4",
            action="block",
            source="admin",
        )
        second_admin = BlockRule.objects.create(
            name="admin second",
            rule_type="ip",
            match_type="exact",
            pattern="198.51.100.4",
            action="block",
            source="admin",
        )
        BlockRule.objects.filter(pk=first_admin.pk).update(created_at=now - datetime.timedelta(days=5))
        BlockRule.objects.filter(pk=second_admin.pk).update(created_at=now)

        forwards = self._forward_callable()
        forwards(self._historical_apps(), connections["default"].schema_editor())

        surviving_auto = BlockRule.objects.filter(source="auto")
        assert surviving_auto.count() == 1
        # The survivor is the newer row specifically, not merely "one of them".
        assert surviving_auto.get().name == "auto newer"
        assert not BlockRule.objects.filter(pk=older_auto.pk).exists()

        surviving_admin = BlockRule.objects.filter(source="admin").order_by("created_at")
        assert [rule.name for rule in surviving_admin] == ["admin first", "admin second"]

    def test_constraint_applies_cleanly_after_dedupe(self, _auto_key_constraint_dropped):
        """After the data step, the table can actually take the constraint.

        This is the reason 0008 orders RunPython before AddConstraint: on a
        database carrying pre-existing duplicates, AddConstraint alone fails
        outright. Re-adding the constraint here is a live proof that the data
        step left no duplicate auto key behind.
        """
        from django_waf.models import BlockRule

        constraint = _auto_key_constraint_dropped
        now = timezone.now()

        older = BlockRule.objects.create(
            name="auto older",
            rule_type="ua",
            match_type="contains",
            pattern="BadBot",
            action="block",
            source="auto",
        )
        BlockRule.objects.create(
            name="auto newer",
            rule_type="ua",
            match_type="contains",
            pattern="BadBot",
            action="block",
            source="auto",
        )
        BlockRule.objects.filter(pk=older.pk).update(created_at=now - datetime.timedelta(days=1))

        forwards = self._forward_callable()
        forwards(self._historical_apps(), connections["default"].schema_editor())

        connection = connections["default"]
        with connection.schema_editor() as schema_editor:
            schema_editor.add_constraint(BlockRule, constraint)
