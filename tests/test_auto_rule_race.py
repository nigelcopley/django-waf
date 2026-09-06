"""Lost-insert-race handling for auto-generated BlockRules (#153, step 4).

Migration 0008 adds a partial UniqueConstraint on
(rule_type, pattern, action) WHERE source=auto. Before it, two concurrent
detector runs that each read no existing row both inserted, leaving
duplicates. With it, the losing INSERT is rejected by the database, so
``_update_or_create_auto_rule`` must catch the IntegrityError inside a
savepoint and merge into the row that won instead of letting the exception
reach the consumer.

House discipline, mirroring ``tests/test_detector_outcomes.py``: every
assertion must be provably falsifiable. The race is simulated
deterministically rather than with real threads, by ``_RaceInjector``, which
commits the winning row outside the savepoint and forces the losing run down
``update_or_create``'s INSERT branch so the constraint really rejects it.
See that class's docstring for why both halves are needed and which simpler
framings do not reproduce the race at all.

Each race test pairs its assertion with a control: the no-race counterpart
is asserted in the same file, so "created is False" is evidence of a
refresh rather than of the return value being False under every path.
"""

from __future__ import annotations

import contextlib
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.db import IntegrityError
from django.utils import timezone

import django_waf.conf as conf_mod
import django_waf.services.anomaly_detector as detector_mod
from django_waf.enums import MatchType, ReviewStatus, RuleAction, RuleSource, RuleType
from django_waf.models import BlockRule

pytestmark = pytest.mark.django_db(transaction=True)


PATTERN = "198.51.100.77"


def _call_kwargs(**overrides) -> dict:
    """Arguments for a single _get_or_create_auto_rule call.

    Deliberately fixes the whole auto key (rule_type, pattern, action) so
    two calls with different detector names still collide on the constraint,
    which is the situation under test.
    """
    kwargs = {
        "name": "auto-block-198.51.100.77",
        "rule_type": RuleType.IP,
        "match_type": MatchType.EXACT,
        "pattern": PATTERN,
        "action": RuleAction.BLOCK,
        "expiry": timezone.now() + timedelta(hours=24),
        "detector_name": "detect_ua_rotation",
    }
    kwargs.update(overrides)
    return kwargs


def _insert_winner(**overrides) -> BlockRule:
    """Insert the row that "wins" the race, directly, as a rival run would.

    Built with the same auto key the losing call uses, so the partial
    UniqueConstraint sees the two as the same row.
    """
    fields = {
        "name": "winner-rule",
        "rule_type": RuleType.IP,
        "match_type": MatchType.EXACT,
        "pattern": PATTERN,
        "action": RuleAction.BLOCK,
        "source": RuleSource.AUTO,
        "is_active": True,
        "review_status": ReviewStatus.NOT_APPLICABLE,
        "detectors": "detect_cloud_spray",
        "expires_at": timezone.now() + timedelta(hours=1),
    }
    fields.update(overrides)
    return BlockRule.objects.create(**fields)


class _RaceInjector:
    """Simulate losing the insert race, at the two points that matter.

    Getting this window right needs care, and two earlier framings were
    wrong in ways worth recording so they are not reintroduced:

    1. Inserting the winner only before ``update_or_create`` is too early.
       ``update_or_create`` performs its OWN ``get()`` and INSERTs only when
       that raises DoesNotExist, so it would simply find the winner, take its
       UPDATE branch, raise no IntegrityError, and never reach the recovery
       path under test.
    2. Inserting the winner INSIDE the savepoint that the failing INSERT
       rolls back is also wrong. The rollback removes the winner along with
       the failed INSERT, so the retry's existence check finds nothing and
       the code raises DoesNotExist. In production the rival run commits in a
       separate transaction, which a savepoint rollback cannot undo.

    So the winner is inserted from the ``_auto_rule_write_defaults`` wrapper,
    which runs BEFORE ``transaction.atomic()`` opens the savepoint, and the
    ``update_or_create`` wrapper separately forces the INSERT branch so the
    database actually rejects the duplicate. The winner therefore survives
    the savepoint rollback, exactly as a committed rival row would.

    ``defaults_calls`` counts the write-defaults derivations, so a test can
    assert the retry really re-derived them rather than reusing the stale set.
    """

    def __init__(self, winner_kwargs: dict | None = None, delete_instead: bool = False):
        self.winner_kwargs = winner_kwargs or {}
        self.delete_instead = delete_instead
        self.defaults_calls = 0
        self.uoc_calls = 0
        self.winner: BlockRule | None = None

    def write_defaults(self, lookup, defaults, detector_name):
        """Wrapper for _auto_rule_write_defaults: runs outside the savepoint."""
        self.defaults_calls += 1
        if self.defaults_calls == 2 and self.delete_instead:
            # Requirement 5: the winner vanishes between the IntegrityError
            # and the retry's re-read. Deleted BEFORE the wrapped call, so
            # the re-read genuinely returns None: _auto_rule_write_defaults
            # returns the row it read, and it is that returned value the
            # production code tests, so deleting afterwards would leave a
            # stale non-None row and the vanished-winner branch would never
            # be reached.
            BlockRule.objects.filter(pk=self.winner.pk).delete()

        result = self.original_defaults(lookup, defaults, detector_name)

        if self.defaults_calls == 1:
            # The rival run commits its row here, in the window between this
            # run's read (just done, saw nothing) and its INSERT below.
            self.winner = _insert_winner(**self.winner_kwargs)
        return result

    def update_or_create(self, **kwargs):
        """Wrapper for update_or_create: forces the INSERT branch once.

        Without this the call would see the winner inserted above and take
        its UPDATE branch, so the constraint would never fire.
        """
        self.uoc_calls += 1
        if self.uoc_calls == 1:
            lookup = {k: v for k, v in kwargs.items() if k != "defaults"}
            fields = {**lookup, **kwargs.get("defaults", {})}
            return BlockRule.objects.create(**fields), True
        return self.original_uoc(**kwargs)


@contextlib.contextmanager
def _patched_injector(injector: _RaceInjector):
    injector.original_defaults = detector_mod._auto_rule_write_defaults
    injector.original_uoc = BlockRule.objects.update_or_create
    with (
        patch.object(detector_mod, "_auto_rule_write_defaults", injector.write_defaults),
        patch.object(BlockRule.objects, "update_or_create", injector.update_or_create),
    ):
        yield injector


# ---------------------------------------------------------------------------
# Control: no race
# ---------------------------------------------------------------------------


class TestNoRaceControl:
    def test_first_ever_detection_inserts_and_reports_created_true(self):
        """The positive control for every created=False assertion below.

        Without this, "created is False" on the race path proves nothing:
        it could mean the function never reports True at all.
        """
        rule, created = detector_mod._get_or_create_auto_rule(**_call_kwargs())

        assert created is True
        assert BlockRule.objects.filter(pattern=PATTERN, source=RuleSource.AUTO).count() == 1
        assert rule.detectors == "detect_ua_rotation"

    def test_second_detection_of_the_same_key_refreshes_and_reports_created_false(self):
        """Ordinary (non-race) refresh: one row, created=False, merged set."""
        detector_mod._get_or_create_auto_rule(**_call_kwargs())

        rule, created = detector_mod._get_or_create_auto_rule(**_call_kwargs(detector_name="detect_cloud_spray"))

        assert created is False
        assert BlockRule.objects.filter(pattern=PATTERN, source=RuleSource.AUTO).count() == 1
        assert rule.detectors == "detect_cloud_spray,detect_ua_rotation"

    def test_the_constraint_itself_rejects_a_second_auto_row_for_the_same_key(self):
        """Falsifiability check for the whole file: prove the database really
        does reject the duplicate, so the recovery path below is exercising a
        real IntegrityError and not a no-op."""
        _insert_winner()

        with pytest.raises(IntegrityError):
            _insert_winner(name="second-row", detectors="")


# ---------------------------------------------------------------------------
# The race path
# ---------------------------------------------------------------------------


class TestLostInsertRace:
    def test_losing_run_merges_into_the_winner_without_raising(self):
        """The core guarantee: no IntegrityError escapes, exactly one row
        survives, and the losing run reports created=False because it
        refreshed a row that already existed."""
        injector = _RaceInjector()

        with _patched_injector(injector):
            rule, created = detector_mod._get_or_create_auto_rule(**_call_kwargs())

        assert injector.defaults_calls == 2, "the retry path must re-derive the write defaults"
        assert created is False
        assert BlockRule.objects.filter(pattern=PATTERN, source=RuleSource.AUTO).count() == 1
        assert rule.pk == injector.winner.pk

    def test_losing_run_contributes_its_detector_name_to_the_merged_set(self):
        """#97 additivity must survive the race path: the winner's own
        detector name is kept AND the loser's is added, rather than either
        side clobbering the other."""
        injector = _RaceInjector(winner_kwargs={"detectors": "detect_cloud_spray"})

        with _patched_injector(injector):
            rule, _created = detector_mod._get_or_create_auto_rule(**_call_kwargs(detector_name="detect_ua_rotation"))

        rule.refresh_from_db()
        assert rule.detectors == "detect_cloud_spray,detect_ua_rotation"

    def test_losing_run_does_not_overwrite_a_confirmed_winner(self):
        """BR-ANOM-007 across the race path: an operator's CONFIRMED decision
        on the winning row survives a concurrent detector run that lost the
        insert. is_active and review_status must be untouched.

        Paired with the unreviewed counterpart below, so this is evidence the
        guard fired rather than that the race path never writes those fields.
        """
        injector = _RaceInjector(
            winner_kwargs={
                "is_active": True,
                "review_status": ReviewStatus.CONFIRMED,
                "detectors": "detect_cloud_spray",
            }
        )

        with (
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
            _patched_injector(injector),
        ):
            rule, created = detector_mod._get_or_create_auto_rule(**_call_kwargs())

        rule.refresh_from_db()
        assert created is False
        # Quarantine was on, so an unguarded write would have forced
        # is_active=False / review_status=PENDING (proven by the next test).
        assert rule.is_active is True
        assert rule.review_status == ReviewStatus.CONFIRMED
        assert "detect_ua_rotation" in rule.detectors.split(",")

    def test_losing_run_does_overwrite_an_unreviewed_winner(self):
        """The direction test for the assertion above: with the same
        quarantine setting, an unreviewed (NOT_APPLICABLE) winner IS
        rewritten to the quarantined state. Without this, the CONFIRMED
        assertion cannot distinguish a working guard from a race path that
        writes nothing at all."""
        injector = _RaceInjector(
            winner_kwargs={
                "is_active": True,
                "review_status": ReviewStatus.NOT_APPLICABLE,
            }
        )

        with (
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
            _patched_injector(injector),
        ):
            rule, _created = detector_mod._get_or_create_auto_rule(**_call_kwargs())

        rule.refresh_from_db()
        assert rule.is_active is False
        assert rule.review_status == ReviewStatus.PENDING

    def test_outer_transaction_is_usable_after_the_recovered_race(self):
        """The savepoint requirement, stated directly: an IntegrityError left
        unrolled-back inside the caller's atomic() block makes every later
        query raise TransactionManagementError. A query issued straight after
        the recovered call proves the outer transaction survived."""
        injector = _RaceInjector()

        with _patched_injector(injector):
            detector_mod._get_or_create_auto_rule(**_call_kwargs())

        # Would raise TransactionManagementError without the savepoint.
        assert BlockRule.objects.filter(source=RuleSource.AUTO).count() == 1


# ---------------------------------------------------------------------------
# Requirement 5: the winner vanishes before the re-read
# ---------------------------------------------------------------------------


class TestWinnerDeletedAfterIntegrityError:
    def test_vanished_winner_raises_does_not_exist_rather_than_returning_none(self):
        """A genuine double race: this run lost the insert, then the winning
        row was deleted (expiry sweep, operator delete, concurrent dedupe)
        before it could be merged into. There is no rule to return, so the
        function raises rather than handing None to callers that dereference
        it, and rather than silently re-inserting into a key the database has
        just proved was contended."""
        injector = _RaceInjector(delete_instead=True)

        with _patched_injector(injector), pytest.raises(BlockRule.DoesNotExist) as exc_info:
            detector_mod._get_or_create_auto_rule(**_call_kwargs())

        assert "vanished after a lost insert race" in str(exc_info.value)

    def test_vanished_winner_does_not_leave_a_resurrected_row_behind(self):
        """The raise must not be accompanied by a silent re-insert: after it,
        no auto row for the key exists. Guards against a future "just retry
        the insert" shim reintroducing the duplicate this whole change
        removes."""
        injector = _RaceInjector(delete_instead=True)

        with _patched_injector(injector), pytest.raises(BlockRule.DoesNotExist):
            detector_mod._get_or_create_auto_rule(**_call_kwargs())

        assert not BlockRule.objects.filter(pattern=PATTERN, source=RuleSource.AUTO).exists()


# ---------------------------------------------------------------------------
# The MultipleObjectsReturned branch must survive (requirement 4)
# ---------------------------------------------------------------------------


class TestMultipleObjectsReturnedBranchStillCovers:
    def test_pre_existing_duplicates_are_still_deduplicated_and_retried(self):
        """Requirement 4: the constraint does not make this branch redundant.
        A consumer whose migration 0008 has not run can still hold duplicate
        auto rows, so the dedupe-and-retry path must remain reachable.

        Simulated by making the first update_or_create raise
        MultipleObjectsReturned, which is what an unconstrained database
        with duplicate rows produces, rather than by inserting duplicates the
        test database's constraint would reject.
        """
        real_update_or_create = BlockRule.objects.update_or_create
        state = {"calls": 0}

        def _raise_once(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] == 1:
                raise BlockRule.MultipleObjectsReturned
            return real_update_or_create(*args, **kwargs)

        with patch.object(BlockRule.objects, "update_or_create", side_effect=_raise_once):
            rule, created = detector_mod._get_or_create_auto_rule(**_call_kwargs())

        assert state["calls"] == 2, "the dedupe branch must retry the write"
        assert created is True
        assert rule.pattern == PATTERN
