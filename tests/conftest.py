"""Shared pytest fixtures for django-waf tests."""

import pytest
from django.db import connections

AUTO_KEY_CONSTRAINT = "django_waf_br_auto_key_uniq"


@pytest.fixture(autouse=True)
def _clear_rule_cache():
    """Reset the in-process rule cache between tests."""
    import django_waf.services.rule_engine as re_mod

    re_mod._process_cache = None
    re_mod._process_cache_version = -1
    yield
    re_mod._process_cache = None
    re_mod._process_cache_version = -1


@pytest.fixture
def _auto_key_constraint_dropped(transactional_db):
    """Drop the auto-key partial unique constraint for the duration of a test.

    The suite builds its schema from the models (MIGRATION_MODULES disables
    migrations), so BlockRule's partial unique constraint exists from the
    moment the table does. A test that needs to seed the duplicate rows
    migration 0008 was written to clean up therefore has to remove it first,
    or the seeding itself raises IntegrityError.

    ``transactional_db`` rather than ``db`` is required, not a preference.
    Django's SQLite schema editor refuses to run inside an open atomic block
    ("SQLite schema editor cannot be used while foreign key constraint checks
    are enabled"), which is exactly what the ``db`` fixture holds open for the
    whole test, so this fixture raised NotSupportedError at setup on SQLite
    while working fine on PostgreSQL.

    Because a transactional test truncates tables rather than rolling back,
    schema changes are NOT undone automatically: the constraint is explicitly
    restored on teardown, or every later test in the same process would run
    against a table that has silently lost it.
    """
    from django_waf.models import BlockRule

    constraint = next(c for c in BlockRule._meta.constraints if c.name == AUTO_KEY_CONSTRAINT)
    connection = connections["default"]
    with connection.schema_editor() as schema_editor:
        schema_editor.remove_constraint(BlockRule, constraint)
    try:
        yield constraint
    finally:
        with connection.cursor() as cursor:
            still_present = AUTO_KEY_CONSTRAINT in connection.introspection.get_constraints(
                cursor, BlockRule._meta.db_table
            )
        if not still_present:
            # A test may legitimately have re-added it itself (that is the
            # assertion in test_constraint_applies_cleanly_after_dedupe), so
            # only restore when it is actually missing.
            BlockRule.objects.filter(source="auto").delete()
            with connection.schema_editor() as schema_editor:
                schema_editor.add_constraint(BlockRule, constraint)


def pytest_configure(config):
    """Ensure django_waf is in INSTALLED_APPS when running from the project root."""
    from django.conf import settings

    if not settings.configured:
        return
    for app in ("django_waf",):
        if app not in settings.INSTALLED_APPS:
            settings.INSTALLED_APPS = [*settings.INSTALLED_APPS, app]
    if not hasattr(settings, "MIGRATION_MODULES"):
        settings.MIGRATION_MODULES = {}
    settings.MIGRATION_MODULES.setdefault("django_waf", None)

    # Ensure ROOT_URLCONF is always set, Django 6 removed the global default,
    # and override_settings can lose it if a site-packages "tests" package
    # shadows the project's tests/ directory during re-resolution.
    if not hasattr(settings, "ROOT_URLCONF"):
        settings.ROOT_URLCONF = "tests.urls"

    # Ensure WAF settings exist for tests
    defaults = {
        "DJANGO_WAF_ENABLED": True,
        "DJANGO_WAF_FEED_ENABLED": False,
        "DJANGO_WAF_FEED_REPORT": False,
        "DJANGO_WAF_LOG_SAMPLE_RATE": 1.0,
    }
    for key, value in defaults.items():
        if not hasattr(settings, key):
            setattr(settings, key, value)
