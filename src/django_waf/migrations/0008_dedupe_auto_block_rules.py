"""Deduplicate auto-generated BlockRule rows, then constrain the key (#153).

The anomaly detector keys an auto-generated rule on
(rule_type, pattern, source=AUTO, action). Two concurrent runs could each
fail to see the other's row and both insert, so existing databases can hold
duplicates for a single key. AddConstraint would fail outright on those rows,
so the RunPython below clears them first.

The forward callable is a hand-written data migration, one of the cases where
a hand edit to a generated migration is allowed. It uses the historical model
via apps.get_model and imports nothing from django_waf, so it stays valid
however the app's current code later changes. It is expressed entirely in the
ORM (no backend-specific SQL), because the suite runs on both SQLite and
PostgreSQL.

Dedupe policy mirrors _deduplicate_block_rules in
services/anomaly_detector.py exactly: order by -created_at and keep the newest
row of each group, deleting the rest.
"""

from django.db import migrations, models


def dedupe_auto_block_rules(apps, schema_editor):
    """Keep only the newest auto rule per (rule_type, pattern, action) group.

    Only source="auto" rows are touched. Admin and feed rules are curated by
    hand and are not covered by the partial constraint, so duplicates among
    them are legitimate and must survive.
    """
    BlockRule = apps.get_model("django_waf", "BlockRule")

    auto_rules = BlockRule.objects.filter(source="auto")
    duplicate_keys = (
        auto_rules.values("rule_type", "pattern", "action")
        .annotate(row_count=models.Count("id"))
        .filter(row_count__gt=1)
    )

    stale_pks = []
    for key in duplicate_keys:
        group = auto_rules.filter(
            rule_type=key["rule_type"],
            pattern=key["pattern"],
            action=key["action"],
        ).order_by("-created_at")
        # Keep the newest, discard the rest. Matches the runtime policy in
        # _deduplicate_block_rules: the most recent write carries the freshest
        # detector evidence, expiry and review status.
        stale_pks.extend(group.values_list("id", flat=True)[1:])

    if stale_pks:
        BlockRule.objects.filter(id__in=stale_pks).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("django_waf", "0007_alter_requestlog_http_fingerprint_and_more"),
    ]

    operations = [
        # Deleted duplicate rows cannot be reconstructed, so the reverse is a
        # noop: reversing this migration drops the constraint and leaves the
        # surviving rows in place rather than pretending to restore data.
        migrations.RunPython(dedupe_auto_block_rules, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="blockrule",
            constraint=models.UniqueConstraint(
                condition=models.Q(("source", "auto")),
                fields=("rule_type", "pattern", "action"),
                name="django_waf_br_auto_key_uniq",
            ),
        ),
    ]
