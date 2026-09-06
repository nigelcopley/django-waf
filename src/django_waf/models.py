"""Models for django-waf."""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_waf.enums import (
    ChallengeStatus,
    MatchType,
    RequestLogSource,
    ReviewStatus,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)

# ---------------------------------------------------------------------------
# Abstract base model, UUID PK + timestamps
# ---------------------------------------------------------------------------


class BaseModel(models.Model):
    """Abstract base with UUID primary key and created/updated timestamps.

    Field-compatible with ``icv_core.models.BaseModel`` for projects that use
    the ICV-Django ecosystem, but fully standalone, no external dependency.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# ---------------------------------------------------------------------------
# BlockRule
# ---------------------------------------------------------------------------


class BlockRuleManager(models.Manager):
    """Custom manager for BlockRule with convenience querysets."""

    def active(self) -> models.QuerySet:
        """Return all active, non-expired rules ordered by priority.

        Excludes rules whose expires_at has passed even when is_active is
        still True, the periodic expire_rules task deactivates those, but
        evaluation must not enforce a rule that has expired in the gap
        before that task next runs (#25).
        """
        not_expired = Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        return self.filter(is_active=True).filter(not_expired).order_by("priority")

    def for_nginx(self) -> models.QuerySet:
        """Return active IP/CIDR/UA block or throttle rules suitable for nginx export.

        Deliberately excludes ``action=challenge`` rules (BR-BL-005 excludes
        log_only for the same reason): nginx cannot serve or verify a JS
        proof-of-work, so a CHALLENGE rule can only be enforced by
        WafMiddleware, not at the edge. detect_ua_rotation,
        detect_subnet_burst, and detect_cloud_spray all auto-create
        CHALLENGE rules on first detection (a deliberately weaker verdict
        for a weak signal, see anomaly_detector.py), so their output is
        middleware-only until repeated triggering escalates the IP to a
        BLOCK rule (rule_engine._create_escalation_rule), at which point it
        starts appearing here. An operator relying solely on the nginx
        blocklist for enforcement will not see these rules at the edge
        until that promotion happens.
        """
        return self.active().filter(
            rule_type__in=[RuleType.IP, RuleType.CIDR, RuleType.UA],
            action__in=[RuleAction.BLOCK, RuleAction.THROTTLE],
        )

    def auto_generated(self) -> models.QuerySet:
        """Return active auto-generated rules."""
        return self.active().filter(source=RuleSource.AUTO)

    def feed_sourced(self) -> models.QuerySet:
        """Return active rules sourced from the collective threat feed."""
        return self.active().filter(source=RuleSource.FEED)

    def expired(self) -> models.QuerySet:
        """Return active rules whose expiry time has passed."""
        return self.filter(is_active=True, expires_at__lte=timezone.now())

    def stale(self, days: int) -> models.QuerySet:
        """Return auto-generated rules safe to hard-delete under retention (wave 2, the rule-provenance wave).

        A row qualifies only when ALL of the following hold:

        - ``source=RuleSource.AUTO``. An operator's hand-authored ``admin``
          rule or a ``feed``-sourced rule is a deliberate, reviewed
          artefact; this retention path exists for the class of rows that
          regenerate themselves on the next detector run (BR-ANOM-007's
          ``update_or_create`` re-detection path), not for rows a human
          typed in.
        - ``is_active=False``: never delete an enforcing rule, quarantined
          or otherwise. Mirrors ``expired()``'s own is_active gate.
        - ``expires_at`` is set and at least ``days`` in the past. A rule
          that never expires (``expires_at is None``) is excluded
          unconditionally, regardless of ``is_active``: BR-ANOM-007's
          quarantine path is the one way a ``source=AUTO`` row can be
          ``is_active=False`` with no ``expires_at``, and that state means
          "awaiting review", not "safe to reclaim".
        - ``review_status`` is ``NOT_APPLICABLE`` or ``EXPIRED_UNREVIEWED``.
          ``PENDING`` and ``CONFIRMED`` are excluded per this wave's plan.
          ``REJECTED`` is also excluded, deliberately, and is the one
          divergence from a literal reading of the plan (which named only
          three states against a five-state enum): a ``REJECTED`` row
          records an operator's explicit decision that this exact pattern
          must not be blocked. Deleting it does not undo that decision, it
          only erases the record of it, so the next time a detector
          re-observes the same pattern it recreates the rule from
          scratch and the operator has to reject it again. Keeping
          ``REJECTED`` rows is the cheaper failure mode: a few extra
          quarantined rows outlive the retention window, versus an
          operator re-litigating a decision they already made once.
        """
        cutoff = timezone.now() - timedelta(days=days)
        return self.filter(
            source=RuleSource.AUTO,
            is_active=False,
            expires_at__isnull=False,
            expires_at__lt=cutoff,
            review_status__in=[ReviewStatus.NOT_APPLICABLE, ReviewStatus.EXPIRED_UNREVIEWED],
        )


def _validate_rule_pattern(rule_type: str, match_type: str, pattern: str) -> None:
    """Reject a catastrophic or invalid UA regex pattern on any save path.

    Guards the ORM entry points (services, data migrations, shell) that the
    admin form and feed importer do not cover, so a ReDoS-prone pattern cannot
    reach the per-request matcher regardless of how the rule was created (#28).
    Only user-agent regex rules carry the risk; other rule types are untouched.
    """
    if rule_type != RuleType.UA or match_type != MatchType.REGEX:
        return
    from django.core.exceptions import ValidationError

    from django_waf.services.pattern_validation import (
        PatternValidationError,
        validate_ua_regex_pattern,
    )

    try:
        validate_ua_regex_pattern(pattern)
    except PatternValidationError as exc:
        raise ValidationError({"pattern": str(exc)}) from exc


class BlockRule(BaseModel):
    """
    A WAF rule that triggers a block, challenge, throttle, or log action.

    Rules are evaluated in priority order (lowest number first). The first
    matching rule's action is applied to the request.
    """

    name = models.CharField(
        max_length=255,
        verbose_name=_("name"),
    )
    rule_type = models.CharField(
        max_length=20,
        choices=RuleType.choices,
        db_index=True,
        verbose_name=_("rule type"),
    )
    match_type = models.CharField(
        max_length=20,
        choices=MatchType.choices,
        verbose_name=_("match type"),
    )
    pattern = models.CharField(
        max_length=2048,
        db_index=True,
        verbose_name=_("pattern"),
        help_text=_("Value to match against (IP, CIDR, user-agent string, or regex)."),
    )
    action = models.CharField(
        max_length=20,
        choices=RuleAction.choices,
        default=RuleAction.BLOCK,
        verbose_name=_("action"),
    )
    priority = models.PositiveIntegerField(
        default=100,
        db_index=True,
        verbose_name=_("priority"),
        help_text=_("Lower numbers are evaluated first."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("active"),
    )
    source = models.CharField(
        max_length=20,
        choices=RuleSource.choices,
        default=RuleSource.ADMIN,
        verbose_name=_("source"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("expires at"),
        help_text=_("Leave blank for rules that never expire."),
    )
    hit_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("hit count"),
    )
    last_hit_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("last hit at"),
    )
    confidence = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal("1.00"),
        verbose_name=_("confidence"),
        help_text=_("Confidence score from 0.00 to 1.00 (feed-sourced rules only)."),
    )
    feed_first_seen = models.DateField(
        null=True,
        blank=True,
        verbose_name=_("feed first seen"),
    )
    feed_reporters = models.PositiveIntegerField(
        default=0,
        verbose_name=_("feed reporters"),
        help_text=_("Number of sites that reported this threat to the collective feed."),
    )
    notes = models.TextField(
        blank=True,
        verbose_name=_("notes"),
        help_text=_(
            "Populated for feed-sourced rules today. Auto-generated rules populate this with a "
            "human-readable rendering of the detection evidence (BR-ANOM-009)."
        ),
    )
    review_status = models.CharField(
        max_length=20,
        choices=ReviewStatus.choices,
        default=ReviewStatus.NOT_APPLICABLE,
        db_index=True,
        verbose_name=_("review status"),
        help_text=_(
            "Review state for an auto-generated rule (BR-ANOM-010). Stays 'not applicable' for "
            "admin and feed rules, and for auto rules that were never queued for review."
        ),
    )
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("reviewed at"),
        help_text=_("Set when review_status transitions to confirmed or rejected."),
    )
    detectors = models.CharField(
        max_length=255,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("detectors"),
        help_text=_(
            "Comma-separated, sorted set of anomaly detector names that have ever caused a "
            "write to this row (e.g. 'detect_cloud_spray,detect_unsolved_challenges'). Additive, "
            "never overwritten: multiple detectors can independently target the same "
            "(rule_type, pattern, source=AUTO, action) shape, most commonly a shared subnet "
            "pattern, and each detector's own write only adds its name rather than replacing "
            "the set. Blank for admin and feed-sourced rules, and for auto-generated rules "
            "created before this field existed. Lets a detector's own promotion logic recognise "
            "a rule it has itself previously written, even after another detector has since "
            "written to the same row (#97)."
        ),
    )

    objects = BlockRuleManager()

    class Meta:
        db_table = "django_waf_block_rule"
        ordering = ["priority", "-created_at"]
        verbose_name = _("block rule")
        verbose_name_plural = _("block rules")
        indexes = [
            models.Index(fields=["rule_type", "is_active"], name="django_waf_br_type_active_idx"),
            models.Index(fields=["source", "is_active"], name="django_waf_br_src_active_idx"),
            models.Index(fields=["priority", "is_active"], name="django_waf_br_prio_active_idx"),
            models.Index(
                fields=["expires_at"],
                condition=Q(is_active=True),
                name="django_waf_br_exp_active_idx",
            ),
            models.Index(fields=["source", "review_status"], name="django_waf_br_review_idx"),
        ]
        constraints = [
            # The anomaly detector identifies an auto-generated rule by
            # (rule_type, pattern, source=AUTO, action): that tuple is the
            # update_or_create lookup in services/anomaly_detector.py, and
            # match_type is a default it writes, not part of the key. Two
            # concurrent detector runs could each miss the other's row and
            # both insert, leaving duplicates that _deduplicate_block_rules
            # had to clean up after the fact. This closes that race in the
            # database instead (#153).
            #
            # Scoped to source=AUTO because only auto rules have a machine
            # key: admin and feed rules are curated by hand and may
            # legitimately repeat a (rule_type, pattern, action) shape with
            # different names, expiries or notes. source is not in the field
            # list because the condition already restricts the rows to it.
            models.UniqueConstraint(
                fields=["rule_type", "pattern", "action"],
                condition=Q(source=RuleSource.AUTO),
                name="django_waf_br_auto_key_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"[{self.action}] {self.name}"

    def clean(self) -> None:
        super().clean()
        _validate_rule_pattern(self.rule_type, self.match_type, self.pattern)


# ---------------------------------------------------------------------------
# AllowRule
# ---------------------------------------------------------------------------


class AllowRuleManager(models.Manager):
    """Custom manager for AllowRule with convenience querysets."""

    def active(self) -> models.QuerySet:
        """Return all active, non-expired allow rules.

        Excludes rules whose expires_at has passed even when is_active is
        still True, mirrors BlockRuleManager.active() (#25). Without this,
        an expired feed or crawler AllowRule keeps bypassing every WAF
        check until the periodic expire_rules task next deactivates it.
        """
        not_expired = Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        return self.filter(is_active=True).filter(not_expired)

    def requiring_rdns(self) -> models.QuerySet:
        """Return active rules that require reverse-DNS verification."""
        return self.active().filter(verify_rdns=True)

    def feed_sourced(self) -> models.QuerySet:
        """Return active rules sourced from the collective threat feed."""
        return self.active().filter(source=RuleSource.FEED)

    def expired(self) -> models.QuerySet:
        """Return active rules whose expiry time has passed.

        Mirrors BlockRuleManager.expired() so the expire_rules task can
        deactivate AllowRules using the same shape (#25).
        """
        return self.filter(is_active=True, expires_at__lte=timezone.now())


class AllowRule(BaseModel):
    """
    A WAF allowlist rule that exempts matching requests from block evaluation.

    Allow rules are evaluated before block rules. A match here bypasses all
    block/challenge/throttle logic for that request.
    """

    name = models.CharField(
        max_length=255,
        verbose_name=_("name"),
    )
    rule_type = models.CharField(
        max_length=20,
        choices=RuleType.choices,
        db_index=True,
        verbose_name=_("rule type"),
    )
    match_type = models.CharField(
        max_length=20,
        choices=MatchType.choices,
        verbose_name=_("match type"),
    )
    pattern = models.CharField(
        max_length=2048,
        verbose_name=_("pattern"),
        help_text=_("Value to match against (IP, CIDR, user-agent string, or regex)."),
    )
    verify_rdns = models.BooleanField(
        default=False,
        verbose_name=_("verify rDNS"),
        help_text=_("Require reverse-DNS lookup to confirm the IP belongs to a trusted network."),
    )
    rdns_pattern = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("rDNS pattern"),
        help_text=_("Regex or suffix matched against the PTR record when verify_rdns is enabled."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("active"),
    )
    source = models.CharField(
        max_length=20,
        choices=RuleSource.choices,
        default=RuleSource.ADMIN,
        verbose_name=_("source"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("expires at"),
        help_text=_("Leave blank for rules that never expire."),
    )
    confidence = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal("1.00"),
        verbose_name=_("confidence"),
        help_text=_("Confidence score from 0.00 to 1.00 (feed-sourced rules only)."),
    )
    feed_first_seen = models.DateField(
        null=True,
        blank=True,
        verbose_name=_("feed first seen"),
    )
    feed_reporters = models.PositiveIntegerField(
        default=0,
        verbose_name=_("feed reporters"),
        help_text=_("Number of sites that reported this allowlist entry to the collective feed."),
    )
    notes = models.TextField(
        blank=True,
        verbose_name=_("notes"),
    )

    objects = AllowRuleManager()

    class Meta:
        db_table = "django_waf_allow_rule"
        ordering = ["name"]
        verbose_name = _("allow rule")
        verbose_name_plural = _("allow rules")
        indexes = [
            models.Index(fields=["rule_type", "is_active"], name="django_waf_ar_type_active_idx"),
            models.Index(fields=["is_active"], name="django_waf_ar_active_idx"),
            models.Index(fields=["source", "is_active"], name="django_waf_ar_src_active_idx"),
        ]

    def __str__(self) -> str:
        return f"[allow] {self.name}"

    def clean(self) -> None:
        super().clean()
        _validate_rule_pattern(self.rule_type, self.match_type, self.pattern)


# ---------------------------------------------------------------------------
# RequestLog
# ---------------------------------------------------------------------------


class RequestLogManager(models.Manager):
    """Custom manager for RequestLog with convenience querysets."""

    def recent(self, hours: int = 24) -> models.QuerySet:
        """Return log entries from the last N hours."""
        cutoff = timezone.now() - timedelta(hours=hours)
        return self.filter(timestamp__gte=cutoff)

    def for_ip(self, ip: str) -> models.QuerySet:
        """Return all log entries for a given IP address."""
        return self.filter(ip_address=ip)

    def blocked(self) -> models.QuerySet:
        """Return log entries with a blocked verdict."""
        return self.filter(verdict=Verdict.BLOCKED)

    def purgeable(self, days: int = 30) -> models.QuerySet:
        """Return log entries older than N days, suitable for deletion."""
        cutoff = timezone.now() - timedelta(days=days)
        return self.filter(timestamp__lt=cutoff)

    def from_middleware(self) -> models.QuerySet:
        """Return log entries carrying a real WAF verdict (source='middleware').

        Excludes nginx_log rows, whose verdict is inferred from the access
        log status code rather than observed by rule_engine.evaluate_request
        (#32). Use this for aggregates where a status-code-inferred verdict
        would distort the result.
        """
        return self.filter(source=RequestLogSource.MIDDLEWARE)


class RequestLog(BaseModel):
    """
    Sampled log of requests evaluated by the WAF middleware.

    Not every request is recorded, the sample rate is controlled by
    DJANGO_WAF_LOG_SAMPLE_RATE. Blocked and challenged requests are always logged
    regardless of the sample rate.

    matched_rule_id is stored as a plain UUID (not a ForeignKey) so that
    log rows survive rule deletion without cascading.
    """

    MATCHED_RULE_TYPE_CHOICES = [
        ("block", _("Block rule")),
        ("allow", _("Allow rule")),
    ]

    timestamp = models.DateTimeField(
        db_index=True,
        verbose_name=_("timestamp"),
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        verbose_name=_("IP address"),
    )
    user_agent = models.CharField(
        max_length=1024,
        blank=True,
        verbose_name=_("user-agent"),
    )
    path = models.CharField(
        max_length=2048,
        verbose_name=_("path"),
    )
    method = models.CharField(
        # 16 fits the longest IANA-registered method (BASELINE-CONTROL).
        max_length=16,
        default="GET",
        verbose_name=_("method"),
    )
    verdict = models.CharField(
        max_length=20,
        choices=Verdict.choices,
        db_index=True,
        verbose_name=_("verdict"),
    )
    # Plain UUID, not a FK so log rows survive rule deletion.
    matched_rule_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("matched rule ID"),
    )
    matched_rule_type = models.CharField(
        max_length=10,
        choices=MATCHED_RULE_TYPE_CHOICES,
        blank=True,
        default="",
        verbose_name=_("matched rule type"),
        help_text=_(
            "Which rule table matched: 'block' = a BlockRule, 'allow' = an "
            "AllowRule. This is the source table, NOT the enforced action: a "
            "BlockRule with action=challenge produces matched_rule_type='block' "
            "and verdict='challenged'. Use the verdict column for enforcement "
            "reporting; use this column for rule-source auditing."
        ),
    )
    anomaly_score = models.DecimalField(
        max_digits=4,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_("anomaly score"),
    )
    response_code = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        verbose_name=_("response code"),
    )
    referer = models.CharField(
        max_length=2048,
        blank=True,
        verbose_name=_("referer"),
        help_text=_("HTTP Referer header value, useful for identifying bot traffic sources."),
    )
    http_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        verbose_name=_("HTTP fingerprint"),
        help_text=_("SHA-256 hash of normalised HTTP headers: identifies real client software."),
    )
    fingerprint_verdict = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("fingerprint verdict"),
        help_text=_("Fingerprint classification: browser, bot, suspicious, unknown."),
    )
    country_code = models.CharField(
        max_length=2,
        blank=True,
        verbose_name=_("country code"),
    )
    source = models.CharField(
        max_length=20,
        choices=RequestLogSource.choices,
        default=RequestLogSource.MIDDLEWARE,
        db_index=True,
        verbose_name=_("source"),
        help_text=_(
            "Which pipeline wrote this row. 'middleware' rows carry a real WAF "
            "verdict; 'nginx_log' rows have a verdict inferred from the access "
            "log status code (#32). The default is 'middleware' so existing "
            "and future middleware writes are correctly tagged without the "
            "middleware needing to pass source explicitly."
        ),
    )
    source_event_id = models.CharField(
        max_length=128,
        blank=True,
        default="",
        verbose_name=_("source event ID"),
        help_text=_(
            "Deterministic identity for a source event, used to dedupe "
            "re-ingested nginx access-log lines (#32). Populated only for "
            "source='nginx_log' rows; middleware rows leave this blank."
        ),
    )

    objects = RequestLogManager()

    class Meta:
        db_table = "django_waf_request_log"
        ordering = ["-timestamp"]
        verbose_name = _("request log")
        verbose_name_plural = _("request logs")
        indexes = [
            models.Index(fields=["timestamp", "verdict"], name="django_waf_rl_ts_verdict_idx"),
            models.Index(fields=["ip_address", "timestamp"], name="django_waf_rl_ip_ts_idx"),
            models.Index(fields=["verdict", "timestamp"], name="django_waf_rl_verdict_ts_idx"),
            models.Index(fields=["matched_rule_id"], name="django_waf_rl_rule_id_idx"),
        ]
        constraints = [
            # Only nginx_log rows carry a populated source_event_id, so this
            # constraint is scoped to that source: it lets bulk_create's
            # ignore_conflicts=True actually dedupe re-ingested log lines
            # without ever colliding on middleware rows, which always leave
            # source_event_id blank (#32).
            models.UniqueConstraint(
                fields=["source", "source_event_id"],
                condition=Q(source=RequestLogSource.NGINX_LOG) & ~Q(source_event_id=""),
                name="django_waf_rl_nginx_event_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.timestamp} {self.ip_address} {self.verdict}"


# ---------------------------------------------------------------------------
# IPReputation
# ---------------------------------------------------------------------------


class IPReputationManager(models.Manager):
    """Custom manager for IPReputation with convenience querysets."""

    def high_threat(self, threshold: float = 0.7) -> models.QuerySet:
        """Return IPs whose threat score exceeds the given threshold."""
        return self.filter(threat_score__gte=threshold)

    def top_offenders(self, limit: int = 10) -> models.QuerySet:
        """Return the top N IPs ordered by threat score descending."""
        return self.order_by("-threat_score")[:limit]


class IPReputation(BaseModel):
    """
    Aggregated reputation metrics for a single IP address.

    Maintained by the scoring service as requests are processed. One row per IP.
    The threat_score is a normalised value in [0.00, 1.00] derived from the
    ratio of blocked/challenged requests, UA rotation count, and other signals.
    """

    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        verbose_name=_("IP address"),
    )
    total_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("total requests"),
    )
    blocked_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("blocked requests"),
    )
    challenged_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenged requests"),
    )
    challenge_passes = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenge passes"),
    )
    challenge_failures = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenge failures"),
    )
    distinct_ua_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("distinct UA count"),
    )
    threat_score = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal("0.00"),
        verbose_name=_("threat score"),
        help_text=_("Normalised threat score from 0.00 (clean) to 1.00 (high threat)."),
    )
    last_seen_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("last seen at"),
    )
    window_start = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("window start"),
        help_text=_("Start of the current scoring window."),
    )
    window_end = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("window end"),
        help_text=_("End of the current scoring window."),
    )

    objects = IPReputationManager()

    class Meta:
        db_table = "django_waf_ip_reputation"
        ordering = ["-threat_score"]
        verbose_name = _("IP reputation")
        verbose_name_plural = _("IP reputations")
        indexes = [
            models.Index(fields=["threat_score"], name="django_waf_ipr_score_idx"),
            models.Index(fields=["last_seen_at"], name="django_waf_ipr_last_seen_idx"),
            models.Index(fields=["distinct_ua_count"], name="django_waf_ipr_ua_count_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.ip_address} (score={self.threat_score})"


# ---------------------------------------------------------------------------
# ChallengeToken
# ---------------------------------------------------------------------------


class ChallengeToken(BaseModel):
    """
    A proof-of-work challenge token issued to a suspicious client.

    The client must solve a hashcash-style puzzle (finding a nonce such that
    SHA-256(token + nonce) has ``difficulty`` leading zero bits) before
    receiving a solved-challenge cookie that bypasses future challenges.
    """

    token = models.CharField(
        max_length=128,
        unique=True,
        db_index=True,
        verbose_name=_("token"),
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        verbose_name=_("IP address"),
    )
    difficulty = models.PositiveSmallIntegerField(
        default=4,
        verbose_name=_("difficulty"),
        help_text=_("Number of leading zero bits required in the solution hash."),
    )
    nonce = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_("nonce"),
        help_text=_("The nonce submitted by the client when solving the challenge."),
    )
    status = models.CharField(
        max_length=20,
        choices=ChallengeStatus.choices,
        default=ChallengeStatus.PENDING,
        db_index=True,
        verbose_name=_("status"),
    )
    issued_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("issued at"),
    )
    expires_at = models.DateTimeField(
        db_index=True,
        verbose_name=_("expires at"),
    )
    solved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("solved at"),
    )

    class Meta:
        db_table = "django_waf_challenge_token"
        ordering = ["-issued_at"]
        verbose_name = _("challenge token")
        verbose_name_plural = _("challenge tokens")
        indexes = [
            models.Index(fields=["ip_address", "status"], name="django_waf_ct_ip_status_idx"),
            models.Index(fields=["expires_at"], name="django_waf_ct_expires_idx"),
        ]

    def __str__(self) -> str:
        return f"Challenge {self.token[:12]}... ({self.status})"
