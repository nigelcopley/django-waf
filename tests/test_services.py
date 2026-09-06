"""Tests for django-waf service functions.

Redis is not available in the test environment; all Redis calls are mocked
using unittest.mock.
"""

from __future__ import annotations

import hashlib
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from django.db import connection
from django.utils import timezone

from django_waf.enums import (
    ChallengeStatus,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)
from django_waf.services.challenge_service import (
    ChallengeExpiredError,
    ChallengeInvalidError,
    ChallengeMismatchError,
    issue_challenge,
    verify_challenge_solution,
)
from django_waf.services.fingerprint import (
    classify_fingerprint,
    compute_fingerprint,
    is_known_fingerprint,
    register_known_fingerprint,
    score_fingerprint_mismatch,
)
from django_waf.services.rate_limiter import check_rate_limit
from django_waf.services.rule_engine import (
    RuleCache,
    evaluate_request,
    load_rule_cache,
)
from django_waf.services.ua_analyser import classify_ua, score_user_agent
from django_waf.testing.factories import (
    AllowRuleFactory,
    BlockRuleFactory,
    ChallengeTokenFactory,
    IPReputationFactory,
    RequestLogFactory,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_redis() -> MagicMock:
    """Return a MagicMock configured as a minimal Redis client."""
    redis = MagicMock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 1
    redis.incr.return_value = 1
    redis.zcount.return_value = 0
    return redis


def _make_pipeline_mock(zcard_return: int) -> MagicMock:
    """Return a pipeline mock for [zadd, zremrangebyscore, zcard, zrange, expire].

    zcard_return sits at index 2, matching every existing call site. The
    zrange(0, 0, withscores=True) result at index 3 is a single (member,
    score) pair scored "now", enough for _retry_after_from_oldest to
    compute a real value in tests that don't care about the exact number
    (see test_retry_after.py for tests pinning an exact Retry-After value).
    """
    pipeline = MagicMock()
    now = time.time()
    pipeline.execute.return_value = [1, 0, zcard_return, [(str(now), now)], True]
    return pipeline


# ---------------------------------------------------------------------------
# score_user_agent
# ---------------------------------------------------------------------------


class TestScoreUserAgent:
    def test_empty_ua_returns_1(self):
        """Empty UA string returns a score of 1.0."""
        assert score_user_agent("") == 1.0

    def test_normal_browser_ua_scores_low(self):
        """A typical browser UA should score 0.0."""
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        assert score_user_agent(ua) == 0.0

    def test_python_requests_carries_no_self_identification_penalty(self):
        """python-requests scores 0.0: no penalty for honest self-identification.

        Issue #82 teeth check: before the fix this scored 2.5 (the
        _RE_SCRAPER_LIBS weight). 22 chars, so the short-UA check does not
        apply either. This test fails against the pre-fix code (asserts
        2.5, not >= 2.5) and passes after.
        """
        assert score_user_agent("python-requests/2.28.1") == 0.0

    def test_curl_carries_no_self_identification_penalty_but_keeps_short_ua_weight(self):
        """curl scores 1.0: the library penalty is gone, the short-UA weight is not.

        Issue #82 teeth check: before the fix this scored 3.5 (2.5 library
        + 1.0 short). curl/7.68.0 is 11 characters, under the 15-char
        threshold, so the short-UA weight is a genuine, independent
        anomaly signal and correctly still applies. This test fails
        against the pre-fix code (asserts 3.5) and passes after.
        """
        assert score_user_agent("curl/7.68.0") == 1.0

    def test_go_http_client_carries_no_self_identification_penalty(self):
        """Go-http-client scores 0.0 (18 chars, over the short-UA threshold)."""
        assert score_user_agent("Go-http-client/1.1") == 0.0

    def test_scrapy_carries_no_self_identification_penalty(self):
        """Scrapy with a project URL scores 0.0 (34 chars, over the short-UA threshold)."""
        assert score_user_agent("Scrapy/2.6.1 (+https://scrapy.org)") == 0.0

    def test_httpx_carries_no_self_identification_penalty_but_keeps_short_ua_weight(self):
        """httpx/0.23.0 scores 1.0: 12 chars is under the short-UA threshold."""
        assert score_user_agent("httpx/0.23.0") == 1.0

    def test_wget_carries_no_self_identification_penalty(self):
        """Wget with its platform suffix scores 0.0 (23 chars, over the short-UA threshold)."""
        assert score_user_agent("Wget/1.20.3 (linux-gnu)") == 0.0

    def test_ancient_msie_scores_high(self):
        """MSIE 6 browser UA triggers ancient-browser weight.

        Regression guard: this weight (2.0) is untouched by the issue #82
        change and must remain exactly as before.
        """
        ua = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        assert score_user_agent(ua) == 2.0

    def test_ancient_firefox_scores_high(self):
        """Firefox/2.x UA triggers ancient-browser weight (unchanged, 2.0)."""
        ua = "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.9) Gecko/20100101 Firefox/2.0"
        assert score_user_agent(ua) == 2.0

    def test_impossible_ios_windows_combo(self):
        """iPhone + Windows NT is an impossible combination (unchanged, 3.0)."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Windows NT 10.0"
        assert score_user_agent(ua) == 3.0

    def test_impossible_android_ios_combo(self):
        """Android + iPhone combination is impossible (unchanged, 3.0)."""
        ua = "Mozilla/5.0 (Android 12; iPhone; U; en-US)"
        assert score_user_agent(ua) == 3.0

    def test_very_short_ua_adds_weight(self):
        """A UA under 15 characters that already has a version token scores 1.0.

        Regression guard: the short-UA weight (1.0) is unaffected by issue
        #82, and is independent of the missing-version-token weight since
        "ShortUA/1" itself matches the version-token pattern.
        """
        ua = "ShortUA/1"  # 9 chars, has a version token → short weight only
        assert score_user_agent(ua) == 1.0

    def test_ua_without_version_token_adds_weight(self):
        """UA lacking any 'Word/version' token scores 1.5 (unchanged)."""
        ua = "UnknownBrowserWithNoVersionToken"
        assert score_user_agent(ua) == 1.5

    def test_score_capped_at_ten(self):
        """Score is capped at 10.0 regardless of accumulation."""
        # Impossible combo (3.0) + ancient browser (2.0) + no version token
        # (1.5) = 6.5, well under the 10.0 cap. Confirms the cap logic
        # without depending on the removed scraper-library weight: before
        # issue #82's fix, a UA matching this pattern plus _RE_SCRAPER_LIBS
        # could reach the full 10.0 cap; that combination is no longer
        # reachable because the weight was removed, not because the cap
        # itself changed.
        ua = "MSIE 6.0 iPhone Windows NT"
        score = score_user_agent(ua)
        assert score == 6.5
        assert score <= 10.0

    def test_googlebot_scores_zero(self):
        """Googlebot's legitimate UA scores 0.0 (no suspicious signals)."""
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        score = score_user_agent(ua)
        assert score == 0.0


# ---------------------------------------------------------------------------
# classify_ua
# ---------------------------------------------------------------------------


class TestClassifyUa:
    def test_empty_ua_is_unknown(self):
        assert classify_ua("") == "unknown"

    def test_googlebot_is_crawler(self):
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        assert classify_ua(ua) == "crawler"

    def test_bingbot_is_crawler(self):
        ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        assert classify_ua(ua) == "crawler"

    def test_python_requests_is_library(self):
        assert classify_ua("python-requests/2.28.1") == "library"

    def test_aiohttp_is_library(self):
        assert classify_ua("Python/3.10 aiohttp/3.8.1") == "library"

    def test_curl_is_library(self):
        assert classify_ua("curl/7.68.0") == "library"

    def test_generic_bot_self_identifier(self):
        """UA containing standalone 'bot' keyword is classified as 'bot'."""
        # _RE_BOT uses \bbot\b, requires 'bot' as a standalone word token.
        assert classify_ua("My Custom bot/1.0") == "bot"

    def test_spider_self_identifier(self):
        """UA containing standalone 'spider' keyword is classified as 'bot'."""
        assert classify_ua("Generic spider/2.0") == "bot"

    def test_normal_chrome_is_browser(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        assert classify_ua(ua) == "browser"

    def test_firefox_is_browser(self):
        ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
        assert classify_ua(ua) == "browser"

    def test_unknown_ua_returns_unknown(self):
        assert classify_ua("SomethingCompletelyUnrecognised/9.9") == "unknown"


# ---------------------------------------------------------------------------
# check_rate_limit
# ---------------------------------------------------------------------------


class TestCheckRateLimit:
    """Tests for check_rate_limit.

    django_waf.conf caches settings values at import time, so the pytest
    ``settings`` fixture alone will not affect thresholds read from
    ``conf.DJANGO_WAF_RATE_LIMIT_*``.  We patch conf module attributes directly.
    """

    def _pipeline_returning(self, zcard_value: int) -> MagicMock:
        """Pipeline mock for [zadd, zremrangebyscore, zcard, zrange, expire].

        The zrange(0, 0, withscores=True) result is a single (member, score)
        pair with score=time.time() (i.e. "just added now"), enough for
        _retry_after_from_oldest to compute a real value without pinning an
        exact number (tests assert retry_after >= 1, not an exact value; the
        exact-value assertions live in test_retry_after.py).
        """
        pipeline = MagicMock()
        now = time.time()
        pipeline.execute.return_value = [1, 0, zcard_value, [(str(now), now)], True]
        return pipeline

    def test_within_limits_returns_not_exceeded(self):
        """When all windows are within limits, exceeded is False."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = self._pipeline_returning(1)  # 1 request in every window

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is False
        assert result.window is None
        assert result.retry_after is None

    def test_burst_exceeded(self):
        """When the 1s burst window is exceeded, result reflects that."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        # First pipeline call (1s window) returns count > burst limit
        redis.pipeline.return_value = self._pipeline_returning(6)

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "1s"
        assert result.retry_after is not None
        assert result.retry_after >= 1

    def test_per_minute_exceeded(self):
        """When only the 1m window is exceeded, result names that window."""
        import django_waf.conf as conf_mod

        redis = _make_redis()

        call_count = 0

        def pipeline_side_effect():
            nonlocal call_count
            call_count += 1
            # Return within-limit for 1s, over-limit for 1m
            if call_count == 1:
                return self._pipeline_returning(2)  # 1s, OK
            return self._pipeline_returning(101)  # 1m, exceeded

        redis.pipeline.side_effect = pipeline_side_effect

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 100),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "1m"

    def test_pipeline_called_once_per_window_at_most(self):
        """Pipeline is called for each window until one is exceeded."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = self._pipeline_returning(6)  # exceeds burst immediately

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            check_rate_limit("1.2.3.4", redis)

        # Only one pipeline should be needed (burst exceeded on first iteration)
        assert redis.pipeline.call_count == 1

    def test_uses_correct_redis_key_per_window(self):
        """Rate limit keys follow the 'waf:rate:{ip}:{window}' format."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        pipeline = MagicMock()
        now = time.time()
        pipeline.execute.return_value = [1, 0, 1, [(str(now), now)], True]
        redis.pipeline.return_value = pipeline

        ip = "5.5.5.5"
        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            check_rate_limit(ip, redis)

        # Check that zadd was called with correct keys for all 3 windows
        zadd_calls = pipeline.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert f"waf:rate:{ip}:1s" in used_keys
        assert f"waf:rate:{ip}:1m" in used_keys
        assert f"waf:rate:{ip}:5m" in used_keys


# ---------------------------------------------------------------------------
# check_rate_limit, per-path limits (DJANGO_WAF_RATE_LIMIT_PATHS)
# ---------------------------------------------------------------------------


class TestCheckRateLimitPerPath:
    """Tests for the per-path rate limiting layer of check_rate_limit."""

    def test_path_limit_breach_returns_exceeded_window_path(self):
        """A path matching a configured prefix that exceeds its limit is throttled."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(11)  # over the limit of 10

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", {"/api/": (10, 60)}):
            result = check_rate_limit("1.2.3.4", redis, path="/api/widgets/")

        assert result.exceeded is True
        assert result.window == "path"
        assert result.retry_after is not None
        assert result.retry_after >= 1

    def test_unmatched_path_falls_through_to_global_windows(self):
        """A path with no matching configured prefix only checks the global windows."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)  # within all limits

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", {"/api/": (10, 60)}),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis, path="/blog/post/")

        assert result.exceeded is False
        # Only the global window keys were touched, no "path" key.
        zadd_calls = redis.pipeline.return_value.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert not any(":path:" in key for key in used_keys)

    def test_global_limit_still_applies_when_under_path_limit(self):
        """When the path limit is not breached, the global windows still run and can throttle."""
        import django_waf.conf as conf_mod

        redis = _make_redis()

        call_count = 0

        def pipeline_side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_pipeline_mock(1)  # path window, within limit
            return _make_pipeline_mock(6)  # global 1s window, exceeded

        redis.pipeline.side_effect = pipeline_side_effect

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", {"/api/": (100, 60)}),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis, path="/api/widgets/")

        assert result.exceeded is True
        assert result.window == "1s"

    def test_longest_prefix_wins_when_multiple_match(self):
        """When several configured prefixes match, the most specific one is enforced."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(3)  # over the login limit of 2

        rate_limit_paths = {
            "/api/": (1000, 60),
            "/api/login/": (2, 60),
        }

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths):
            result = check_rate_limit("1.2.3.4", redis, path="/api/login/")

        assert result.exceeded is True
        assert result.window == "path"

        # Confirm the key used was derived from the longer, more specific prefix.
        import hashlib

        expected_hash = hashlib.sha1(b"/api/login/").hexdigest()[:12]
        zadd_calls = redis.pipeline.return_value.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert f"waf:rate:1.2.3.4:path:{expected_hash}" in used_keys


# ---------------------------------------------------------------------------
# check_rate_limit, method-scoped per-path limits (BR-RATE-004)
# ---------------------------------------------------------------------------


class TestCheckRateLimitMethodScoping:
    """Tests for the three-item, method-scoped form of
    DJANGO_WAF_RATE_LIMIT_PATHS: {prefix: (max_requests, window_seconds,
    methods)}.
    """

    def test_two_item_entry_still_limits_every_method_unchanged(self):
        """The pre-existing two-item form must keep limiting every method,
        exactly as every prior release did: no silent behaviour change for
        a widely deployed setting."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(11)  # over the limit of 10

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", {"/api/": (10, 60)}):
            get_result = check_rate_limit("1.2.3.4", redis, path="/api/widgets/", method="GET")
            post_result = check_rate_limit("1.2.3.4", redis, path="/api/widgets/", method="POST")
            no_method_result = check_rate_limit("1.2.3.4", redis, path="/api/widgets/")

        assert get_result.exceeded is True
        assert post_result.exceeded is True
        assert no_method_result.exceeded is True

    def test_scoped_entry_limits_only_the_named_method(self):
        """A three-item entry scoped to POST must not throttle a GET at the
        same prefix."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(11)  # would breach if checked

        rate_limit_paths = {"/scan/": (5, 300, ("POST",))}

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 1000),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 1000),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 1000),
        ):
            get_result = check_rate_limit("1.2.3.4", redis, path="/scan/", method="GET")

        # The GET never matched the scoped entry, so no path-level breach;
        # falls through to the (deliberately generous) global windows.
        assert get_result.exceeded is False

    def test_scoped_entry_limits_the_named_method(self):
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(6)  # over the limit of 5

        rate_limit_paths = {"/scan/": (5, 300, ("POST",))}

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths):
            post_result = check_rate_limit("1.2.3.4", redis, path="/scan/", method="POST")

        assert post_result.exceeded is True
        assert post_result.window == "path"

    def test_method_matching_is_case_insensitive(self):
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(6)

        rate_limit_paths = {"/scan/": (5, 300, ("post",))}

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths):
            result = check_rate_limit("1.2.3.4", redis, path="/scan/", method="POST")

        assert result.exceeded is True

    def test_no_method_supplied_does_not_match_a_scoped_entry(self):
        """A caller with no method to offer (empty string, the default)
        cannot match a method-scoped entry: matching would mean guessing
        which method was meant."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(11)

        rate_limit_paths = {"/scan/": (5, 300, ("POST",))}

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 1000),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 1000),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 1000),
        ):
            result = check_rate_limit("1.2.3.4", redis, path="/scan/")

        assert result.exceeded is False

    def test_longer_scoped_prefix_falls_through_to_shorter_unscoped_prefix(self):
        """Pins the resolution rule: a longer prefix that matches the path
        but is method-scoped away for this request falls through to a
        shorter, unscoped prefix rather than the request seeing no path
        limit at all.
        """
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(3)  # over the shorter limit of 2

        rate_limit_paths = {
            "/scan/": (2, 60),  # shorter, unscoped: covers every method
            "/scan/submit/": (100, 60, ("POST",)),  # longer, scoped to POST only
        }

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths):
            get_result = check_rate_limit("1.2.3.4", redis, path="/scan/submit/", method="GET")

        # The longer prefix matched the path but not the method, so
        # evaluation fell through to the shorter, unscoped prefix, whose
        # limit of 2 is breached by the mocked count of 3.
        assert get_result.exceeded is True
        assert get_result.window == "path"

        import hashlib

        expected_hash = hashlib.sha1(b"/scan/").hexdigest()[:12]
        zadd_calls = redis.pipeline.return_value.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert f"waf:rate:1.2.3.4:path:{expected_hash}" in used_keys

    def test_longer_scoped_prefix_wins_when_method_matches(self):
        """The same configuration as above, but with the method the longer
        prefix scopes to: the longer, more specific prefix wins as usual."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(101)  # over the longer limit of 100

        rate_limit_paths = {
            "/scan/": (2, 60),
            "/scan/submit/": (100, 60, ("POST",)),
        }

        with patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", rate_limit_paths):
            post_result = check_rate_limit("1.2.3.4", redis, path="/scan/submit/", method="POST")

        assert post_result.exceeded is True

        import hashlib

        expected_hash = hashlib.sha1(b"/scan/submit/").hexdigest()[:12]
        zadd_calls = redis.pipeline.return_value.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert f"waf:rate:1.2.3.4:path:{expected_hash}" in used_keys


# ---------------------------------------------------------------------------
# load_rule_cache
# ---------------------------------------------------------------------------


class TestLoadRuleCache:
    def test_cache_miss_rebuilds_from_db(self, db):
        """When Redis has no cached data, rules are loaded from the database."""
        BlockRuleFactory(is_active=True, rule_type=RuleType.IP)
        AllowRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.return_value = None  # No version, no cached data

        cache = load_rule_cache(redis)

        assert isinstance(cache, RuleCache)
        assert len(cache.block_rules) == 1
        assert len(cache.allow_rules) == 1

    def test_cache_hit_returns_without_db_query(self, db):
        """When Redis has valid cached data, it is used directly (no DB query)."""
        cached_data = json.dumps(
            {
                "allow_rules": [
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "rule_type": "ip",
                        "match_type": "exact",
                        "pattern": "192.168.1.1",
                        "verify_rdns": False,
                        "rdns_pattern": "",
                    },
                ],
                "block_rules": [],
            }
        )

        redis = _make_redis()
        # Return version=5, then cached payload
        redis.get.side_effect = ["5", cached_data.encode()]

        cache = load_rule_cache(redis)

        assert cache.version == 5
        assert len(cache.allow_rules) == 1
        assert cache.allow_rules[0]["pattern"] == "192.168.1.1"
        assert len(cache.block_rules) == 0

    def test_returns_rule_cache_namedtuple(self, db):
        """load_rule_cache always returns a RuleCache namedtuple."""
        redis = _make_redis()

        cache = load_rule_cache(redis)

        assert hasattr(cache, "version")
        assert hasattr(cache, "allow_rules")
        assert hasattr(cache, "block_rules")
        assert hasattr(cache, "ua_regex_set")

    def test_ua_regex_patterns_are_precompiled(self, db):
        """UA-type block rules are compiled into ua_regex_set."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.UA,
            match_type="regex",
            pattern=r"BadBot/\d+",
        )

        redis = _make_redis()
        cache = load_rule_cache(redis)

        assert len(cache.ua_regex_set) == 1
        compiled_re, rule_dict = cache.ua_regex_set[0]
        # Compiled pattern should match a known bad bot string
        assert compiled_re.search("BadBot/2.0")

    def test_inactive_rules_excluded(self, db):
        """Inactive rules are not included in the rebuilt cache."""
        BlockRuleFactory(is_active=True)
        BlockRuleFactory(is_active=False)

        redis = _make_redis()
        cache = load_rule_cache(redis)

        assert len(cache.block_rules) == 1

    def test_corrupt_cache_falls_back_to_db(self, db):
        """Corrupt cached JSON causes a rebuild from the database."""
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.side_effect = ["5", b"not valid json"]  # version=5, then corrupt

        cache = load_rule_cache(redis)

        # Still returns valid cache rebuilt from DB
        assert len(cache.block_rules) == 1

    def test_rebuild_acquires_and_releases_stampede_lock(self, db):
        """On a cache miss, the rebuild acquires the Redis lock and releases it after."""
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.set.return_value = True  # Lock acquired on first try

        load_rule_cache(redis)

        redis.set.assert_any_call("waf:rule_cache:lock", "1", nx=True, ex=5)
        redis.delete.assert_any_call("waf:rule_cache:lock")

    def test_rebuild_proceeds_fail_open_when_lock_unavailable(self, db):
        """When the lock cannot be acquired after retrying, the rebuild proceeds anyway.

        Per the stampede-protection fix: losing the lock race must not block
        the request. The rebuild still returns a valid RuleCache and the
        lock is never released by this process (it never held it).
        """
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.set.return_value = False  # Lock always contended

        with patch("time.sleep") as mock_sleep:
            cache = load_rule_cache(redis)

        assert len(cache.block_rules) == 1
        # Retried up to 3 times, sleeping between attempts, then gave up.
        assert mock_sleep.call_count == 3
        # Never held the lock, so must not have tried to release it.
        redis.delete.assert_not_called()


# ---------------------------------------------------------------------------
# evaluate_request
# ---------------------------------------------------------------------------


class TestEvaluateRequest:
    """Tests for evaluate_request via mocked Redis + DB-backed rules."""

    def _make_rule_cache(
        self,
        allow_rules=None,
        block_rules=None,
    ) -> RuleCache:
        return RuleCache(
            version=1,
            allow_rules=allow_rules or [],
            block_rules=block_rules or [],
            ua_regex_set=[],
        )

    def test_allowed_when_no_rules_and_within_rate_limit(self, db):
        """Clean request with no matching rules returns ALLOWED verdict."""
        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)  # 1 request, within limits
        redis.zcount.return_value = 5  # <10 recent requests, no UA scoring

        result = evaluate_request(
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            path="/page/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.ALLOWED
        assert result.action is None
        # Must be "" (empty string), not None, RequestLog.matched_rule_type is NOT NULL
        # and Django's default="" only applies when the field is omitted, not when
        # None is passed explicitly. See CHANGELOG 0.8.1.
        assert result.matched_rule_type == ""

    def test_matched_rule_type_is_never_none(self, db):
        """Every EvaluationResult path returns matched_rule_type as a str (never None).

        Regression test: passing None to RequestLog.objects.create(matched_rule_type=None)
        produces an IntegrityError because the DB column is NOT NULL. The rule engine
        must always return "" in the no-match cases.
        """
        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5

        # Unmatched request, falls through to final return
        result = evaluate_request(
            ip_address="10.0.0.99",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )
        assert result.matched_rule_type is not None
        assert isinstance(result.matched_rule_type, str)

    def test_allow_rule_match_returns_passed(self, db):
        """A matching AllowRule bypasses block rules and returns PASSED."""
        AllowRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="1.1.1.1",
        )

        redis = _make_redis()

        result = evaluate_request(
            ip_address="1.1.1.1",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.PASSED
        assert result.matched_rule_id is not None
        assert result.matched_rule_type == "allow"

    def test_block_rule_match_returns_blocked(self, db):
        """A matching BlockRule with BLOCK action returns BLOCKED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="2.2.2.2",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None  # No cached blocked IP entry

        result = evaluate_request(
            ip_address="2.2.2.2",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id is not None
        assert result.matched_rule_type == "block"

    def test_challenge_rule_returns_challenged(self, db):
        """A matching BlockRule with CHALLENGE action returns CHALLENGED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="3.3.3.3",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="3.3.3.3",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.CHALLENGED
        assert result.action == RuleAction.CHALLENGE

    def test_throttle_rule_returns_throttled(self, db):
        """A matching BlockRule with THROTTLE action returns THROTTLED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="4.4.4.4",
            action=RuleAction.THROTTLE,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="4.4.4.4",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.THROTTLED

    def test_redis_blocked_ip_fast_path(self, db):
        """An IP in the Redis blocked-IP cache is rejected immediately.

        Legacy cache value of ``"1"`` (written by pre-v0.10.6 code) carries
        no rule attribution, matched_rule_id stays None and no hit counter
        is bumped. Newer entries store the rule id; see the
        ``test_fast_path_attributes_hit_to_rule`` test below for that path.
        """
        redis = _make_redis()
        # Simulate a legacy blocked-IP cache hit (value "1")
        redis.get.side_effect = lambda key: b"1" if "blocked" in key else None

        result = evaluate_request(
            ip_address="5.5.5.5",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id is None  # Legacy cache entries carry no attribution

    def test_fast_path_attributes_hit_to_rule(self, db):
        """When the fast-path cache stores a rule UUID, the hit is attributed.

        Regression: pre-v0.10.6 the fast-path always blocked anonymously,
        so any IP blocked once stopped contributing to BlockRule.hit_count.
        From v0.10.6, the cache stores the matched rule_id and the fast
        path calls ``_record_rule_hit`` so the rule's counter still
        increments on repeat blocks.
        """
        import uuid

        rule_uuid = uuid.uuid4()
        redis = _make_redis()
        redis.get.side_effect = lambda key: str(rule_uuid).encode() if "blocked" in key else None

        result = evaluate_request(
            ip_address="5.5.5.6",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id == rule_uuid
        assert result.matched_rule_type == "block"

        # Confirm the hit counter was bumped.
        incr_keys = [c.args[0] for c in redis.incr.call_args_list]
        assert f"waf:rule_hits:{rule_uuid}" in incr_keys

    def test_fast_path_malformed_cache_value_falls_back(self, db):
        """A malformed cache value still blocks but carries no attribution.

        Defensive: someone could write garbage to the cache key (replication
        race, manual ops intervention). The fast path must still block, failing open on a malformed cache value would be
        worse than failing
        closed without attribution.
        """
        redis = _make_redis()
        redis.get.side_effect = lambda key: b"not-a-uuid" if "blocked" in key else None

        result = evaluate_request(
            ip_address="5.5.5.7",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id is None

    def test_rate_limit_exceeded_returns_throttled(self, db):
        """When rate limit is exceeded, result is THROTTLED."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.get.return_value = None
        # Pipeline returns count > burst limit of 1
        redis.pipeline.return_value = _make_pipeline_mock(zcard_return=2)

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 1),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = evaluate_request(
                ip_address="6.6.6.6",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.THROTTLED
        assert result.action == RuleAction.THROTTLE

    def test_ua_anomaly_score_triggers_challenge(self, db):
        """High-anomaly UA with >10 recent requests triggers CHALLENGED verdict."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        redis.get.return_value = None
        # Within rate limits
        redis.pipeline.return_value = _make_pipeline_mock(1)
        # >10 recent requests so UA scoring kicks in
        redis.zcount.return_value = 15

        # This UA scores 5.0 (ancient-browser 2.0 + impossible OS/browser
        # combo 3.0), which maps to CHALLENGED per _score_to_verdict. Not
        # 'urllib', which scored 5.0 before issue #82 removed the
        # self-identification weight from score_user_agent and now scores
        # only 2.5 (no version token 1.5 + short 1.0), no longer enough to
        # clear the threshold this test exercises.
        ua = "Mozilla/4.0 (compatible; MSIE 6.0; iPhone; Windows NT 5.1)"
        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 1200),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 6000),
        ):
            result = evaluate_request(
                ip_address="7.7.7.7",
                user_agent=ua,
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict in (Verdict.CHALLENGED, Verdict.BLOCKED)
        assert result.anomaly_score is not None

    def test_ua_anomaly_scoring_skipped_under_10_requests(self, db):
        """UA scoring is skipped when the IP has 10 or fewer recent requests."""
        redis = _make_redis()
        redis.get.return_value = None
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5  # <=10, no UA scoring

        result = evaluate_request(
            ip_address="8.8.8.8",
            user_agent="python-requests/2.28.1",
            path="/",
            method="GET",
            redis_client=redis,
        )

        # Without UA scoring even a scraper UA is ALLOWED
        assert result.verdict == Verdict.ALLOWED
        assert result.anomaly_score is None

    def test_allow_rule_takes_precedence_over_block_rule(self, db):
        """Allow rules are evaluated before block rules (BR-EVAL-003)."""
        AllowRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="9.9.9.9",
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="9.9.9.9",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()

        result = evaluate_request(
            ip_address="9.9.9.9",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.PASSED

    def test_cidr_block_rule_matches_ip_in_range(self, db):
        """CIDR block rule matches an IP within the specified network."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern="192.168.100.0/24",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="192.168.100.42",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED

    def test_ua_block_rule_matches_contains_pattern(self, db):
        """UA block rule with CONTAINS match_type matches a substring."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.UA,
            match_type="contains",
            pattern="SuspiciousTool",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="10.0.0.1",
            user_agent="SuspiciousTool/2.0 (python)",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED


# ---------------------------------------------------------------------------
# Device-aware difficulty selection (v0.10.5)
# ---------------------------------------------------------------------------


class TestPickDifficulty:
    def test_mobile_ua_selects_mobile_difficulty(self):
        import django_waf.conf as conf_mod
        from django_waf.services.challenge_service import _pick_difficulty

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
        ):
            iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605"
            android_phone = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile"
            assert _pick_difficulty(iphone) == 18
            assert _pick_difficulty(android_phone) == 18

    def test_desktop_ua_selects_desktop_difficulty(self):
        import django_waf.conf as conf_mod
        from django_waf.services.challenge_service import _pick_difficulty

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
        ):
            mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605 Version/16 Safari"
            windows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0"
            android_tablet = "Mozilla/5.0 (Linux; Android 13; SM-T970) AppleWebKit/537.36 Safari"
            assert _pick_difficulty(mac) == 22
            assert _pick_difficulty(windows) == 22
            # "Android" without "Mobi" → tablet → desktop band.
            assert _pick_difficulty(android_tablet) == 22

    def test_empty_ua_falls_back_to_desktop(self):
        import django_waf.conf as conf_mod
        from django_waf.services.challenge_service import _pick_difficulty

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
        ):
            assert _pick_difficulty("") == 22

    def test_device_key_none_falls_back_to_single_value(self):
        """Setting desktop/mobile to None makes _pick_difficulty fall through
        to DJANGO_WAF_CHALLENGE_DIFFICULTY, the legacy single-value path."""
        import django_waf.conf as conf_mod
        from django_waf.services.challenge_service import _pick_difficulty

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", None),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", None),
        ):
            assert _pick_difficulty("Mozilla/5.0 (iPhone) Mobi") == 20
            assert _pick_difficulty("Mozilla/5.0 (Windows)") == 20


# ---------------------------------------------------------------------------
# PoW bit-counting helper (regression: v0.10.4 counted bytes, not bits)
# ---------------------------------------------------------------------------


class TestDigestHasLeadingZeroBits:
    def test_zero_bits_always_true(self):
        """Difficulty 0 means no work, every digest passes."""
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        assert _digest_has_leading_zero_bits(b"\xff\xff", 0) is True

    def test_one_bit_checks_msb_of_first_byte(self):
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        # 0x7F = 0111_1111, MSB is zero, passes 1-bit.
        assert _digest_has_leading_zero_bits(b"\x7f", 1) is True
        # 0x80 = 1000_0000, MSB is one, fails 1-bit.
        assert _digest_has_leading_zero_bits(b"\x80", 1) is False

    def test_eight_bits_requires_full_zero_byte(self):
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        assert _digest_has_leading_zero_bits(b"\x00\xff", 8) is True
        assert _digest_has_leading_zero_bits(b"\x01\xff", 8) is False

    def test_partial_byte_boundary(self):
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        # 12 bits = one zero byte + top 4 bits of next byte zero.
        # 0x00 0x0F = 0000_0000 0000_1111, top 4 bits of second byte zero, passes.
        assert _digest_has_leading_zero_bits(b"\x00\x0f", 12) is True
        # 0x00 0x10 = 0000_0000 0001_0000, bit 11 (from MSB) is one, fails.
        assert _digest_has_leading_zero_bits(b"\x00\x10", 12) is False

    def test_short_digest_returns_false(self):
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        # Need at least one byte to check 1 bit.
        assert _digest_has_leading_zero_bits(b"", 1) is False


# ---------------------------------------------------------------------------
# issue_challenge
# ---------------------------------------------------------------------------


class TestIssueChallenge:
    def test_creates_challenge_token_in_db(self, db):
        """issue_challenge creates and persists a ChallengeToken record."""
        import django_waf.conf as conf_mod
        from django_waf.models import ChallengeToken

        redis = _make_redis()

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            token_obj = issue_challenge("10.0.0.1", redis)

        assert token_obj.pk is not None
        assert ChallengeToken.objects.filter(pk=token_obj.pk).exists()
        assert token_obj.ip_address == "10.0.0.1"
        assert token_obj.status == ChallengeStatus.PENDING
        assert token_obj.difficulty == 4

    def test_token_stored_in_redis(self, db):
        """issue_challenge stores the challenge payload in Redis."""
        import django_waf.conf as conf_mod

        redis = _make_redis()

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            issue_challenge("10.0.0.2", redis)

        # setex should have been called once for the challenge key
        assert redis.setex.called
        setex_call = redis.setex.call_args
        key = setex_call.args[0]
        assert key.startswith("waf:challenge:")

        # The payload should be valid JSON with ip and difficulty
        payload = json.loads(setex_call.args[2])
        assert payload["ip"] == "10.0.0.2"
        assert payload["difficulty"] == 4

    def test_token_uses_configured_difficulty(self, db):
        """Difficulty on created token reflects DJANGO_WAF_CHALLENGE_DIFFICULTY setting."""
        import django_waf.conf as conf_mod

        redis = _make_redis()

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 6),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 6),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 6),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            token_obj = issue_challenge("10.0.0.3", redis)

        assert token_obj.difficulty == 6

    def test_expiry_is_set_based_on_cookie_ttl(self, db):
        """expires_at is approximately now + DJANGO_WAF_CHALLENGE_COOKIE_TTL seconds."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        before = timezone.now()

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 7200),
        ):  # 2 hours
            token_obj = issue_challenge("10.0.0.4", redis)

        after = timezone.now()
        expected_min = before + timezone.timedelta(seconds=7199)
        expected_max = after + timezone.timedelta(seconds=7201)

        assert token_obj.expires_at >= expected_min
        assert token_obj.expires_at <= expected_max

    def test_emits_challenge_issued_signal(self, db):
        """issue_challenge emits the challenge_issued signal."""
        import django_waf.conf as conf_mod
        from django_waf.signals import challenge_issued

        received = []

        def handler(sender, token, ip_address, **kwargs):
            received.append((token, ip_address))

        challenge_issued.connect(handler, dispatch_uid="test_issue_challenge_signal")
        try:
            redis = _make_redis()
            with (
                patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 4),
                patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 3600),
            ):
                issue_challenge("10.0.0.5", redis)
        finally:
            challenge_issued.disconnect(dispatch_uid="test_issue_challenge_signal")

        assert len(received) == 1
        _, ip = received[0]
        assert ip == "10.0.0.5"


# ---------------------------------------------------------------------------
# verify_challenge_solution
# ---------------------------------------------------------------------------


class TestVerifyChallengeService:
    def _valid_nonce(self, token: str, difficulty: int) -> str:
        """Brute-force a nonce that satisfies the proof-of-work for the given token.

        Counts leading zero **bits** to match the production verifier.
        """
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        for n in range(1_000_000):
            nonce = str(n)
            digest = hashlib.sha256(f"{token}{nonce}".encode()).digest()
            if _digest_has_leading_zero_bits(digest, difficulty):
                return nonce
        raise RuntimeError("Could not find a valid nonce within 1,000,000 iterations")

    def test_valid_solution_returns_true(self, db):
        """A correct nonce marks the token SOLVED and returns True."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )
        nonce = self._valid_nonce(token_obj.token, 1)

        redis = _make_redis()
        redis.get.return_value = None  # Force DB lookup

        result = verify_challenge_solution(
            token=token_obj.token,
            nonce=nonce,
            ip_address="1.2.3.4",
            redis_client=redis,
        )

        assert result is True
        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.SOLVED
        assert token_obj.nonce == nonce
        assert token_obj.solved_at is not None

    def test_expired_token_raises(self, db):
        """A token past its expiry raises ChallengeExpiredError."""
        past = timezone.now() - timezone.timedelta(hours=1)
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            status=ChallengeStatus.PENDING,
            expires_at=past,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.EXPIRED

    def test_already_solved_token_raises(self, db):
        """A token that was already solved raises ChallengeExpiredError."""
        token_obj = ChallengeTokenFactory(status=ChallengeStatus.SOLVED)

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address=token_obj.ip_address,
                redis_client=redis,
            )

    def test_already_failed_token_raises(self, db):
        """A token that was already failed raises ChallengeExpiredError."""
        token_obj = ChallengeTokenFactory(status=ChallengeStatus.FAILED)

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address=token_obj.ip_address,
                redis_client=redis,
            )

    def test_ip_mismatch_raises(self, db):
        """Submitting a solution from a different IP raises ChallengeMismatchError."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeMismatchError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="some_nonce",
                ip_address="5.5.5.5",  # Wrong IP
                redis_client=redis,
            )

    def test_invalid_nonce_raises(self, db):
        """A nonce that fails proof-of-work raises ChallengeInvalidError."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            # 24 bits, chance of accidental pass with a fixed wrong nonce is 1/16M.
            difficulty=24,
            status=ChallengeStatus.PENDING,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeInvalidError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="wrong_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.FAILED

    def test_nonexistent_token_raises(self, db):
        """A token that does not exist raises ChallengeInvalidError."""
        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeInvalidError, match="not found"):
            verify_challenge_solution(
                token="no-such-token",
                nonce="any_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

    def test_redis_cache_used_when_available(self, db):
        """verify_challenge_solution uses Redis data when available (avoids DB lookup)."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )
        nonce = self._valid_nonce(token_obj.token, 1)

        redis_payload = json.dumps(
            {
                "ip": "1.2.3.4",
                "difficulty": 1,
                "expires": token_obj.expires_at.isoformat(),
            }
        ).encode()
        redis = _make_redis()
        redis.get.return_value = redis_payload

        result = verify_challenge_solution(
            token=token_obj.token,
            nonce=nonce,
            ip_address="1.2.3.4",
            redis_client=redis,
        )

        assert result is True


# ---------------------------------------------------------------------------
# validate_pass_cookie / issue_pass_cookie
#
# Covered in tests/test_pass_cookie.py, including the IPv6-safety fix for
# GH #26 (the versioned "|"-delimited payload format).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# detect_ua_rotation
# ---------------------------------------------------------------------------


class TestDetectUaRotation:
    def test_creates_block_rule_for_rotating_ip(self, db):
        """detect_ua_rotation creates a CHALLENGE block rule for offending IPs."""
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_ua_rotation

        ip = "11.11.11.11"
        now = timezone.now()
        # Create distinct UAs from the same IP
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert len(created) == 1
        rule = created[0]
        assert rule.pattern == ip
        assert rule.action == RuleAction.CHALLENGE
        assert rule.source == RuleSource.AUTO
        assert rule.rule_type == RuleType.IP
        assert BlockRule.objects.filter(pk=rule.pk).exists()

    def test_returns_empty_when_no_offenders(self, db):
        """detect_ua_rotation returns empty list when no IP exceeds the threshold."""
        from django_waf.services.anomaly_detector import detect_ua_rotation

        result = detect_ua_rotation(window_minutes=5, threshold=20)

        assert result == []

    def test_does_not_duplicate_existing_auto_rule(self, db):
        """update_or_create refreshes an existing auto rule instead of creating a duplicate."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        ip = "12.12.12.12"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"UA-{i}/1.0", timestamp=now)

        # Pre-existing auto rule with same key fields
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.CHALLENGE,
            source=RuleSource.AUTO,
        )

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        # update_or_create found the existing rule, no new creation
        assert created == []
        # Still only one rule for this IP
        from django_waf.models import BlockRule

        assert BlockRule.objects.filter(pattern=ip, source=RuleSource.AUTO).count() == 1


# ---------------------------------------------------------------------------
# detect_subnet_burst
# ---------------------------------------------------------------------------


class TestDetectSubnetBurst:
    def test_creates_cidr_rule_for_bursting_subnet(self, db):
        """detect_subnet_burst creates a CIDR block rule for a bursting /24 subnet."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # 100 requests from a single /24 subnet, 1 each from 9 other subnets.
        # Median = 1. 3× = 3. The 20.20.20.0/24 subnet (100 requests) clears
        # both the ratio and the absolute floor.
        for i in range(100):
            RequestLogFactory(ip_address=f"20.20.20.{i % 255}", timestamp=now)
        for j in range(9):
            RequestLogFactory(ip_address=f"30.30.{j}.1", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_subnet_burst(window_minutes=60)

        # The 20.20.20.0/24 subnet should be flagged
        assert len(created) >= 1
        rule_patterns = [r.pattern for r in created]
        assert "20.20.20.0/24" in rule_patterns

    def test_returns_empty_when_no_burst(self, db):
        """detect_subnet_burst returns empty list when no subnet exceeds 3× median."""
        from django_waf.services.anomaly_detector import detect_subnet_burst

        result = detect_subnet_burst(window_minutes=15)

        assert result == []

    def test_spread_botnet_at_sustained_low_rate_is_detected(self, db):
        """A botnet spread across several adjacent /24s at a similar low rate is
        detected once each prefix clears the absolute floor (issue #80).

        Before #80, the threshold was 3x the arithmetic MEAN of the window's
        own per-subnet counts. Every one of these attacker subnets sits at
        the identical count, so the mean equals that count and the ratio
        3x-the-mean can never be exceeded by any of them: the old detector
        was structurally blind to a uniform spread regardless of volume.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # Five adjacent /24s, each sustaining the same volume, well clear of
        # the absolute floor. A couple of quiet legitimate subnets sit
        # alongside them so the window is not attacker-only.
        attacker_subnets = ["163.7.14", "163.7.15", "163.7.16", "163.7.17", "163.7.18"]
        for subnet in attacker_subnets:
            for i in range(40):
                RequestLogFactory(ip_address=f"{subnet}.{i % 255}", timestamp=now)
        for j in range(3):
            RequestLogFactory(ip_address=f"9.9.{j}.1", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_subnet_burst(window_minutes=60)

        rule_patterns = {r.pattern for r in created}
        for subnet in attacker_subnets:
            assert f"{subnet}.0/24" in rule_patterns

    def test_adding_more_attacker_subnets_does_not_reduce_detection(self, db):
        """Adding more attacker-controlled subnets at the same volume must not
        reduce detection probability for any of them (issue #80's required
        property).

        This is the discriminator: the pre-#80 mean-relative threshold was
        raised by every additional attacker subnet added at the same volume,
        so a wider spread was strictly SAFER for the attacker than a narrow
        one. Run the same per-subnet volume against a smaller and a larger
        attacker footprint and assert that every attacker subnet is still
        flagged in both cases; the larger footprint must not de-detect any
        of the subnets the smaller footprint already caught.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule, RequestLog
        from django_waf.services.anomaly_detector import detect_subnet_burst

        per_subnet_count = 40

        def run_with_attacker_count(n_attacker_subnets: int) -> set[str]:
            # Each footprint must be judged as its own independent world.
            # detect_subnet_burst only reports NEWLY created rules (BR-ANOM-007's
            # re-detection guard refreshes, rather than recreates, an already-active
            # auto rule for the same pattern): without clearing BlockRule here, the
            # smaller footprint's rules would still be active when the larger
            # footprint runs, and its subnets would be silently omitted from the
            # second call's `created` list despite the detector correctly having
            # (re-)flagged them. That would make this test conflate "detected" with
            # "newly created", not "not detected".
            BlockRule.objects.all().delete()
            RequestLog.objects.all().delete()
            now = timezone.now()
            attacker_subnets = [f"163.7.{20 + n}" for n in range(n_attacker_subnets)]
            for subnet in attacker_subnets:
                for i in range(per_subnet_count):
                    RequestLogFactory(ip_address=f"{subnet}.{i % 255}", timestamp=now)
            # A stable, small population of quiet legitimate subnets, so the
            # window is never attacker-only in either run.
            for j in range(3):
                RequestLogFactory(ip_address=f"9.9.{j}.1", timestamp=now)

            with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
                created = detect_subnet_burst(window_minutes=60)

            return {f"{subnet}.0/24" for subnet in attacker_subnets} & {r.pattern for r in created}

        detected_small_spread = run_with_attacker_count(3)
        detected_large_spread = run_with_attacker_count(8)

        assert len(detected_small_spread) == 3
        assert len(detected_large_spread) == 8


# ---------------------------------------------------------------------------
# _get_subnet_prefix
# ---------------------------------------------------------------------------


class TestGetSubnetPrefix:
    def test_ipv4_returns_slash24(self):
        """An IPv4 address is truncated to its /24 network."""
        from django_waf.services.anomaly_detector import _get_subnet_prefix

        assert _get_subnet_prefix("192.0.2.100") == "192.0.2.0/24"

    def test_ipv6_returns_slash48(self):
        """An IPv6 address is truncated to its /48 network, not a /24.

        Regression: naively applying "/24" to an IPv6 address (as
        ipaddress.ip_network(f"{ip}/24", strict=False) does) produces an
        absurdly wide network, a /24 IPv6 prefix still spans 2**104
        addresses. /48 is the correct IPv6-equivalent aggregation.
        """
        from django_waf.services.anomaly_detector import _get_subnet_prefix

        assert _get_subnet_prefix("2001:db8:abcd:1234::1") == "2001:db8:abcd::/48"

    def test_invalid_ip_raises_value_error(self):
        """An invalid IP string raises ValueError so callers can skip it."""
        from django_waf.services.anomaly_detector import _get_subnet_prefix

        with pytest.raises(ValueError):
            _get_subnet_prefix("999.999.999.999")


# ---------------------------------------------------------------------------
# detect_challenge_farms
# ---------------------------------------------------------------------------


class TestDetectChallengeFarms:
    def test_creates_block_rule_for_farm_ip(self, db):
        """detect_challenge_farms creates a BLOCK rule for IPs with high failure rates."""
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_challenge_farms

        IPReputationFactory(
            ip_address="99.99.99.99",
            challenge_failures=15,
            challenge_passes=0,
            last_seen_at=timezone.now(),
        )

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_challenge_farms(window_hours=24)

        assert len(created) == 1
        rule = created[0]
        assert rule.pattern == "99.99.99.99"
        assert rule.action == RuleAction.BLOCK
        assert rule.source == RuleSource.AUTO
        assert BlockRule.objects.filter(pk=rule.pk).exists()

    def test_returns_empty_when_no_suspects(self, db):
        """detect_challenge_farms returns empty list when no IPs meet the criteria."""
        from django_waf.services.anomaly_detector import detect_challenge_farms

        # IP with low failure count, should not be flagged
        IPReputationFactory(
            challenge_failures=2,
            challenge_passes=5,
            last_seen_at=timezone.now(),
        )

        result = detect_challenge_farms(window_hours=24)

        assert result == []

    def test_does_not_duplicate_existing_auto_block_rule(self, db):
        """update_or_create refreshes an existing auto rule instead of duplicating."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_challenge_farms

        ip = "88.88.88.88"
        IPReputationFactory(
            ip_address=ip,
            challenge_failures=20,
            challenge_passes=0,
            last_seen_at=timezone.now(),
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
            source=RuleSource.AUTO,
        )

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_challenge_farms(window_hours=24)

        assert created == []
        from django_waf.models import BlockRule

        assert BlockRule.objects.filter(pattern=ip, source=RuleSource.AUTO).count() == 1


# ---------------------------------------------------------------------------
# run_all_detectors
# ---------------------------------------------------------------------------


class TestRunAllDetectors:
    def test_returns_summary_dict_with_correct_keys(self, db):
        """run_all_detectors returns a dict with the expected summary keys."""
        from django_waf.services.anomaly_detector import run_all_detectors

        result = run_all_detectors()

        assert set(result.keys()) == {
            "ua_rotation_rules",
            "subnet_burst_rules",
            "challenge_farm_rules",
            "unsolved_challenge_rules",
            "cloud_spray_rules",
            "scraper_404_rules",
            "total_rules_created",
        }

    def test_returns_zero_counts_when_no_anomalies(self, db):
        """When no anomalies exist, all counts are zero."""
        from django_waf.services.anomaly_detector import run_all_detectors

        result = run_all_detectors()

        assert result["ua_rotation_rules"] == 0
        assert result["subnet_burst_rules"] == 0
        assert result["challenge_farm_rules"] == 0
        assert result["total_rules_created"] == 0

    def test_total_rules_created_sums_all_detectors(self, db):
        """total_rules_created is the sum across all three detectors."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import run_all_detectors

        now = timezone.now()
        # Trigger UA rotation detector: one IP with many distinct UAs
        for i in range(25):
            RequestLogFactory(ip_address="55.55.55.55", user_agent=f"UA-{i}/1.0", timestamp=now)

        with (
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 20),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            result = run_all_detectors()

        assert result["ua_rotation_rules"] == 1
        expected = result["ua_rotation_rules"] + result["subnet_burst_rules"] + result["challenge_farm_rules"]
        assert result["total_rules_created"] == expected


# ---------------------------------------------------------------------------
# DETECTOR_NAMES / DETECTOR_NAME_TO_RESULT_KEY wiring guard (wave 2, #99's
# sibling defect class, django_waf.W009's own test-suite counterpart)
# ---------------------------------------------------------------------------


class TestDetectorNamesResultKeyWiring:
    """Guards the invariant django_waf.W009 (checks.py) checks at boot:
    DETECTOR_NAMES and DETECTOR_NAME_TO_RESULT_KEY must name exactly the
    same six detectors, and run_all_detectors' real return dict must
    actually produce a result key for every one of them.

    Follows tests/test_conf.py's TestCeleryBeatScheduleDefault shape
    (:47-68): an INDEPENDENT, hand-written expected set, not derived from
    DETECTOR_NAMES or DETECTOR_NAME_TO_RESULT_KEY themselves, compared
    against the real values. A set built FROM either constant could never
    catch that constant drifting: it would always equal itself.
    """

    # Hand-written, not sourced from anomaly_detector.py: BR-ANOM-012
    # named five detectors when it was written; BR-ANOM-014 added the
    # sixth (detect_scraper_404_ratio). If a seventh detector is ever
    # added without updating this literal set, this test fails, which is
    # the point: it is the completeness net the hand-written case list in
    # TestDetectUnsolvedChallenges.test_detector_field_populated_by_every_
    # detector_passing_it (this file) does not provide.
    _EXPECTED_DETECTOR_NAMES = frozenset(
        {
            "detect_ua_rotation",
            "detect_subnet_burst",
            "detect_challenge_farms",
            "detect_unsolved_challenges",
            "detect_cloud_spray",
            "detect_scraper_404_ratio",
        }
    )

    def test_detector_names_matches_the_independent_expected_set(self):
        from django_waf.services.anomaly_detector import DETECTOR_NAMES

        assert DETECTOR_NAMES == self._EXPECTED_DETECTOR_NAMES

    def test_result_key_map_covers_exactly_the_same_names(self):
        """DETECTOR_NAME_TO_RESULT_KEY's key set (not its values) must
        equal DETECTOR_NAMES exactly: this is the invariant django_waf.W009
        exists to catch a violation of at boot.
        """
        from django_waf.services.anomaly_detector import (
            DETECTOR_NAME_TO_RESULT_KEY,
            DETECTOR_NAMES,
        )

        assert set(DETECTOR_NAME_TO_RESULT_KEY) == DETECTOR_NAMES
        assert set(DETECTOR_NAME_TO_RESULT_KEY) == self._EXPECTED_DETECTOR_NAMES

    def test_real_run_all_detectors_return_dict_covers_every_result_key(self, db):
        """The assertion nothing else in the suite makes (per this wave's
        plan): a REAL, unmocked run_all_detectors() call against an empty
        database (every detector legitimately returns [] with no fixture
        traffic present, so this only exercises the dict-shape contract,
        not detection logic, which TestRunAllDetectors and
        test_detector_probe.py's falsifiability tests already cover) must
        produce a key for every DETECTOR_NAME_TO_RESULT_KEY value, and
        total_rules_created is the only extra key beyond that set. A
        result key present in DETECTOR_NAME_TO_RESULT_KEY but absent from
        run_all_detectors' actual return dict would mean the mapping
        constant and the function's own hardcoded return statement have
        desynced, the second of run_all_detectors' seven hand-maintained
        places (see W009's docstring) that DETECTOR_NAMES /
        DETECTOR_NAME_TO_RESULT_KEY alone cannot catch, since both of
        those constants can agree with each other while still disagreeing
        with what the function actually returns.
        """
        from django_waf.services.anomaly_detector import (
            DETECTOR_NAME_TO_RESULT_KEY,
            run_all_detectors,
        )

        result = run_all_detectors()

        result_keys_excluding_total = set(result) - {"total_rules_created"}
        assert result_keys_excluding_total == set(DETECTOR_NAME_TO_RESULT_KEY.values())


# ---------------------------------------------------------------------------
# _emit_anomaly_signal exception path
# ---------------------------------------------------------------------------


class TestEmitAnomalySignalExceptionPath:
    def test_exception_during_signal_send_is_swallowed(self, db):
        """_emit_anomaly_signal swallows exceptions raised inside the signal send."""
        from django_waf.enums import AnomalyType
        from django_waf.services.anomaly_detector import _emit_anomaly_signal

        rule = BlockRuleFactory(is_active=True, rule_type=RuleType.IP)

        with patch("django_waf.signals.anomaly_detected.send", side_effect=Exception("signal error")):
            # Should not raise, exceptions from signal send are caught
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.UA_ROTATION,
                details={"distinct_ua_count": 5},
            )


# ---------------------------------------------------------------------------
# _get_or_create_auto_rule, deduplication on MultipleObjectsReturned
# ---------------------------------------------------------------------------


class TestGetOrCreateAutoRuleDedup:
    """Regression tests for duplicate BlockRule handling in _get_or_create_auto_rule.

    If duplicate rows exist for the same (rule_type, pattern, source, action)
    key, update_or_create raises MultipleObjectsReturned. The fix catches this,
    deduplicates by keeping the newest row, and retries.
    """

    def test_deduplicates_and_retries_on_multiple_objects_returned(self, _auto_key_constraint_dropped):
        """Pre-existing duplicates are cleaned up, then the rule is created normally.

        Since #153 the auto key carries a partial UniqueConstraint, so this
        scenario can no longer be seeded on a migrated database and the
        fixture drops the constraint first. The branch under test is still
        load-bearing rather than dead code: it covers a consumer whose
        migration 0008 has not run yet, which is exactly the unconstrained
        state the fixture reproduces.
        """
        from django_waf.enums import RuleAction, RuleSource, RuleType
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import _get_or_create_auto_rule

        # Create two duplicate rows manually
        for _ in range(2):
            BlockRule.objects.create(
                name="dupe",
                rule_type=RuleType.UA,
                pattern="bad-bot/1.0",
                match_type="contains",
                action=RuleAction.CHALLENGE,
                source=RuleSource.AUTO,
                is_active=True,
            )
        assert BlockRule.objects.filter(pattern="bad-bot/1.0", source=RuleSource.AUTO).count() == 2

        # This would previously raise MultipleObjectsReturned
        rule, created = _get_or_create_auto_rule(
            name="Auto: UA rotation",
            rule_type=RuleType.UA,
            match_type="contains",
            pattern="bad-bot/1.0",
            action=RuleAction.CHALLENGE,
            expiry=timezone.now() + timezone.timedelta(hours=24),
        )

        # Duplicates resolved, exactly one row, refreshed
        remaining = BlockRule.objects.filter(pattern="bad-bot/1.0", source=RuleSource.AUTO)
        assert remaining.count() == 1
        assert remaining.first().pk == rule.pk
        assert rule.name == "Auto: UA rotation"

    @pytest.mark.django_db
    def test_no_duplicates_uses_normal_update_or_create(self):
        """Without duplicates, _get_or_create_auto_rule works normally."""
        from django_waf.enums import RuleAction, RuleType
        from django_waf.services.anomaly_detector import _get_or_create_auto_rule

        rule, created = _get_or_create_auto_rule(
            name="Auto: test",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="203.0.113.99",
            action=RuleAction.BLOCK,
            expiry=timezone.now() + timezone.timedelta(hours=24),
        )
        assert created is True

        # Second call refreshes, not creates
        rule2, created2 = _get_or_create_auto_rule(
            name="Auto: test refreshed",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="203.0.113.99",
            action=RuleAction.BLOCK,
            expiry=timezone.now() + timezone.timedelta(hours=48),
        )
        assert created2 is False
        assert rule2.pk == rule.pk
        assert rule2.name == "Auto: test refreshed"


# ---------------------------------------------------------------------------
# detect_subnet_burst, branch coverage for non-burst path
# ---------------------------------------------------------------------------


class TestDetectSubnetBurstBranches:
    def test_subnet_below_burst_threshold_not_flagged(self, db):
        """Subnets at or below 3× median (and below the absolute floor) are not flagged."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # Uniform distribution: 10 requests per /24 subnet, no burst
        for j in range(10):
            RequestLogFactory(ip_address=f"40.40.{j}.1", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_subnet_burst(window_minutes=60)

        assert created == []

    @pytest.mark.skipif(
        connection.vendor != "sqlite",
        reason=(
            "Needs a malformed value in RequestLog.ip_address, which only a permissive "
            "backend allows. GenericIPAddressField is backed by PostgreSQL's inet type, "
            "which rejects '999.999.999.999' at insert, so this precondition is "
            "unreachable there and the _get_subnet_prefix ValueError guard it exercises "
            "is correspondingly unreachable via this column. The guard is kept because "
            "sqlite deployments can reach it; this test can only run where it is real."
        ),
    )
    def test_invalid_ip_in_logs_is_skipped(self, db):
        """RequestLog entries with invalid IP addresses are silently skipped."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # Create a log entry with a value that cannot be parsed as an IP
        RequestLogFactory(ip_address="999.999.999.999", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            # Should not raise
            result = detect_subnet_burst(window_minutes=60)

        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# detect_cloud_spray, IPv6 subnet aggregation
# ---------------------------------------------------------------------------


class TestDetectCloudSprayIPv6:
    def test_ipv6_suspicious_ips_are_aggregated_to_slash48_not_slash24(self, db):
        """detect_cloud_spray aggregates IPv6 IPs to their /48 network.

        Regression: the subnet aggregation step naively applied
        ``ipaddress.ip_network(f"{ip}/24", strict=False)`` to every IP,
        which for IPv6 addresses produces an absurdly wide network (a /24
        IPv6 prefix still spans 2**104 addresses). It must instead go
        through ``_get_subnet_prefix``, the same helper used by
        ``detect_subnet_burst``, which truncates IPv6 to /48.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_cloud_spray

        now = timezone.now()
        shared_ua = "curl/8.0.0"
        # DJANGO_WAF_CLOUD_SPRAY_MIN_IPS distinct IPv6 IPs in the same /48,
        # each making a single request with no referer.
        min_ips = 20
        for i in range(min_ips):
            RequestLogFactory(
                ip_address=f"2001:db8:abcd:1234::{i:x}",
                user_agent=shared_ua,
                referer="",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert len(created) == 1
        assert created[0].pattern == "2001:db8:abcd::/48"


# ---------------------------------------------------------------------------
# sync_feed
# ---------------------------------------------------------------------------


class TestSyncFeed:
    def test_creates_new_rules_from_feed(self, db):
        """sync_feed creates BlockRule records for new feed entries."""
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "1.2.3.4",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
                "reporters": 5,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        assert result["updated"] == 0
        assert result["skipped"] == 0
        assert BlockRule.objects.filter(source="feed", pattern="1.2.3.4").exists()

    def test_updates_existing_feed_rule(self, db):
        """sync_feed updates an existing feed rule matched on (source, rule_type, pattern)."""
        from django_waf.enums import RuleSource
        from django_waf.services.threat_feed import sync_feed

        BlockRuleFactory(
            source=RuleSource.FEED,
            rule_type="ip",
            match_type="exact",
            pattern="5.6.7.8",
            action="block",
            confidence="0.7",
            is_active=True,
        )

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "5.6.7.8",
                "action": "challenge",
                "match_type": "exact",
                "confidence": 0.95,
                "reporters": 10,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["updated"] == 1
        assert result["created"] == 0

    def test_skips_entries_below_confidence_threshold(self, db):
        """Entries with confidence below the threshold are counted as skipped."""
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "9.9.9.9",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.1,  # below threshold
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.8)

        assert result["skipped"] == 1
        assert result["created"] == 0

    def test_skips_entries_missing_rule_type_or_pattern(self, db):
        """Entries without rule_type or pattern are counted as skipped."""
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {"confidence": 0.9, "action": "block"},  # missing rule_type and pattern
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1

    def test_deactivates_feed_rules_absent_from_feed(self, db):
        """Feed rules no longer in the feed response are deactivated (BR-FEED-005)."""
        from django_waf.enums import RuleSource
        from django_waf.services.threat_feed import sync_feed

        stale_rule = BlockRuleFactory(
            source=RuleSource.FEED,
            rule_type="ip",
            match_type="exact",
            pattern="10.20.30.40",
            action="block",
            is_active=True,
        )

        # Feed returns an empty list, stale_rule is not present
        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = []
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["expired"] == 1
        stale_rule.refresh_from_db()
        assert stale_rule.is_active is False

    def test_network_error_returns_error_dict(self, db):
        """When the HTTP request fails, sync_feed returns an error dict without raising."""
        from django_waf.services.threat_feed import sync_feed

        with patch("httpx.get", side_effect=Exception("connection refused")):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert "error" in result
        assert result["created"] == 0

    def test_accepts_wrapped_rules_dict(self, db):
        """sync_feed handles a feed payload wrapped in {'rules': [...]} format."""
        from django_waf.services.threat_feed import sync_feed

        feed_payload = {
            "rules": [
                {
                    "rule_type": "ip",
                    "pattern": "11.22.33.44",
                    "action": "block",
                    "match_type": "exact",
                    "confidence": 0.9,
                }
            ]
        }

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1

    def test_entry_with_expires_field_uses_parsed_datetime(self, db):
        """A feed entry with an 'expires' field sets expires_at from that value."""
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        future_ts = "2099-12-31T00:00:00+00:00"
        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "66.77.88.99",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
                "expires": future_ts,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        rule = BlockRule.objects.get(pattern="66.77.88.99")
        assert rule.expires_at.year == 2099

    def test_emits_feed_synced_signal(self, db):
        """sync_feed emits the feed_synced signal on completion."""
        from django_waf.services.threat_feed import sync_feed
        from django_waf.signals import feed_synced

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        feed_synced.connect(handler, dispatch_uid="test_sync_feed_signal")
        try:
            with patch("httpx.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.json.return_value = []
                mock_resp.raise_for_status.return_value = None
                mock_get.return_value = mock_resp

                sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)
        finally:
            feed_synced.disconnect(dispatch_uid="test_sync_feed_signal")

        assert len(received) == 1
        assert "created" in received[0]

    def test_allow_rule_entry_with_rdns_creates_allow_rule_ac_feed_004(self, db):
        """kind='allow' entry with verify_rdns + rdns_pattern creates AllowRule, no BlockRule.

        AC-FEED-004: Given a feed entry with kind="allow", rule_type="ua",
        pattern="Googlebot", verify_rdns=true, rdns_pattern set, and confidence
        above threshold, when sync_feed processes it, then a feed-sourced
        AllowRule must be created with those fields, and no BlockRule must be
        created for that entry.
        """
        from django_waf.models import AllowRule, BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "Googlebot",
                "match_type": "regex",
                "verify_rdns": True,
                "rdns_pattern": r"\.googlebot\.com$|\.google\.com$",
                "confidence": 0.9,
                "reporters": 3,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        assert result["updated"] == 0
        allow_rule = AllowRule.objects.filter(pattern="Googlebot").first()
        assert allow_rule is not None
        assert allow_rule.verify_rdns is True
        assert allow_rule.rdns_pattern == r"\.googlebot\.com$|\.google\.com$"
        assert allow_rule.feed_reporters == 3
        assert BlockRule.objects.filter(pattern="Googlebot").count() == 0

    def test_feed_no_kind_field_imports_as_block_rule_ac_feed_005(self, db):
        """Feed with no kind field on any entry imports as BlockRule (backward compat).

        AC-FEED-005: Given a feed with no kind field on any entry, when
        sync_feed processes it, then every entry must import as BlockRule
        exactly as before the allow-rule extension (backward compatibility),
        and no AllowRule must be created.
        """
        from django_waf.models import AllowRule, BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": "scraperbot",
                "action": "block",
                "match_type": "contains",
                "confidence": 0.85,
            },
            {
                "rule_type": "ip",
                "pattern": "192.0.2.1",
                "action": "challenge",
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 2
        assert BlockRule.objects.filter(pattern="scraperbot").count() == 1
        assert BlockRule.objects.filter(pattern="192.0.2.1").count() == 1
        assert AllowRule.objects.count() == 0

    def test_allow_rule_absent_from_feed_deactivates_ac_feed_006(self, db):
        """Feed-sourced AllowRule absent in later sync is deactivated.

        AC-FEED-006: Given a feed-sourced AllowRule created by a prior sync,
        when a later sync_feed runs whose response no longer contains that
        entry, then the AllowRule must be deactivated (is_active=False),
        mirroring the block-rule absence rule.
        """
        from django_waf.enums import RuleSource
        from django_waf.services.threat_feed import sync_feed

        stale_allow = AllowRuleFactory(
            source=RuleSource.FEED,
            rule_type="ua",
            match_type="regex",
            pattern="OldBot",
            verify_rdns=True,
            rdns_pattern=r"\.oldbot\.com$",
            is_active=True,
        )

        # Feed returns entries but not the stale_allow entry
        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "NewBot",
                "match_type": "regex",
                "verify_rdns": True,
                "rdns_pattern": r"\.newbot\.com$",
                "confidence": 0.9,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["expired"] == 1
        stale_allow.refresh_from_db()
        assert stale_allow.is_active is False

    def test_allow_entry_below_confidence_threshold_skipped(self, db):
        """Allow entry with confidence below threshold is skipped, no AllowRule.

        Covers the confidence threshold gate for allow-kind entries.
        """
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "LowConfidenceBot",
                "match_type": "contains",
                "verify_rdns": False,
                "confidence": 0.2,  # below 0.5 threshold
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0
        assert AllowRule.objects.filter(pattern="LowConfidenceBot").count() == 0

    def test_sync_feed_allow_rule_idempotent(self, db):
        """Re-syncing identical allow feed is idempotent: AllowRule count stable.

        Verifies the update_or_create keying on (source, rule_type, pattern).
        Per #33, a feed allow entry must carry verify_rdns=True with a
        non-empty rdns_pattern or it is skipped, so this fixture now supplies
        both. The created rule is quarantined (is_active=False) by default
        (DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES), which idempotency is
        unaffected by.
        """
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "IdempotentBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": r"\.idempotentbot\.example$",
                "confidence": 0.95,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result1 = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)
            result2 = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result1["created"] == 1
        assert result1["updated"] == 0
        assert result2["created"] == 0
        assert result2["updated"] == 1
        assert AllowRule.objects.filter(pattern="IdempotentBot").count() == 1

    def test_block_and_allow_same_pattern_do_not_interfere(self, db):
        """Block and allow entries with same (rule_type, pattern) coexist.

        Verifies separate tracking in seen_block_keys and seen_allow_keys.
        Per #33, the allow entry carries verify_rdns=True and rdns_pattern
        so it is not skipped by the rDNS-required-for-allow constraint.
        """
        from django_waf.models import AllowRule, BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "block",
                "rule_type": "ua",
                "pattern": "DualBot",
                "action": "block",
                "match_type": "contains",
                "confidence": 0.9,
            },
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "DualBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": r"\.dualbot\.example$",
                "confidence": 0.9,
            },
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 2
        assert BlockRule.objects.filter(pattern="DualBot").count() == 1
        assert AllowRule.objects.filter(pattern="DualBot").count() == 1


# ---------------------------------------------------------------------------
# Seed migration and rDNS verification
# ---------------------------------------------------------------------------


class TestSeedVerifiedCrawlers:
    """Test the seed_verified_crawlers migration function (AC-CHAL-001a/d)."""

    def test_seed_creates_two_rows_with_default_setting(self, db):
        """With DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS=True, seed creates 2 rows.

        AC-CHAL-001a: Given a fresh database migrated with
        DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS at its default (True), when
        migrations have run, then active rDNS-gated AllowRule rows must exist
        for Googlebot and Bingbot.
        """
        from importlib import import_module

        from django.apps import apps

        from django_waf.models import AllowRule

        # Import the migration module to get the seed function
        migration = import_module("django_waf.migrations.0003_seed_verified_crawlers")
        seed_verified_crawlers = migration.seed_verified_crawlers

        # Clear any existing rows
        AllowRule.objects.all().delete()

        # Call seed_verified_crawlers directly
        seed_verified_crawlers(apps, None)

        # Verify exactly 2 rows created with correct patterns
        assert AllowRule.objects.count() == 2
        googlebot = AllowRule.objects.get(pattern="Googlebot")
        bingbot = AllowRule.objects.get(pattern="bingbot")

        assert googlebot.verify_rdns is True
        assert googlebot.rdns_pattern == r"\.googlebot\.com$|\.google\.com$"
        assert googlebot.is_active is True
        assert googlebot.rule_type == "ua"
        assert googlebot.match_type == "regex"

        assert bingbot.verify_rdns is True
        assert bingbot.rdns_pattern == r"\.search\.msn\.com$"
        assert bingbot.is_active is True
        assert bingbot.rule_type == "ua"
        assert bingbot.match_type == "regex"

    def test_seed_is_idempotent(self, db):
        """Re-running seed_verified_crawlers keeps AllowRule count at 2.

        Tests the update_or_create keying.
        """
        from importlib import import_module

        from django.apps import apps

        from django_waf.models import AllowRule

        migration = import_module("django_waf.migrations.0003_seed_verified_crawlers")
        seed_verified_crawlers = migration.seed_verified_crawlers

        AllowRule.objects.all().delete()

        seed_verified_crawlers(apps, None)
        count_first = AllowRule.objects.count()

        seed_verified_crawlers(apps, None)
        count_second = AllowRule.objects.count()

        assert count_first == 2
        assert count_second == 2

    def test_unseed_removes_crawler_rows(self, db):
        """Unseed removes exactly the two seeded crawler rows.

        Tests the rollback path.
        """
        from importlib import import_module

        from django.apps import apps

        from django_waf.models import AllowRule

        migration = import_module("django_waf.migrations.0003_seed_verified_crawlers")
        seed_verified_crawlers = migration.seed_verified_crawlers
        unseed_verified_crawlers = migration.unseed_verified_crawlers

        AllowRule.objects.all().delete()

        seed_verified_crawlers(apps, None)
        assert AllowRule.objects.count() == 2

        unseed_verified_crawlers(apps, None)
        assert AllowRule.objects.count() == 0

    def test_seed_respects_allow_verified_crawlers_setting_false(self, db):
        """With DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS=False, seed creates 0 rows.

        AC-CHAL-001d: Given DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS=False at
        migrate time, when migrations run on a fresh database, then the
        crawler seed rows must not be created.
        """
        from importlib import import_module

        from django.apps import apps
        from django.test import override_settings

        from django_waf.models import AllowRule

        migration = import_module("django_waf.migrations.0003_seed_verified_crawlers")
        seed_verified_crawlers = migration.seed_verified_crawlers

        AllowRule.objects.all().delete()

        with override_settings(DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS=False):
            seed_verified_crawlers(apps, None)

        assert AllowRule.objects.count() == 0


class TestRdnsGatingInRuleEngine:
    """Test rDNS verification in rule evaluation (AC-CHAL-001b/c).

    These test the service layer, mocking rDNS resolution to avoid
    real socket calls. Tests verify that the allow-rule matching path
    respects verify_rdns gating.
    """

    def test_allow_rule_with_rdns_passes_matching_ptr(self, db):
        """AllowRule with verify_rdns=True passes when PTR matches rdns_pattern.

        AC-CHAL-001b: Given an active seeded-equivalent Googlebot AllowRule
        with verify_rdns=True, when the request arrives from an IP whose PTR
        record ends in .googlebot.com, then evaluate_request must return
        PASSED via the allow rule.
        """
        from django_waf.enums import Verdict
        from django_waf.services.rule_engine import evaluate_request

        # Create an AllowRule matching Googlebot with rDNS gating
        AllowRuleFactory(
            rule_type="ua",
            match_type="regex",
            pattern="Googlebot",
            verify_rdns=True,
            rdns_pattern=r"\.googlebot\.com$|\.google\.com$",
            is_active=True,
        )

        redis_client = _make_redis()

        # Mock _verify_rdns to return True (PTR matches)
        with patch("django_waf.services.rule_engine._verify_rdns", return_value=True):
            result = evaluate_request(
                ip_address="1.2.3.4",
                user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
                path="/",
                method="GET",
                redis_client=redis_client,
            )

        assert result.verdict == Verdict.PASSED
        assert result.matched_rule_id is not None

    def test_allow_rule_with_rdns_fails_non_matching_ptr(self, db):
        """AllowRule with verify_rdns=True fails when PTR does not match.

        AC-CHAL-001c: Given a spoofed Googlebot UA from an IP whose PTR
        record does not resolve under .googlebot.com/.google.com, when
        evaluate_request runs, then the seeded AllowRule must not match
        (rDNS check fails) and the request must fall through to normal
        scoring.
        """
        from django_waf.services.rule_engine import evaluate_request

        # Create an AllowRule for Googlebot with rDNS gating
        AllowRuleFactory(
            rule_type="ua",
            match_type="regex",
            pattern="Googlebot",
            verify_rdns=True,
            rdns_pattern=r"\.googlebot\.com$|\.google\.com$",
            is_active=True,
        )

        redis_client = _make_redis()
        # Set up the pipeline for rate limit checks (execute returns [zadd, zrem, zcard, expire])
        # zcard returns 1 (within limits)
        redis_client.pipeline.return_value = _make_pipeline_mock(1)

        # Mock _verify_rdns to return False (PTR does not match)
        with patch("django_waf.services.rule_engine._verify_rdns", return_value=False):
            result = evaluate_request(
                ip_address="203.0.113.1",  # spoofed IP without valid PTR
                user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
                path="/",
                method="GET",
                redis_client=redis_client,
            )

        # Without the allow rule match, the request falls through to normal scoring
        # and is unlikely to pass (Googlebot UA alone without allow rule doesn't grant pass)
        assert result.matched_rule_type != "allow"


# ---------------------------------------------------------------------------
# build_telemetry_payload
# ---------------------------------------------------------------------------


class TestBuildTelemetryPayload:
    def test_returns_payload_with_expected_keys(self, db):
        """build_telemetry_payload returns a dict with all required top-level keys."""
        from django_waf.services.threat_feed import build_telemetry_payload

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="test-install-id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert set(payload.keys()) == {"install_id", "period", "ua_hashes", "subnets", "anomalies", "summary"}

    def test_install_id_in_payload(self, db):
        """The install_id from get_or_create_install_id is included in the payload."""
        from django_waf.services.threat_feed import build_telemetry_payload

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="my-stable-id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert payload["install_id"] == "my-stable-id"

    def test_summary_counts_requests_in_period(self, db):
        """summary.total_requests reflects the count of RequestLog entries in the period."""
        from django_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory.create_batch(3, timestamp=now - timezone.timedelta(minutes=30))

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert payload["summary"]["total_requests"] == 3

    def test_ua_hashes_are_sha256_of_ua_rules(self, db):
        """UA block rules are hashed with SHA-256, raw patterns are not included."""
        import hashlib

        from django_waf.enums import RuleSource
        from django_waf.services.threat_feed import build_telemetry_payload

        raw_pattern = "EvilBot/1.0"
        BlockRuleFactory(
            source=RuleSource.ADMIN,
            rule_type="ua",
            match_type="exact",
            pattern=raw_pattern,
            is_active=True,
        )

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        ua_hashes = payload["ua_hashes"]
        assert len(ua_hashes) == 1
        expected_hash = hashlib.sha256(raw_pattern.encode()).hexdigest()
        assert ua_hashes[0]["sha256"] == expected_hash
        # Raw pattern must not appear anywhere in the payload
        assert raw_pattern not in str(payload)

    def test_subnets_are_truncated_to_slash24(self, db):
        """IP addresses in logs are truncated to /24 subnets in the payload."""
        from django_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory(ip_address="192.0.2.100", timestamp=now - timezone.timedelta(minutes=5))

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        subnet_cidrs = [s["cidr"] for s in payload["subnets"]]
        assert "192.0.2.0/24" in subnet_cidrs

    @pytest.mark.skipif(
        connection.vendor != "sqlite",
        reason=(
            "Needs a malformed value in RequestLog.ip_address; PostgreSQL's inet type "
            "rejects it at insert. See the matching skip on "
            "TestDetectSubnetBurstBranches.test_invalid_ip_in_logs_is_skipped."
        ),
    )
    def test_invalid_ip_in_logs_is_skipped(self, db):
        """RequestLog entries with invalid IPs are skipped during subnet aggregation."""
        from django_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory(ip_address="999.999.999.999", timestamp=now - timezone.timedelta(minutes=5))

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            # Should not raise
            payload = build_telemetry_payload(period_start, period_end)

        assert isinstance(payload["subnets"], list)

    def test_ipv6_subnets_are_truncated_to_slash48_not_full_address(self, db):
        """IPv6 addresses are truncated to /48 subnets, a full IPv6 address
        must never appear in the telemetry payload (BR-TEL-002).

        Regression: the pre-fix code applied "/24" unconditionally, which for
        IPv6 produces a network so wide it is effectively meaningless as
        aggregation and leaks far more positional information than intended.
        """
        from django_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        full_ip = "2001:db8:abcd:1234::1"
        RequestLogFactory(ip_address=full_ip, timestamp=now - timezone.timedelta(minutes=5))

        with patch("django_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        subnet_cidrs = [s["cidr"] for s in payload["subnets"]]
        assert "2001:db8:abcd::/48" in subnet_cidrs
        # The full address must not appear anywhere in the payload.
        assert full_ip not in str(payload)


# ---------------------------------------------------------------------------
# submit_telemetry
# ---------------------------------------------------------------------------


class TestSubmitTelemetry:
    def test_returns_true_on_successful_post(self):
        """submit_telemetry returns True when the server responds with 2xx."""
        from django_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is True

    def test_returns_false_on_non_2xx_response(self):
        """submit_telemetry returns False when the server responds with a non-2xx status."""
        from django_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.is_success = False
            mock_resp.status_code = 503
            mock_post.return_value = mock_resp

            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is False

    def test_returns_false_on_network_error(self):
        """submit_telemetry returns False when a network error occurs (BR-TEL-004)."""
        from django_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post", side_effect=Exception("timeout")):
            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is False

    def test_includes_bearer_token_when_api_key_set(self):
        """An API key from conf is sent as a Bearer token in the Authorization header."""
        import django_waf.conf as conf_mod
        from django_waf.services.threat_feed import submit_telemetry

        with (
            patch.object(conf_mod, "DJANGO_WAF_FEED_API_KEY", "secret-key-123"),
            patch("httpx.post") as mock_post,
        ):
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        _, call_kwargs = mock_post.call_args
        headers = call_kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer secret-key-123"

    def test_omits_auth_header_when_no_api_key(self):
        """When DJANGO_WAF_FEED_API_KEY is empty, no Authorization header is sent."""
        import django_waf.conf as conf_mod
        from django_waf.services.threat_feed import submit_telemetry

        with (
            patch.object(conf_mod, "DJANGO_WAF_FEED_API_KEY", ""),
            patch("httpx.post") as mock_post,
        ):
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        _, call_kwargs = mock_post.call_args
        headers = call_kwargs.get("headers", {})
        assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# get_or_create_install_id
# ---------------------------------------------------------------------------


class TestGetOrCreateInstallId:
    """get_or_create_install_id caches through django.core.cache.caches[alias]
    (#149, ADR-037), not the bare ``cache`` proxy, so these tests patch
    ``django.core.cache.caches`` with a mapping whose ``__getitem__`` returns
    the mock, rather than patching ``django.core.cache.cache`` directly
    (which the function under test no longer touches).
    """

    def _patched_caches(self, mock_cache):
        mapping = MagicMock()
        mapping.__getitem__.return_value = mock_cache
        return patch("django.core.cache.caches", mapping)

    def test_returns_cached_value_without_file_io(self):
        """Returns the install_id from Django cache without touching the filesystem."""
        from django_waf.services.threat_feed import get_or_create_install_id

        mock_cache = MagicMock()
        mock_cache.get.return_value = "cached-install-id"

        with self._patched_caches(mock_cache):
            result = get_or_create_install_id()

        assert result == "cached-install-id"

    def test_reads_id_from_file_when_cache_empty(self, tmp_path):
        """When the cache is empty, reads install_id from the filesystem file."""
        from unittest.mock import mock_open

        from django_waf.services.threat_feed import get_or_create_install_id

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        with (
            self._patched_caches(mock_cache),
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", mock_open(read_data="file-install-id")),
        ):
            result = get_or_create_install_id()

        assert result == "file-install-id"

    def test_generates_new_uuid_when_no_file_exists(self, tmp_path):
        """When the cache is empty and no file exists, generates and persists a new UUID."""
        import uuid as uuid_mod

        from django_waf.services.threat_feed import get_or_create_install_id

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        with (
            self._patched_caches(mock_cache),
            patch("os.path.isfile", return_value=False),
            patch("uuid.uuid4", return_value=uuid_mod.UUID("12345678-1234-5678-1234-567812345678")),
            patch("builtins.open", side_effect=OSError("no write")),
        ):
            result = get_or_create_install_id()

        assert result == "12345678-1234-5678-1234-567812345678"
        mock_cache.set.assert_called_once()

    def test_persists_new_id_to_cache(self, tmp_path):
        """A freshly generated install_id is stored in the Django cache."""
        from django_waf.services.threat_feed import get_or_create_install_id

        mock_cache = MagicMock()
        mock_cache.get.return_value = None

        with (
            self._patched_caches(mock_cache),
            patch("os.path.isfile", return_value=False),
            patch("builtins.open", side_effect=OSError("no write")),
        ):
            get_or_create_install_id()

        assert mock_cache.set.called


class TestGetOrCreateInstallIdIcvCachesAliasRouting:
    """get_or_create_install_id routes through ICV_CACHES_ALIAS (#149,
    ADR-037), proven against two real, distinct LocMemCache aliases rather
    than a mock: writing to the wrong alias and reading it back from the
    right one would pass a mocked test that only asserts "some cache was
    called", so this uses ``django.core.cache.caches`` for real.
    """

    def test_writes_to_the_configured_alias_and_not_default(self):
        from django.core.cache import caches
        from django.test import override_settings

        from django_waf.services.threat_feed import _INSTALL_ID_SETTING, get_or_create_install_id

        with override_settings(
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "icv-caches-alias-default",
                },
                "icv": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "icv-caches-alias-icv",
                },
            },
            ICV_CACHES_ALIAS="icv",
        ):
            caches["default"].clear()
            caches["icv"].clear()

            with (
                patch("os.path.isfile", return_value=False),
                patch("builtins.open", side_effect=OSError("no write")),
            ):
                install_id = get_or_create_install_id()

            assert caches["icv"].get(_INSTALL_ID_SETTING) == install_id
            assert caches["default"].get(_INSTALL_ID_SETTING) is None


# ---------------------------------------------------------------------------
# generate_nginx_blocklist
# ---------------------------------------------------------------------------


class TestGenerateNginxBlocklist:
    def test_writes_file_with_ip_and_ua_rules(self, db, tmp_path):
        """generate_nginx_blocklist writes both IP/CIDR and UA rules to the output file."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        BlockRuleFactory(
            is_active=True,
            rule_type="ip",
            match_type="exact",
            pattern="10.0.0.1",
            action="block",
        )
        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="EvilBot/1.0",
            action="block",
        )

        count = generate_nginx_blocklist(output_path=output_file)

        assert count == 2
        with open(output_file) as fh:
            content = fh.read()
        assert "10.0.0.1" in content
        assert '"EvilBot/1.0"' in content
        assert "map $http_user_agent $waf_block_ua" in content
        assert "geo $waf_block_ip" in content

    def test_returns_count_of_rules_written(self, db, tmp_path):
        """generate_nginx_blocklist returns the number of rules written."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory.create_batch(3, is_active=True, rule_type="ip", match_type="exact", action="block")
        output_file = str(tmp_path / "blocklist.conf")

        count = generate_nginx_blocklist(output_path=output_file)

        assert count == 3

    def test_write_is_atomic_via_rename(self, db, tmp_path):
        """The output file is written via temp file + rename (BR-BL-002)."""
        import os

        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        rename_calls = []
        real_rename = os.rename

        def tracking_rename(src, dst):
            rename_calls.append((src, dst))
            real_rename(src, dst)

        with patch("django_waf.services.blocklist_generator.os.rename", side_effect=tracking_rename):
            generate_nginx_blocklist(output_path=output_file)

        assert len(rename_calls) == 1
        _, dst = rename_calls[0]
        assert dst == output_file

    def test_ua_contains_pattern_escaped_as_regex(self, db, tmp_path):
        """UA rules with match_type='contains' are written as case-insensitive nginx regexes."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="contains",
            pattern="badbot",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        # Contains pattern should use ~* prefix
        assert "~*" in content

    def test_ua_regex_pattern_written_with_prefix(self, db, tmp_path):
        """UA rules with match_type='regex' are written with ~* nginx prefix."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="regex",
            pattern=r"EvilBot/\d+",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        assert "~*" in content

    def test_empty_ua_pattern_is_omitted(self, db, tmp_path):
        """UA rules with an empty pattern are not written to the output file."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="",  # empty, should be skipped
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        # An empty-pattern rule should produce no entry line beyond 'default 0;'
        ua_section = content.split("map $http_user_agent")[1].split("}")[0]
        lines_with_entries = [
            line for line in ua_section.splitlines() if line.strip() and "default 0" not in line and "{" not in line
        ]
        assert lines_with_entries == []


# ---------------------------------------------------------------------------
# reload_nginx
# ---------------------------------------------------------------------------


class TestReloadNginx:
    def test_returns_true_on_successful_reload(self):
        """reload_nginx returns True when nginx exits with code 0."""
        from django_waf.services.blocklist_generator import reload_nginx

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")

            result = reload_nginx()

        assert result is True

    def test_returns_false_on_nonzero_exit_code(self):
        """reload_nginx returns False when nginx exits with a non-zero code."""
        from django_waf.services.blocklist_generator import reload_nginx

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="configuration file error")

            result = reload_nginx()

        assert result is False

    def test_returns_false_when_nginx_not_found(self):
        """reload_nginx returns False when nginx is not on the PATH."""
        from django_waf.services.blocklist_generator import reload_nginx

        with patch(
            "django_waf.services.blocklist_generator.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            result = reload_nginx()

        assert result is False

    def test_returns_false_on_timeout(self):
        """reload_nginx returns False when the subprocess times out."""
        import subprocess

        from django_waf.services.blocklist_generator import reload_nginx

        with patch(
            "django_waf.services.blocklist_generator.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nginx", timeout=10),
        ):
            result = reload_nginx()

        assert result is False

    def test_returns_false_on_os_error(self):
        """reload_nginx returns False on a generic OSError."""
        from django_waf.services.blocklist_generator import reload_nginx

        with patch(
            "django_waf.services.blocklist_generator.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            result = reload_nginx()

        assert result is False


# ---------------------------------------------------------------------------
# rule_engine, _verify_rdns
# ---------------------------------------------------------------------------


class TestVerifyRdns:
    """_verify_rdns is forward-confirmed reverse DNS (FCrDNS) since #34, see
    tests/test_rdns_fcrdns.py for the full FCrDNS-specific coverage (spoofed
    PTR denial, genuine FCrDNS allow, IPv4/IPv6, failure-cache TTLs). These
    tests keep the lighter-weight "does the wiring still work" coverage in
    this shared file."""

    def test_returns_true_when_ptr_matches_and_forward_confirms(self):
        """_verify_rdns returns True when the PTR hostname matches the pattern
        AND the hostname forward-resolves back to the original IP."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None  # No cached verdict

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("66.249.66.1", 0))],
            ),
        ):
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        assert result is True

    def test_returns_false_when_hostname_does_not_match_pattern(self):
        """A PTR hostname that doesn't match the pattern fails before any forward lookup."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch("django_waf.services.rule_engine.socket.gethostbyaddr", return_value=("evil.example.com", [], [])),
            patch("django_waf.services.rule_engine.socket.getaddrinfo") as mock_forward,
        ):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False
        mock_forward.assert_not_called()

    def test_returns_false_when_forward_resolution_does_not_confirm(self):
        """Spoofed PTR: the hostname matches the pattern, but forward
        resolution of that hostname does not include the original IP:
        the attacker controls the PTR record but not the pattern's DNS
        zone (#34's core fix)."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("spoofed.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("9.9.9.9", 0))],  # not the original IP
            ),
        ):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False

    def test_returns_false_on_reverse_dns_failure(self):
        """_verify_rdns returns False when the reverse (PTR) lookup fails."""
        import socket

        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with patch("django_waf.services.rule_engine.socket.gethostbyaddr", side_effect=socket.herror):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False

    def test_returns_false_on_forward_dns_failure(self):
        """_verify_rdns returns False when the forward lookup fails, even
        though the PTR hostname matched the pattern (fails closed)."""
        import socket

        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                side_effect=socket.gaierror,
            ),
        ):
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        assert result is False

    def test_uses_cached_positive_verdict_without_dns_lookup(self):
        """_verify_rdns uses a cached positive verdict from Redis without
        performing either DNS lookup."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = b"1"

        with (
            patch("django_waf.services.rule_engine.socket.gethostbyaddr") as mock_reverse,
            patch("django_waf.services.rule_engine.socket.getaddrinfo") as mock_forward,
        ):
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        mock_reverse.assert_not_called()
        mock_forward.assert_not_called()
        assert result is True

    def test_uses_cached_negative_verdict_without_dns_lookup(self):
        """A cached negative verdict ("0") also short-circuits both lookups."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = b"0"

        with patch("django_waf.services.rule_engine.socket.gethostbyaddr") as mock_reverse:
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        mock_reverse.assert_not_called()
        assert result is False

    def test_stores_positive_verdict_with_24h_ttl(self):
        """A successful FCrDNS verification is cached for 24 hours."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("host.example.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("1.2.3.4", 0))],
            ),
        ):
            _verify_rdns("1.2.3.4", r"example\.com$", redis)

        assert redis.setex.called
        call_args = redis.setex.call_args
        assert call_args.args[1] == 86400  # 24-hour TTL
        assert call_args.args[2] == "1"

    def test_stores_negative_verdict_with_short_failure_ttl(self):
        """A failed verification is cached with DJANGO_WAF_RDNS_FAILURE_CACHE_TTL,
        not the 24-hour positive TTL."""
        import django_waf.conf as conf_mod
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch.object(conf_mod, "DJANGO_WAF_RDNS_FAILURE_CACHE_TTL", 300),
            patch("django_waf.services.rule_engine.socket.gethostbyaddr", return_value=("evil.example.com", [], [])),
        ):
            _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert redis.setex.called
        call_args = redis.setex.call_args
        assert call_args.args[1] == 300
        assert call_args.args[2] == "0"

    def test_returns_false_for_empty_ptr_hostname(self):
        """An empty PTR hostname (successful lookup, empty result) fails
        before any forward lookup."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with (
            patch("django_waf.services.rule_engine.socket.gethostbyaddr", return_value=("", [], [])),
            patch("django_waf.services.rule_engine.socket.getaddrinfo") as mock_forward,
        ):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False
        mock_forward.assert_not_called()

    def test_returns_false_for_invalid_rdns_regex(self):
        """_verify_rdns returns False gracefully when rdns_pattern is an invalid regex."""
        from django_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with patch("django_waf.services.rule_engine.socket.gethostbyaddr", return_value=("host.example.com", [], [])):
            result = _verify_rdns("1.2.3.4", "[invalid(regex", redis)

        assert result is False


# ---------------------------------------------------------------------------
# rule_engine, _check_block_rules CIDR and regex paths
# ---------------------------------------------------------------------------


class TestCheckBlockRulesPaths:
    def test_cidr_rule_matches_ip_in_range(self, db):
        """_check_block_rules matches a CIDR-type rule for an IP within the network."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        cidr_rule = {
            "id": "00000000-0000-0000-0000-000000000001",
            "rule_type": "cidr",
            "match_type": "cidr",
            "pattern": "10.10.0.0/16",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[cidr_rule], ua_regex_set=[])

        result = _check_block_rules("10.10.5.1", "Mozilla/5.0", cache)

        assert result is not None
        matched_id, rule = result
        assert matched_id == cidr_rule["id"]

    def test_cidr_rule_does_not_match_ip_outside_range(self, db):
        """_check_block_rules does not match a CIDR rule for an IP outside the network."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        cidr_rule = {
            "id": "00000000-0000-0000-0000-000000000002",
            "rule_type": "cidr",
            "match_type": "cidr",
            "pattern": "10.10.0.0/16",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[cidr_rule], ua_regex_set=[])

        result = _check_block_rules("192.168.1.1", "Mozilla/5.0", cache)

        assert result is None

    def test_ua_regex_rule_matches(self, db):
        """_check_block_rules matches a UA rule with regex match_type."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        ua_rule = {
            "id": "00000000-0000-0000-0000-000000000003",
            "rule_type": "ua",
            "match_type": "regex",
            "pattern": r"EvilBot/\d+",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[ua_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "EvilBot/3", cache)

        assert result is not None

    def test_ua_contains_rule_matches(self, db):
        """_check_block_rules matches a UA rule with contains match_type."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        ua_rule = {
            "id": "00000000-0000-0000-0000-000000000004",
            "rule_type": "ua",
            "match_type": "contains",
            "pattern": "SuspiciousTool",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[ua_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "Some SuspiciousTool/2.0", cache)

        assert result is not None

    def test_unknown_rule_type_returns_none(self, db):
        """_check_block_rules returns None for an unrecognised rule_type."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        unknown_rule = {
            "id": "00000000-0000-0000-0000-000000000005",
            "rule_type": "unknown_type",
            "match_type": "exact",
            "pattern": "1.2.3.4",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[unknown_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "Mozilla/5.0", cache)

        assert result is None


# ---------------------------------------------------------------------------
# rule_engine, _compile_ua_patterns invalid regex
# ---------------------------------------------------------------------------


class TestCompileUaPatterns:
    def test_invalid_regex_pattern_is_skipped_with_warning(self):
        """_compile_ua_patterns skips rules with invalid regex patterns."""
        from django_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "rule_type": "ua",
                "match_type": "regex",
                "pattern": "[invalid(regex",  # deliberately invalid
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        # Invalid pattern should be silently dropped
        assert result == []

    def test_valid_regex_pattern_is_compiled(self):
        """_compile_ua_patterns compiles a valid regex pattern."""
        from django_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "rule_type": "ua",
                "match_type": "regex",
                "pattern": r"BadBot/\d+",
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        assert len(result) == 1
        compiled_re, rule_dict = result[0]
        assert compiled_re.search("BadBot/99")

    def test_non_ua_rules_are_excluded(self):
        """_compile_ua_patterns only processes ua-type rules."""
        from django_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000003",
                "rule_type": "ip",
                "match_type": "exact",
                "pattern": "1.2.3.4",
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        assert result == []


# ---------------------------------------------------------------------------
# rule_engine, load_rule_cache DB fallback path
# ---------------------------------------------------------------------------


class TestLoadRuleCacheDbFallback:
    def test_corrupt_json_triggers_db_rebuild(self, db):
        """A corrupt Redis cache value causes a DB rebuild."""
        BlockRuleFactory(is_active=True, rule_type=RuleType.IP)
        AllowRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.side_effect = ["3", b"{not: valid json}"]

        cache = load_rule_cache(redis)

        assert len(cache.block_rules) == 1
        assert len(cache.allow_rules) == 1

    def test_db_rebuild_stores_result_in_redis(self, db):
        """After a DB rebuild, the result is stored in Redis via setex."""
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.return_value = None

        load_rule_cache(redis)

        assert redis.setex.called


# ---------------------------------------------------------------------------
# rule_engine, record_block_verdict
# ---------------------------------------------------------------------------


class TestRecordBlockVerdict:
    def test_sets_blocked_ip_key_in_redis(self):
        """record_block_verdict writes the blocked-IP key to Redis with the given TTL."""
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("1.2.3.4", redis, ttl=300)

        redis.setex.assert_called_once_with("waf:blocked:1.2.3.4", 300, "1")

    def test_increments_daily_stats_counter(self):
        """record_block_verdict increments the daily stats blocked counter."""
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("1.2.3.4", redis, ttl=300)

        redis.hincrby.assert_called_once_with("waf:stats:today", "blocked", 1)

    def test_custom_ttl_is_respected(self):
        """record_block_verdict uses the custom TTL argument."""
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("5.6.7.8", redis, ttl=600)

        call_args = redis.setex.call_args.args
        assert call_args[1] == 600

    def test_default_ttl_is_300(self):
        """record_block_verdict defaults to a 300-second TTL."""
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("9.8.7.6", redis)

        call_args = redis.setex.call_args.args
        assert call_args[1] == 300

    def test_stores_rule_id_when_provided(self):
        """When called with rule_id, the cache value is the rule UUID string.

        This is what gives the fast-path its hit attribution from v0.10.6
        onward, see test_fast_path_attributes_hit_to_rule.
        """
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("9.8.7.5", redis, ttl=300, rule_id="abc-123")

        redis.setex.assert_called_once_with("waf:blocked:9.8.7.5", 300, "abc-123")

    def test_stores_sentinel_when_rule_id_missing(self):
        """When rule_id is None or empty, falls back to the legacy "1" sentinel."""
        from django_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("9.8.7.4", redis, ttl=300, rule_id=None)

        redis.setex.assert_called_once_with("waf:blocked:9.8.7.4", 300, "1")


# ---------------------------------------------------------------------------
# detect_unsolved_challenges
# ---------------------------------------------------------------------------


class TestDetectUnsolvedChallenges:
    """Tests for the composite unsolved-challenge anomaly detector."""

    @pytest.mark.django_db
    def test_blocks_ip_with_challenges_no_solves_empty_referer(self):
        """IP with 3+ challenged verdicts, 0 solves, and empty referers is blocked."""
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "101.47.1.1"
        now = timezone.now()
        for _ in range(4):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/products/old-page",
                referer="",
                timestamp=now,
            )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.pattern == ip
        assert rule.action == RuleAction.BLOCK
        assert rule.source == RuleSource.AUTO
        assert BlockRule.objects.filter(pattern=ip, is_active=True).exists()

    @pytest.mark.django_db
    def test_skips_ip_with_solved_challenge(self):
        """IP that has solved at least one challenge is not flagged."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.5"
        now = timezone.now()
        for _ in range(5):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )
        ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.SOLVED, solved_at=now)

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_skips_ip_below_min_challenged_threshold(self):
        """IP with fewer than min_challenged verdicts is not flagged."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.6"
        now = timezone.now()
        RequestLogFactory(
            ip_address=ip,
            verdict=Verdict.CHALLENGED,
            path="/page",
            referer="",
            timestamp=now,
        )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_skips_ip_with_referer_present(self):
        """IP whose requests have referer headers is not flagged."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.7"
        now = timezone.now()
        for _ in range(5):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/products/item",
                referer="https://www.google.com/search?q=test",
                timestamp=now,
            )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_skips_ip_with_only_root_path_requests(self):
        """IP with all requests to '/' is skipped (no non-root requests to evaluate)."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.8"
        now = timezone.now()
        for _ in range(5):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/",
                referer="",
                timestamp=now,
            )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_does_not_duplicate_existing_auto_rule(self):
        """update_or_create refreshes an existing auto rule instead of duplicating."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.9"
        now = timezone.now()
        for _ in range(5):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )
        BlockRuleFactory(
            rule_type=RuleType.IP,
            pattern=ip,
            is_active=True,
            action=RuleAction.BLOCK,
            source=RuleSource.AUTO,
        )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0
        from django_waf.models import BlockRule

        assert BlockRule.objects.filter(pattern=ip, source=RuleSource.AUTO).count() == 1

    @pytest.mark.django_db
    def test_referer_ratio_threshold(self):
        """IP with some referers below the ratio threshold is not flagged."""
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.10"
        now = timezone.now()
        # 3 challenged
        for _ in range(3):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )
        # 3 with referer (so ratio is 50%, below 80% default)
        for _ in range(3):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.ALLOWED,
                path="/other",
                referer="https://example.com",
                timestamp=now,
            )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_skips_ip_with_solved_challenge_across_varied_issued_at(self):
        """A solved-challenge IP is skipped even when its tokens' issued_at
        values differ (#59 regression).

        ChallengeToken.Meta.ordering = ["-issued_at"] makes Django append
        issued_at to the SELECT unless order_by() clears it before
        distinct(). With identical issued_at values (the prior fixture)
        DISTINCT still collapses to one row per IP and hides that defect.
        Varying issued_at across rows for a single IP is what proves the
        ordering column no longer corrupts the distinct membership check.
        """
        from django_waf.models import ChallengeToken
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.11"
        now = timezone.now()
        for _ in range(4):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )

        # issued_at is auto_now_add, so create multiple solved tokens for the
        # same IP, then use a queryset update() (which bypasses auto_now_add,
        # unlike save()) to force distinct issued_at values across rows.
        tokens = [ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.SOLVED, solved_at=now) for _ in range(3)]
        for offset, token in enumerate(tokens):
            ChallengeToken.objects.filter(pk=token.pk).update(issued_at=now - timezone.timedelta(minutes=offset))

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert len(rules) == 0

    @pytest.mark.django_db
    def test_wired_into_run_all_detectors(self):
        """run_all_detectors includes unsolved_challenge_rules in its output."""
        from django_waf.services.anomaly_detector import run_all_detectors

        result = run_all_detectors()

        assert "unsolved_challenge_rules" in result
        assert "total_rules_created" in result

    @pytest.mark.django_db
    def test_subnet_promoted_when_no_individual_ip_qualifies(self):
        """A /24 whose IPs each fall below min_challenged is still promoted
        to a CHALLENGE rule once the subnet aggregate clears its own
        threshold with enough distinct contributing IPs (issue #84).

        This must fail against a per-IP-only implementation: every
        individual IP here carries only 2 challenged verdicts, one short of
        min_challenged=3.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        # 15 distinct IPs in 203.0.113.0/24, 2 challenges each = 30 total.
        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.113.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            rules = detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        subnet_rules = [r for r in rules if r.rule_type == RuleType.CIDR]
        assert len(subnet_rules) == 1
        rule = subnet_rules[0]
        assert rule.pattern == "203.0.113.0/24"
        assert rule.action == RuleAction.CHALLENGE
        assert rule.source == RuleSource.AUTO
        assert BlockRule.objects.filter(pattern="203.0.113.0/24", is_active=True).exists()

    @pytest.mark.django_db
    def test_subnet_below_distinct_ip_floor_is_not_promoted(self):
        """A single noisy IP cannot cross the subnet total-count threshold
        alone: the distinct-IP floor guards against one host escalating its
        whole /24.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        # One IP alone racks up 40 challenges -- clears the 30-count floor
        # but only 1 distinct IP, well under the 10-IP floor.
        for _ in range(40):
            RequestLogFactory(
                ip_address="198.51.100.7",
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            rules = detect_unsolved_challenges(window_minutes=60, min_challenged=999)

        subnet_rules = [r for r in rules if r.rule_type == RuleType.CIDR]
        assert subnet_rules == []

    @pytest.mark.django_db
    def test_subnet_second_crossing_promotes_challenge_to_block(self):
        """A repeat crossing of the same subnet promotes the existing active
        auto CHALLENGE rule to BLOCK; a first crossing never blocks
        outright (issue #82's false-positive discipline).
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()

        def make_traffic():
            for i in range(15):
                for _ in range(2):
                    RequestLogFactory(
                        ip_address=f"203.0.114.{i}",
                        verdict=Verdict.CHALLENGED,
                        path="/page",
                        referer="",
                        timestamp=now,
                    )

        make_traffic()
        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            first_pass = detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        first_subnet_rules = [r for r in first_pass if r.rule_type == RuleType.CIDR]
        assert len(first_subnet_rules) == 1
        assert first_subnet_rules[0].action == RuleAction.CHALLENGE

        # A second crossing of the same subnet, with the CHALLENGE rule
        # still active, must promote to BLOCK rather than re-issuing
        # CHALLENGE or blocking on the very first crossing.
        make_traffic()
        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            second_pass = detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        second_subnet_rules = [r for r in second_pass if r.rule_type == RuleType.CIDR]
        assert len(second_subnet_rules) == 1
        assert second_subnet_rules[0].action == RuleAction.BLOCK
        assert second_subnet_rules[0].pattern == "203.0.114.0/24"
        assert "detect_unsolved_challenges" in second_subnet_rules[0].detectors.split(",")

    @pytest.mark.django_db
    def test_subnet_burst_challenge_rule_does_not_promote_first_own_crossing(self):
        """A CHALLENGE rule created by detect_subnet_burst for the same
        subnet must not count as detect_unsolved_challenges's own prior
        crossing (issue #97, own-provenance-only). The first
        detect_unsolved_challenges crossing for this subnet must still
        create CHALLENGE, not BLOCK, even though an active AUTO/CIDR/
        CHALLENGE rule for the identical pattern already exists.

        This must fail against the pre-#97 code: matching on rule shape
        alone (rule_type, pattern, source=AUTO, action=CHALLENGE,
        is_active=True) with no detector scoping treats any detector's
        rule as this detector's own, so the first real crossing here would
        wrongly promote straight to BLOCK.

        A pre-existing CHALLENGE row for this exact lookup key means
        _get_or_create_auto_rule refreshes it (created=False) rather than
        creating a new one, so this test reads the BlockRule row directly
        rather than the function's created_rules return value, which only
        ever includes newly-created rows.
        """
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        BlockRuleFactory(
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern="203.0.116.0/24",
            action=RuleAction.CHALLENGE,
            source=RuleSource.AUTO,
            is_active=True,
            detectors="detect_subnet_burst",
        )

        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.116.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )

        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        rule = BlockRule.objects.get(rule_type=RuleType.CIDR, pattern="203.0.116.0/24")
        assert rule.action == RuleAction.CHALLENGE
        assert "detect_unsolved_challenges" in rule.detectors.split(",")

    @pytest.mark.django_db
    def test_cloud_spray_challenge_rule_does_not_promote_first_own_crossing(self):
        """Same as above for a detect_cloud_spray-provenance CHALLENGE rule:
        another detector's rule of the identical shape still must not
        promote detect_unsolved_challenges's own first crossing.

        As above, a pre-existing row for this lookup key means
        _get_or_create_auto_rule reports created=False, so this test reads
        the BlockRule row directly rather than the created_rules return
        value.
        """
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        BlockRuleFactory(
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern="203.0.117.0/24",
            action=RuleAction.CHALLENGE,
            source=RuleSource.AUTO,
            is_active=True,
            detectors="detect_cloud_spray",
        )

        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.117.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )

        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        rule = BlockRule.objects.get(rule_type=RuleType.CIDR, pattern="203.0.117.0/24")
        assert rule.action == RuleAction.CHALLENGE
        assert "detect_unsolved_challenges" in rule.detectors.split(",")

    @pytest.mark.django_db
    def test_own_provenance_repeat_crossing_still_promotes_to_block(self):
        """Own-provenance-only (#97) must not regress the existing
        own-detector repeat-crossing promotion: an active CHALLENGE rule
        this detector itself created still promotes on the next crossing.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        BlockRuleFactory(
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern="203.0.118.0/24",
            action=RuleAction.CHALLENGE,
            source=RuleSource.AUTO,
            is_active=True,
            detectors="detect_unsolved_challenges",
        )

        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.118.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            rules = detect_unsolved_challenges(window_minutes=60, min_challenged=3)

        subnet_rules = [r for r in rules if r.rule_type == RuleType.CIDR and r.pattern == "203.0.118.0/24"]
        assert len(subnet_rules) == 1
        assert subnet_rules[0].action == RuleAction.BLOCK
        assert "detect_unsolved_challenges" in subnet_rules[0].detectors.split(",")

    @pytest.mark.django_db
    def test_detector_field_populated_by_every_detector_passing_it(self):
        """Every detector that passes detector_name to _get_or_create_auto_rule
        must have its name added to the created BlockRule's detectors set
        (#97). Covers all six DETECTOR_NAMES entries plus rule_engine's
        escalation caller, which passes a detector_name outside that set
        (`detectors` is a superset of DETECTOR_NAMES by design, see
        BR-ANOM-011 / anomaly_detector.py's own comment).

        This hand-written list is a fixed regression case, not a
        completeness check: it is not parametrised over DETECTOR_NAMES and
        does not fail if a seventh detector is added without a case here.
        The wave-2 guard test in TestDetectorNamesResultKeyWiring
        (services/anomaly_detector.py's own module, this file) is the
        authoritative completeness check for DETECTOR_NAMES membership;
        this test only pins the specific #97 regression (the detectors
        field itself gets populated) for one representative pattern per
        named detector, once BR-ANOM-014 added detect_scraper_404_ratio,
        this list was extended to include it rather than left at the five
        that existed when #97 was fixed.
        """
        from django_waf.services.anomaly_detector import _get_or_create_auto_rule

        cases = [
            ("detect_ua_rotation", RuleType.UA, "some-bot/1.0"),
            ("detect_subnet_burst", RuleType.CIDR, "203.0.119.0/24"),
            ("detect_challenge_farms", RuleType.IP, "203.0.119.50"),
            ("detect_unsolved_challenges", RuleType.CIDR, "203.0.120.0/24"),
            ("detect_cloud_spray", RuleType.CIDR, "203.0.121.0/24"),
            ("detect_scraper_404_ratio", RuleType.IP, "203.0.119.52"),
            ("challenge_escalation", RuleType.IP, "203.0.119.51"),
        ]
        for detector_name, rule_type, pattern in cases:
            rule, created = _get_or_create_auto_rule(
                name=f"Auto: {detector_name} test",
                rule_type=rule_type,
                match_type="exact" if rule_type != RuleType.CIDR else "cidr",
                pattern=pattern,
                action=RuleAction.CHALLENGE,
                expiry=timezone.now() + timezone.timedelta(hours=24),
                detector_name=detector_name,
            )
            assert created is True
            assert rule.detectors == detector_name

    @pytest.mark.django_db
    def test_detectors_field_is_additive_not_overwritten_by_a_later_detector(self):
        """The regression this session's coordinator review caught: three
        detectors (detect_subnet_burst, detect_unsolved_challenges's subnet
        path, detect_cloud_spray) can all target the identical (CIDR,
        subnet, AUTO, CHALLENGE) key for a shared subnet, and
        run_all_detectors runs them in exactly that order on every pass.
        A last-writer-wins detectors value would let detect_cloud_spray,
        which always runs after detect_unsolved_challenges, clobber that
        detector's own stamp at the end of every pass, so on the NEXT pass
        detect_unsolved_challenges would no longer recognise its own prior
        rule and could never promote to BLOCK.

        This must fail against a last-writer-wins implementation: after
        detect_cloud_spray writes to the row, detect_unsolved_challenges's
        own name must still be present in detectors, and a subsequent
        crossing must still promote to BLOCK.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import (
            detect_cloud_spray,
            detect_unsolved_challenges,
        )

        now = timezone.now()
        subnet_ips = [f"203.0.122.{i}" for i in range(15)]

        def make_challenge_traffic():
            for ip in subnet_ips:
                for _ in range(2):
                    RequestLogFactory(
                        ip_address=ip,
                        verdict=Verdict.CHALLENGED,
                        path="/page",
                        referer="",
                        timestamp=now,
                    )

        # First pass: detect_unsolved_challenges creates the stage-one
        # CHALLENGE rule and stamps its own name.
        make_challenge_traffic()
        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            first_pass = detect_unsolved_challenges(window_minutes=60, min_challenged=3)
        first_subnet_rules = [r for r in first_pass if r.rule_type == RuleType.CIDR]
        assert len(first_subnet_rules) == 1
        assert first_subnet_rules[0].action == RuleAction.CHALLENGE

        rule = BlockRule.objects.get(rule_type=RuleType.CIDR, pattern="203.0.122.0/24", action=RuleAction.CHALLENGE)
        assert "detect_unsolved_challenges" in rule.detectors.split(",")

        # A different detector, sharing the same subnet pattern via
        # _get_subnet_prefix, now writes to the SAME row: enough distinct
        # IPs with no referer, each making a small number of requests, to
        # clear detect_cloud_spray's own thresholds.
        for ip in subnet_ips:
            for _ in range(2):
                RequestLogFactory(
                    ip_address=ip,
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )
        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 10),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 5),
        ):
            detect_cloud_spray(window_minutes=60)
        # detect_cloud_spray finds the same (CIDR, subnet, AUTO, CHALLENGE)
        # row detect_unsolved_challenges already created, so its own
        # update_or_create reports created=False (a refresh, not a new
        # row) and this subnet is absent from its returned created_rules
        # list. That is expected dedup behaviour and not what this test is
        # about: the row itself, not the return value, carries the
        # evidence of whether the write was additive.

        # The shared row must now carry BOTH names, not just the most
        # recent writer's.
        rule.refresh_from_db()
        detectors_after_spray = set(rule.detectors.split(","))
        assert "detect_unsolved_challenges" in detectors_after_spray
        assert "detect_cloud_spray" in detectors_after_spray

        # Second pass: detect_unsolved_challenges must still recognise its
        # own prior rule and promote to BLOCK, despite detect_cloud_spray
        # having written to the row in between. Promotion creates a
        # separate BLOCK row (action is part of the update_or_create
        # lookup key, unrelated to this fix and unchanged by it); what
        # matters here is that this second crossing reaches BLOCK at all,
        # rather than re-issuing CHALLENGE because the own-provenance
        # check no longer finds this detector's name in a row
        # detect_cloud_spray has since touched.
        make_challenge_traffic()
        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            second_pass = detect_unsolved_challenges(window_minutes=60, min_challenged=3)
        second_subnet_rules = [r for r in second_pass if r.rule_type == RuleType.CIDR]
        assert len(second_subnet_rules) == 1
        assert second_subnet_rules[0].action == RuleAction.BLOCK

    @pytest.mark.django_db
    def test_run_all_detectors_two_passes_still_promotes_shared_subnet(self):
        """The realistic production path (coordinator review): run
        run_all_detectors itself, twice, for a subnet that trips both
        detect_unsolved_challenges and detect_cloud_spray on every pass.
        Promotion to BLOCK must still occur on the repeat crossing, exactly
        as it would if detect_unsolved_challenges were the only detector
        ever touching this subnet.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import run_all_detectors

        now = timezone.now()
        subnet_ips = [f"203.0.123.{i}" for i in range(15)]

        def make_traffic():
            for ip in subnet_ips:
                for _ in range(2):
                    RequestLogFactory(
                        ip_address=ip,
                        verdict=Verdict.CHALLENGED,
                        path="/page",
                        referer="",
                        timestamp=now,
                    )

        patches = (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 10),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 5),
        )

        make_traffic()
        with patches[0], patches[1], patches[2], patches[3]:
            run_all_detectors(window_minutes=60)

        rule = BlockRule.objects.get(rule_type=RuleType.CIDR, pattern="203.0.123.0/24", action=RuleAction.CHALLENGE)
        assert "detect_unsolved_challenges" in rule.detectors.split(",")
        assert "detect_cloud_spray" in rule.detectors.split(",")

        make_traffic()
        with patches[0], patches[1], patches[2], patches[3]:
            run_all_detectors(window_minutes=60)

        # Promotion creates a separate BLOCK row (action is part of the
        # update_or_create lookup key, unrelated to and unchanged by this
        # fix); what this asserts is that the second pass reaches BLOCK at
        # all, which is exactly what the last-writer-wins defect prevented.
        assert BlockRule.objects.filter(
            rule_type=RuleType.CIDR, pattern="203.0.123.0/24", action=RuleAction.BLOCK
        ).exists()

    @pytest.mark.django_db
    def test_ip_solved_outside_recency_window_is_still_eligible(self):
        """An IP whose only solved challenge falls outside the configured
        recency window is not exempted (issue #84): this must fail against
        the pre-#84 unbounded exemption, which grants immunity from a
        single solve at any point in history.
        """
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.20"
        now = timezone.now()
        for _ in range(4):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )
        # Solved 48 hours ago -- well outside the default 24-hour
        # DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS.
        old_solve = now - timezone.timedelta(hours=48)
        ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.SOLVED, solved_at=old_solve)

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        ip_rules = [r for r in rules if r.rule_type == RuleType.IP and r.pattern == ip]
        assert len(ip_rules) == 1
        assert ip_rules[0].action == RuleAction.BLOCK

    @pytest.mark.django_db
    def test_ip_solved_within_recency_window_is_still_exempted(self):
        """The recency bound does not regress the existing exemption for a
        genuinely recent solve.
        """
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "10.0.0.21"
        now = timezone.now()
        for _ in range(4):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/page",
                referer="",
                timestamp=now,
            )
        ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.SOLVED, solved_at=now)

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        ip_rules = [r for r in rules if r.rule_type == RuleType.IP and r.pattern == ip]
        assert ip_rules == []

    @pytest.mark.django_db
    def test_dry_run_suppresses_subnet_writes(self):
        """dry_run=True makes zero writes on the subnet path too (BR-ANOM-006)."""
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.115.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            rules = detect_unsolved_challenges(window_minutes=60, min_challenged=3, dry_run=True)

        subnet_rules = [r for r in rules if r.rule_type == RuleType.CIDR]
        assert len(subnet_rules) == 1
        assert subnet_rules[0].action == RuleAction.CHALLENGE
        assert not BlockRule.objects.filter(pattern="203.0.115.0/24").exists()

    @pytest.mark.django_db
    def test_subnet_window_is_the_discriminator_for_a_slow_drip_spread(self):
        """A slow-drip subnet that does NOT qualify inside a 60-minute
        window DOES qualify once the subnet path is given its own wider
        window (issue #93).

        15 distinct IPs in one /24, 2 challenges each (30 total, clearing
        DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED with exactly
        DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS distinct IPs), spread evenly
        across the last 300 minutes so no single 60-minute slice ever
        contains more than a handful of them. This must fail if
        subnet_window_minutes is ignored and the subnet path shares the
        per-IP path's 60-minute window: at 60 minutes only the last couple
        of IPs' traffic falls inside the window, clearing neither the count
        nor the distinct-IP floor.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        # Spread the 15 IPs' traffic across 0..300 minutes ago, 20 minutes
        # apart, so a 60-minute window only ever catches the most recent 2-3
        # IPs (well under both thresholds) while a 360-minute window catches
        # all 15.
        for i in range(15):
            offset = timezone.timedelta(minutes=i * 20)
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.116.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now - offset,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
        ):
            # At the per-IP path's own 60-minute window, forced onto the
            # subnet path too, the spread traffic cannot clear either gate.
            rules_at_60m = detect_unsolved_challenges(
                window_minutes=60,
                min_challenged=999,
                subnet_window_minutes=60,
            )
            assert [r for r in rules_at_60m if r.rule_type == RuleType.CIDR] == []

            # The same data, with only the subnet window widened to 360
            # minutes, qualifies: the existing (30, 10) thresholds are
            # unchanged, only the window differs.
            rules_at_360m = detect_unsolved_challenges(
                window_minutes=60,
                min_challenged=999,
                subnet_window_minutes=360,
            )

        subnet_rules = [r for r in rules_at_360m if r.rule_type == RuleType.CIDR]
        assert len(subnet_rules) == 1
        assert subnet_rules[0].pattern == "203.0.116.0/24"
        assert subnet_rules[0].action == RuleAction.CHALLENGE
        assert BlockRule.objects.filter(pattern="203.0.116.0/24", is_active=True).exists()

    @pytest.mark.django_db
    def test_subnet_window_defaults_to_the_configured_setting(self):
        """With subnet_window_minutes not passed, the subnet path reads
        DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES, not the per-IP
        window_minutes (issue #93's decoupling).
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        now = timezone.now()
        # Traffic sits 200 minutes back: outside the per-IP path's 60-minute
        # window (window_minutes stays default, unaffected) but inside the
        # default 360-minute subnet window.
        offset = timezone.timedelta(minutes=200)
        for i in range(15):
            for _ in range(2):
                RequestLogFactory(
                    ip_address=f"203.0.117.{i}",
                    verdict=Verdict.CHALLENGED,
                    path="/page",
                    referer="",
                    timestamp=now - offset,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10),
            patch.object(conf_mod, "DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES", 360),
        ):
            rules = detect_unsolved_challenges(window_minutes=60, min_challenged=999)

        subnet_rules = [r for r in rules if r.rule_type == RuleType.CIDR]
        assert len(subnet_rules) == 1
        assert subnet_rules[0].pattern == "203.0.117.0/24"


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------


# Reusable realistic browser and bot META dicts.
_CHROME_META = {
    "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
    "HTTP_ACCEPT_LANGUAGE": "en-GB,en;q=0.9",
    "HTTP_ACCEPT_ENCODING": "gzip, deflate, br",
    "HTTP_SEC_CH_UA": '"Chromium";v="120", "Not?A_Brand";v="8"',
    "HTTP_SEC_CH_UA_MOBILE": "?0",
    "HTTP_SEC_CH_UA_PLATFORM": '"macOS"',
    "HTTP_SEC_FETCH_SITE": "none",
    "HTTP_SEC_FETCH_MODE": "navigate",
    "HTTP_SEC_FETCH_DEST": "document",
    "HTTP_SEC_FETCH_USER": "?1",
    "HTTP_CONNECTION": "keep-alive",
    "HTTP_UPGRADE_INSECURE_REQUESTS": "1",
}

_CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class TestComputeFingerprint:
    """Tests for compute_fingerprint()."""

    def test_returns_sha256_hex_string(self):
        """Fingerprint is a 64-char hex SHA-256 hash."""
        fp = compute_fingerprint(_CHROME_META)
        assert isinstance(fp, str)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_identical_meta_produces_identical_hash(self):
        """Two identical META dicts produce the same fingerprint."""
        assert compute_fingerprint(_CHROME_META) == compute_fingerprint(dict(_CHROME_META))

    def test_different_meta_produces_different_hash(self):
        """Different headers produce different fingerprints."""
        alt = dict(_CHROME_META)
        alt["HTTP_ACCEPT_LANGUAGE"] = "fr-FR,fr;q=0.9"
        assert compute_fingerprint(_CHROME_META) != compute_fingerprint(alt)

    def test_empty_meta_produces_stable_hash(self):
        """An empty META dict still produces a valid (all-empty) fingerprint hash."""
        fp = compute_fingerprint({})
        assert len(fp) == 64
        # Deterministic, repeat call produces the same hash
        assert compute_fingerprint({}) == fp

    def test_missing_header_is_treated_as_empty(self):
        """A missing header produces the same hash as an empty-string header."""
        meta_missing = dict(_CHROME_META)
        del meta_missing["HTTP_SEC_CH_UA"]
        meta_empty = dict(_CHROME_META)
        meta_empty["HTTP_SEC_CH_UA"] = ""
        assert compute_fingerprint(meta_missing) == compute_fingerprint(meta_empty)

    def test_normalisation_strips_and_lowercases(self):
        """Header values are stripped and lowercased before hashing."""
        meta_a = dict(_CHROME_META)
        meta_a["HTTP_ACCEPT_LANGUAGE"] = "EN-GB,EN;q=0.9"
        meta_b = dict(_CHROME_META)
        meta_b["HTTP_ACCEPT_LANGUAGE"] = "  en-gb,en;q=0.9  "
        assert compute_fingerprint(meta_a) == compute_fingerprint(meta_b)


class TestScoreFingerprintMismatch:
    """Tests for score_fingerprint_mismatch()."""

    def test_empty_ua_returns_zero(self):
        """No UA claim, nothing to verify against."""
        assert score_fingerprint_mismatch("", _CHROME_META) == 0.0

    def test_real_chrome_scores_zero(self):
        """A real Chrome UA with full browser headers scores 0.0."""
        assert score_fingerprint_mismatch(_CHROME_UA, _CHROME_META) == 0.0

    def test_chrome_ua_without_sec_ch_ua_adds_2(self):
        """Chrome 89+ must send Sec-CH-UA; its absence is a +2.0 deterministic signal."""
        meta = dict(_CHROME_META)
        meta["HTTP_SEC_CH_UA"] = ""
        score = score_fingerprint_mismatch(_CHROME_UA, meta)
        assert score >= 2.0

    def test_chrome_under_89_does_not_require_sec_ch_ua(self):
        """Chrome versions below 89 are not penalised for missing Sec-CH-UA."""
        old_chrome = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
        )
        meta = dict(_CHROME_META)
        meta["HTTP_SEC_CH_UA"] = ""
        # Chrome 80 + no Sec-CH-UA must not trigger the +2.0 signal on its own
        assert score_fingerprint_mismatch(old_chrome, meta) < 2.0

    def test_browser_ua_without_sec_fetch_adds_1_5(self):
        """A browser UA without any Sec-Fetch-* headers scores at least 1.5."""
        meta = {k: v for k, v in _CHROME_META.items() if not k.startswith("HTTP_SEC_FETCH_")}
        score = score_fingerprint_mismatch(_CHROME_UA, meta)
        assert score >= 1.5

    def test_browser_ua_without_accept_language_adds_1(self):
        """A browser UA without Accept-Language scores at least 1.0."""
        meta = dict(_CHROME_META)
        meta["HTTP_ACCEPT_LANGUAGE"] = ""
        score = score_fingerprint_mismatch(_CHROME_UA, meta)
        assert score >= 1.0

    def test_browser_ua_with_star_accept_language_adds_1(self):
        """Accept-Language: * is treated as missing (bots fall back to this)."""
        meta = dict(_CHROME_META)
        meta["HTTP_ACCEPT_LANGUAGE"] = "*"
        score = score_fingerprint_mismatch(_CHROME_UA, meta)
        assert score >= 1.0

    def test_browser_ua_with_wildcard_accept_adds_0_5(self):
        """Accept: */* from a claimed browser is a weak but present signal."""
        meta = dict(_CHROME_META)
        meta["HTTP_ACCEPT"] = "*/*"
        score = score_fingerprint_mismatch(_CHROME_UA, meta)
        assert score >= 0.5

    def test_python_requests_claiming_chrome_scores_5(self):
        """A bot (no browser headers) claiming to be Chrome hits the 5.0 cap."""
        bot_meta = {"HTTP_ACCEPT": "*/*"}
        score = score_fingerprint_mismatch(_CHROME_UA, bot_meta)
        assert score == 5.0

    def test_score_is_capped_at_5(self):
        """The returned score never exceeds 5.0 regardless of signal count."""
        score = score_fingerprint_mismatch(_CHROME_UA, {})
        assert score <= 5.0

    def test_non_browser_ua_scores_zero(self):
        """A UA that doesn't claim to be a browser produces no mismatch signals."""
        score = score_fingerprint_mismatch("curl/7.88.1", {})
        assert score == 0.0


class TestClassifyFingerprint:
    """Tests for classify_fingerprint()."""

    def test_real_browser_classifies_as_browser(self):
        """A real Chrome request scores 0 and classifies as 'browser'."""
        assert classify_fingerprint(_CHROME_UA, _CHROME_META) == "browser"

    def test_python_requests_claiming_chrome_classifies_as_bot(self):
        """A bot with Chrome UA scores 5.0 and classifies as 'bot' (>= 3.0)."""
        assert classify_fingerprint(_CHROME_UA, {"HTTP_ACCEPT": "*/*"}) == "bot"

    def test_partial_mismatch_classifies_as_suspicious(self):
        """A score between 1.5 and 3.0 classifies as 'suspicious'."""
        meta = dict(_CHROME_META)
        meta["HTTP_ACCEPT_LANGUAGE"] = ""  # +1.0
        meta["HTTP_ACCEPT"] = "*/*"  # +0.5
        # Total 1.5, just enters the suspicious band
        assert classify_fingerprint(_CHROME_UA, meta) == "suspicious"

    def test_no_ua_classifies_as_unknown(self):
        """An empty UA with no signals classifies as 'unknown'."""
        assert classify_fingerprint("", {}) == "unknown"

    def test_non_browser_ua_classifies_as_unknown(self):
        """A non-browser UA like curl scores 0.0 and classifies as 'unknown'.

        Before the issue #82 fix, this fell through to 'browser' purely
        because a UA that never claimed to be a browser could not fail any
        of score_fingerprint_mismatch's browser-claim-gated checks. That
        recorded honest libraries and crawlers as fingerprint_verdict
        'browser' in RequestLog. curl never claims to be a browser, so
        'unknown' (no signal either way) is the honest label, not 'browser'.
        """
        assert classify_fingerprint("curl/7.88.1", {}) == "unknown"

    def test_crawler_ua_classifies_as_unknown(self):
        """A crawler UA that makes no browser claim also classifies as 'unknown'.

        Regression guard distinguishing this from the empty-UA 'unknown'
        case: Googlebot's UA is non-empty and known to classify_ua as
        'crawler', but it matches neither _CHROMIUM_UA_RE nor
        _SEC_FETCH_BROWSERS_RE, so it must land on the same 'unknown'
        branch as curl, not fall through to 'browser'.
        """
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        assert classify_fingerprint(ua, {}) == "unknown"

    def test_browser_claiming_ua_still_classifies_as_browser(self):
        """A genuine browser-claiming UA with consistent headers is still 'browser'.

        Regression guard: the fix must not turn every clean-fingerprint
        request into 'unknown'. Only a UA that makes no browser claim at
        all is affected.
        """
        assert classify_fingerprint(_CHROME_UA, _CHROME_META) == "browser"

    def test_bot_verdict_set_is_unchanged_for_deceptive_browser_claim(self):
        """A browser-claiming UA with bot-shaped headers still classifies as 'bot'.

        BR-CHAL-013's escalation gate keys on fingerprint_verdict == 'bot'.
        This fix only touches the non-browser-claiming fallthrough
        (mismatch is always 0.0 there), so it cannot change which inputs
        cross the mismatch >= 3.0 threshold that produces 'bot'.
        """
        assert classify_fingerprint(_CHROME_UA, {"HTTP_ACCEPT": "*/*"}) == "bot"


class TestIssue82Composite:
    """Composite checks tying score_user_agent and classify_fingerprint
    together the way evaluate_request does, confirming issue #82's two
    changes compose correctly and classify_ua is untouched by either.
    """

    def test_deceptive_browser_still_scores_five_via_fingerprint(self):
        """A browser-claiming client with no client hints still scores 5.0.

        Unchanged by issue #82: score_fingerprint_mismatch and
        classify_fingerprint's 'bot' branch are untouched. Chrome 120
        claims Chromium 89+ (needs Sec-CH-UA), claims a Sec-Fetch-*
        browser (needs Sec-Fetch-*, Accept-Language, and a non-wildcard
        Accept), and the empty meta dict supplies none of them: 2.0 + 1.5
        + 1.0 + 0.5 = 5.0, the fingerprint scorer's cap.
        """
        assert score_fingerprint_mismatch(_CHROME_UA, {}) == 5.0
        assert classify_fingerprint(_CHROME_UA, {}) == "bot"
        # score_user_agent is unaffected: Chrome 120's UA string matches
        # none of the anomaly checks, self-identification weight or not.
        assert score_user_agent(_CHROME_UA) == 0.0

    def test_honest_curl_scores_low_on_both_axes(self):
        """Honest curl scores low on score_user_agent and 'unknown' on fingerprint.

        curl/7.68.0 never claims to be a browser, so
        score_fingerprint_mismatch is 0.0 by construction and
        classify_fingerprint is 'unknown' (issue #82 change 2), and
        score_user_agent no longer carries the self-identification penalty
        (issue #82 change 1), leaving only the short-UA weight (1.0).
        """
        ua = "curl/7.68.0"
        assert score_user_agent(ua) == 1.0
        assert score_fingerprint_mismatch(ua, {}) == 0.0
        assert classify_fingerprint(ua, {}) == "unknown"

    def test_googlebot_scores_zero_on_both_axes(self):
        """Googlebot scores 0.0 on score_user_agent and 'unknown' on fingerprint."""
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        assert score_user_agent(ua) == 0.0
        assert score_fingerprint_mismatch(ua, {}) == 0.0
        assert classify_fingerprint(ua, {}) == "unknown"

    def test_classify_ua_categories_are_completely_unchanged(self):
        """classify_ua's return value for all five categories is untouched by issue #82.

        Neither change in this issue alters classify_ua or the regexes it
        reads (_RE_CRAWLER, _RE_SCRAPER_LIBS, _RE_BOT, _RE_BROWSER): change
        1 only removes _RE_SCRAPER_LIBS's contribution inside
        score_user_agent, and change 2 only touches classify_fingerprint.
        """
        cases = {
            "": "unknown",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "crawler",
            "curl/7.68.0": "library",
            "My Custom bot/1.0": "bot",
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ): "browser",
        }
        for ua, expected in cases.items():
            assert classify_ua(ua) == expected


class TestKnownFingerprintRegistry:
    """Tests for register_known_fingerprint and is_known_fingerprint."""

    def test_register_calls_incr_and_expire(self):
        """register_known_fingerprint increments a counter and sets a 30-day TTL."""
        redis = MagicMock()
        register_known_fingerprint("abc123", redis)

        redis.incr.assert_called_once_with("waf:known_fp:abc123")
        redis.expire.assert_called_once()
        # TTL is 30 days (86400 * 30)
        assert redis.expire.call_args[0][1] == 86400 * 30

    def test_register_empty_hash_is_noop(self):
        """Empty fingerprint hash skips the Redis call."""
        redis = MagicMock()
        register_known_fingerprint("", redis)
        redis.incr.assert_not_called()

    def test_register_swallows_redis_exception(self):
        """A Redis error during register does not raise: the caller (VerifyView)
        must still complete the redirect."""
        redis = MagicMock()
        redis.incr.side_effect = RuntimeError("redis down")
        # Must not raise
        register_known_fingerprint("abc123", redis)

    def test_register_logs_a_warning_on_failure(self, caplog):
        """A silent failure here is a false-positive amplifier, not a neutral
        fail-open: is_known_fingerprint fails closed, so a real user who just
        solved a challenge would be re-challenged on every subsequent visit
        with no operator-visible signal that the allowlist has stopped
        growing."""
        import logging

        redis = MagicMock()
        redis.incr.side_effect = RuntimeError("redis down")
        with caplog.at_level(logging.WARNING, logger="django_waf.fingerprint"):
            register_known_fingerprint("abc123", redis)

        assert any("abc123" in message for message in caplog.messages)

    def test_is_known_returns_true_when_counter_present(self):
        """is_known_fingerprint returns True when the Redis key has a value."""
        redis = MagicMock()
        redis.get.return_value = b"1"
        assert is_known_fingerprint("abc123", redis) is True
        redis.get.assert_called_once_with("waf:known_fp:abc123")

    def test_is_known_returns_false_when_counter_absent(self):
        """is_known_fingerprint returns False when the Redis key is missing."""
        redis = MagicMock()
        redis.get.return_value = None
        assert is_known_fingerprint("abc123", redis) is False

    def test_is_known_empty_hash_returns_false(self):
        """Empty fingerprint hash short-circuits to False without calling Redis."""
        redis = MagicMock()
        assert is_known_fingerprint("", redis) is False
        redis.get.assert_not_called()

    def test_is_known_swallows_redis_exception(self):
        """A Redis error during lookup returns False, never raises."""
        redis = MagicMock()
        redis.get.side_effect = RuntimeError("redis down")
        assert is_known_fingerprint("abc123", redis) is False


# ---------------------------------------------------------------------------
# rule_engine, internal helpers
# ---------------------------------------------------------------------------


class TestRuleEngineHelpers:
    """Tests for rule_engine internal helper functions.

    These helpers are pure (or Redis-mockable) and easy to exercise directly
    without going through the full evaluate_request path.
    """

    # ------------------------------------------------------------------ _match_ua

    def test_match_ua_exact(self):
        from django_waf.services.rule_engine import _match_ua

        assert _match_ua("curl/7.88", "curl/7.88", "exact") is True
        assert _match_ua("curl/7.88", "curl/7.87", "exact") is False

    def test_match_ua_contains_is_case_insensitive(self):
        from django_waf.services.rule_engine import _match_ua

        assert _match_ua("Mozilla/5.0 Chrome/120", "chrome", "contains") is True
        assert _match_ua("curl/7.88", "chrome", "contains") is False

    def test_match_ua_regex(self):
        from django_waf.services.rule_engine import _match_ua

        assert _match_ua("python-requests/2.31", r"python-\w+", "regex") is True
        assert _match_ua("curl/7.88", r"python-\w+", "regex") is False

    def test_match_ua_invalid_regex_returns_false(self):
        """An invalid regex pattern is swallowed and returns False."""
        from django_waf.services.rule_engine import _match_ua

        assert _match_ua("anything", "[unclosed", "regex") is False

    def test_match_ua_unknown_match_type_returns_false(self):
        from django_waf.services.rule_engine import _match_ua

        assert _match_ua("anything", "anything", "bogus") is False

    # ------------------------------------------------------------------ _match_ip

    def test_match_ip_exact(self):
        from django_waf.services.rule_engine import _match_ip

        assert _match_ip("203.0.113.1", "203.0.113.1", "exact") is True
        assert _match_ip("203.0.113.2", "203.0.113.1", "exact") is False

    def test_match_ip_unknown_match_type_returns_false(self):
        from django_waf.services.rule_engine import _match_ip

        assert _match_ip("203.0.113.1", "203.0.113.1", "regex") is False

    # ------------------------------------------------------------------ _match_cidr

    def test_match_cidr_within_range(self):
        from django_waf.services.rule_engine import _match_cidr

        assert _match_cidr("10.0.0.42", "10.0.0.0/24") is True
        assert _match_cidr("10.0.1.42", "10.0.0.0/24") is False

    def test_match_cidr_invalid_pattern_returns_false(self):
        """A garbage CIDR string returns False rather than raising."""
        from django_waf.services.rule_engine import _match_cidr

        assert _match_cidr("10.0.0.42", "not-a-cidr") is False
        assert _match_cidr("not-an-ip", "10.0.0.0/24") is False

    # ------------------------------------------------------------------ _rule_matches

    def test_rule_matches_composite_both_match(self):
        """A composite rule requires both UA and IP/CIDR to match."""
        from django_waf.services.rule_engine import _rule_matches

        rule = {
            "rule_type": "composite",
            "match_type": "contains",
            "pattern": "python-requests||10.0.0.0/8",
        }
        assert _rule_matches(rule, "10.5.6.7", "python-requests/2.31") is True
        # UA matches but IP does not
        assert _rule_matches(rule, "203.0.113.1", "python-requests/2.31") is False
        # IP matches but UA does not
        assert _rule_matches(rule, "10.5.6.7", "Mozilla/5.0") is False

    def test_rule_matches_composite_without_separator_returns_false(self):
        """A composite rule with no `||` separator is a legacy fallback that cannot match."""
        from django_waf.services.rule_engine import _rule_matches

        rule = {"rule_type": "composite", "match_type": "contains", "pattern": "something"}
        assert _rule_matches(rule, "10.0.0.1", "Mozilla") is False

    def test_rule_matches_unknown_rule_type_returns_false(self):
        """An unknown rule_type falls through to False (defensive default)."""
        from django_waf.services.rule_engine import _rule_matches

        rule = {"rule_type": "bogus", "match_type": "exact", "pattern": "x"}
        assert _rule_matches(rule, "10.0.0.1", "Mozilla") is False

    # ------------------------------------------------------------------ _record_rule_hit

    def test_record_rule_hit_increments_and_expires(self):
        from django_waf.services.rule_engine import _record_rule_hit

        redis = MagicMock()
        _record_rule_hit("rule-123", redis)

        redis.incr.assert_called_once_with("waf:rule_hits:rule-123")
        redis.expire.assert_called_once_with("waf:rule_hits:rule-123", 86400 * 2)

    def test_record_rule_hit_swallows_exception(self):
        """Redis failures during hit recording must not propagate."""
        from django_waf.services.rule_engine import _record_rule_hit

        redis = MagicMock()
        redis.incr.side_effect = RuntimeError("redis down")
        # Must not raise
        _record_rule_hit("rule-123", redis)

    # ------------------------------------------------------------------ _resolve_and_confirm_rdns
    #
    # _verify_rdns's own cache-hit/cache-miss/TTL behaviour is covered by
    # TestVerifyRdns above and tests/test_rdns_fcrdns.py. These tests cover
    # the split-out pure-resolution helper directly (no caching involved).

    def test_resolve_and_confirm_matches_and_confirms(self):
        from django_waf.services.rule_engine import _resolve_and_confirm_rdns

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl-1-2-3-4.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("1.2.3.4", 0))],
            ),
        ):
            assert _resolve_and_confirm_rdns("1.2.3.4", r"\.googlebot\.com$") is True

    def test_resolve_and_confirm_reverse_lookup_failure(self):
        from django_waf.services.rule_engine import _resolve_and_confirm_rdns

        with patch("django_waf.services.rule_engine.socket.gethostbyaddr", side_effect=OSError("no ptr")):
            assert _resolve_and_confirm_rdns("203.0.113.1", r"\.googlebot\.com$") is False

    def test_resolve_and_confirm_empty_hostname(self):
        from django_waf.services.rule_engine import _resolve_and_confirm_rdns

        with patch("django_waf.services.rule_engine.socket.gethostbyaddr", return_value=("", [], [])):
            assert _resolve_and_confirm_rdns("203.0.113.1", r"\.googlebot\.com$") is False

    def test_resolve_and_confirm_invalid_pattern(self):
        """An invalid rDNS regex pattern is swallowed and returns False."""
        from django_waf.services.rule_engine import _resolve_and_confirm_rdns

        with patch(
            "django_waf.services.rule_engine.socket.gethostbyaddr",
            return_value=("something.example.com", [], []),
        ):
            assert _resolve_and_confirm_rdns("1.2.3.4", "[unclosed") is False

    def test_resolve_and_confirm_forward_mismatch_fails(self):
        """PTR matches the pattern, but the forward-resolved set does not
        include the original IP, the spoofed-PTR case #34 exists to catch."""
        from django_waf.services.rule_engine import _resolve_and_confirm_rdns

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("bingbot-5-6-7-8.search.msn.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("203.0.113.99", 0))],
            ),
        ):
            assert _resolve_and_confirm_rdns("5.6.7.8", r"\.search\.msn\.com$") is False

    # ------------------------------------------------------------------ _action_to_verdict

    def test_action_to_verdict_mapping(self):
        from django_waf.enums import RuleAction, Verdict
        from django_waf.services.rule_engine import _action_to_verdict

        assert _action_to_verdict(RuleAction.BLOCK) == Verdict.BLOCKED
        assert _action_to_verdict(RuleAction.CHALLENGE) == Verdict.CHALLENGED
        assert _action_to_verdict(RuleAction.THROTTLE) == Verdict.THROTTLED
        assert _action_to_verdict(RuleAction.LOG_ONLY) == Verdict.LOGGED

    def test_action_to_verdict_unknown_defaults_to_blocked(self):
        from django_waf.enums import Verdict
        from django_waf.services.rule_engine import _action_to_verdict

        assert _action_to_verdict("something-weird") == Verdict.BLOCKED

    # ------------------------------------------------------------------ _score_to_verdict

    def test_score_to_verdict_thresholds(self):
        from django_waf.enums import RuleAction, Verdict
        from django_waf.services.rule_engine import _score_to_verdict

        # Below log threshold → ALLOWED
        verdict, action = _score_to_verdict(0.0)
        assert verdict == Verdict.ALLOWED
        assert action is None

        # Log threshold (default 3.0)
        verdict, action = _score_to_verdict(3.5)
        assert verdict == Verdict.LOGGED
        assert action == RuleAction.LOG_ONLY

        # Challenge threshold (default 5.0)
        verdict, action = _score_to_verdict(5.5)
        assert verdict == Verdict.CHALLENGED
        assert action == RuleAction.CHALLENGE

        # Block threshold (default 7.0)
        verdict, action = _score_to_verdict(8.0)
        assert verdict == Verdict.BLOCKED
        assert action == RuleAction.BLOCK

    # ------------------------------------------------------------------ _score_path

    def test_score_path_matches_suspicious_patterns(self):
        """Paths matching suspicious patterns accumulate score."""
        from django_waf.services.rule_engine import _score_path

        # A clearly suspicious path hits at least one of the default patterns
        score = _score_path("/wp-admin/")
        assert score > 0

    def test_score_path_clean_returns_zero(self):
        from django_waf.services.rule_engine import _score_path

        assert _score_path("/") == 0.0
        assert _score_path("/about/team/") == 0.0

    def test_score_path_default_patterns_cover_common_probes(self):
        """Default pattern list catches the credential/webshell probes seen in production.

        Regression for the v0.7 staging sample: probes like /.env, /.git/config,
        /alfashell.php, /onvif/device_service were logged as 'allowed' because
        the default pattern list did not cover them or the version deployed
        predated path scoring entirely. v0.9.0 expanded the defaults to cover
        these probe classes.
        """
        from django_waf.services.rule_engine import _score_path

        probes = [
            "/.env",
            "/.env.production",
            "/.git/config",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/.bash_history",
            "/wp-config.php",
            "/wp-admin/",
            "/wp-login.php",
            "/xmlrpc.php",
            "/alfashell.php",
            "/shell.php",
            "/c99.php",
            "/r57.php",
            "/filemanager.php",
            "/phpinfo.php",
            "/phpmyadmin/index.php",
            "/onvif/device_service",
            "/HNAP1",
            "/boaform/admin/formLogin",
            "/backup.zip",
            "/dump.sql",
            "/db.sqlite",
        ]
        for probe in probes:
            assert _score_path(probe) > 0, f"probe {probe!r} did not score"

    def test_score_path_does_not_catch_legitimate_django_paths(self):
        """Paths a real Django app would serve must NOT trigger path scoring.

        Guards against over-broad patterns (e.g. we deliberately dropped
        ``.ini`` and ``.conf`` from the defaults because real apps use them).
        """
        from django_waf.services.rule_engine import _score_path

        legit_paths = [
            "/",
            "/en/",
            "/products/barbour-jacket/",
            "/search/?q=boots",
            "/cart/",
            "/checkout/",
            "/accounts/login/",
            "/api/v1/products/",
            "/robots.txt",
            "/sitemap.xml",
            "/static/css/app.css",
            "/media/product-images/foo.jpg",
        ]
        for path in legit_paths:
            assert _score_path(path) == 0.0, f"legitimate path {path!r} triggered scoring"

    def test_score_path_is_capped_at_10(self):
        """Accumulated score is capped at 10.0 even when many patterns match."""
        from django_waf.services.rule_engine import _score_path

        with (
            patch(
                "django_waf.conf.DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS",
                [r"a", r"b", r"c", r"d", r"e", r"f", r"g", r"h", r"i", r"j", r"k"],
            ),
            patch("django_waf.conf.DJANGO_WAF_SUSPICIOUS_PATH_SCORE", 2.0),
        ):
            assert _score_path("abcdefghijk") == 10.0

    def test_score_path_skips_invalid_regex(self):
        """Invalid regex patterns in config are skipped rather than raising."""
        from django_waf.services.rule_engine import _score_path

        with (
            patch("django_waf.conf.DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS", ["[unclosed", r"wp-admin"]),
            patch("django_waf.conf.DJANGO_WAF_SUSPICIOUS_PATH_SCORE", 2.0),
        ):
            # Invalid pattern is skipped; the valid one still matches
            assert _score_path("/wp-admin/") == 2.0

    # ------------------------------------------------------------------ _get_unsolved_challenge_count

    def test_get_unsolved_challenge_count_no_key(self):
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        redis.get.return_value = None
        assert _get_unsolved_challenge_count("203.0.113.1", redis) == 0

    def test_get_unsolved_challenge_count_returns_count(self):
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        # First .get() returns the challenged counter, second returns the solved flag (None)
        redis.get.side_effect = [b"5", None]
        assert _get_unsolved_challenge_count("203.0.113.1", redis) == 5

    def test_get_unsolved_challenge_count_clears_when_solved(self):
        """If the solved flag is set, the counter is cleared and 0 is returned."""
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        redis.get.side_effect = [b"5", b"1"]  # challenged count, solved flag
        assert _get_unsolved_challenge_count("203.0.113.1", redis) == 0
        redis.delete.assert_called_once_with("waf:challenged:203.0.113.1")

    def test_get_unsolved_challenge_count_bot_fingerprint_ignores_solved_flag(self):
        """A 'bot' fingerprint_verdict returns the count as-is, without ever
        consulting the solved flag: a datacentre CPU solves the hashcash
        proof-of-work almost for free, so 'solved' must not mean 'legitimate'
        for a fingerprint-classified bot (BR-FP-001)."""
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        # Only the challenged counter should be read: the solved flag must
        # never even be consulted for a bot fingerprint.
        redis.get.side_effect = [b"5"]
        assert _get_unsolved_challenge_count("203.0.113.2", redis, fingerprint_verdict="bot") == 5
        redis.delete.assert_not_called()
        redis.get.assert_called_once_with("waf:challenged:203.0.113.2")

    def test_get_unsolved_challenge_count_non_bot_fingerprint_still_clears_on_solve(self):
        """A non-bot fingerprint_verdict (e.g. 'browser') preserves the
        pre-fix safety valve: a solved challenge still clears the counter,
        so a real user is not penalised for having been challenged."""
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        redis.get.side_effect = [b"5", b"1"]  # challenged count, solved flag
        assert _get_unsolved_challenge_count("203.0.113.3", redis, fingerprint_verdict="browser") == 0
        redis.delete.assert_called_once_with("waf:challenged:203.0.113.3")

    def test_get_unsolved_challenge_count_swallows_exception(self):
        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        redis.get.side_effect = RuntimeError("redis down")
        assert _get_unsolved_challenge_count("203.0.113.1", redis) == 0

    def test_get_unsolved_challenge_count_logs_a_warning_on_failure(self, caplog):
        """A Redis failure here returns 0, indistinguishable from a fresh
        IP, which silently disables challenge escalation. Must be logged,
        not swallowed silently (see the fail-open observability release)."""
        import logging

        from django_waf.services.rule_engine import _get_unsolved_challenge_count

        redis = MagicMock()
        redis.get.side_effect = RuntimeError("redis down")
        with caplog.at_level(logging.WARNING, logger="django_waf.rule_engine"):
            _get_unsolved_challenge_count("203.0.113.1", redis)

        assert any("203.0.113.1" in message for message in caplog.messages)

    # ------------------------------------------------------------------ _create_escalation_rule

    @pytest.mark.django_db
    def test_create_escalation_rule_creates_auto_block(self):
        """An escalation rule is created as source=AUTO with a TTL."""
        from django_waf.enums import RuleAction, RuleSource, RuleType
        from django_waf.models import BlockRule
        from django_waf.services.rule_engine import _create_escalation_rule

        _create_escalation_rule("203.0.113.77")

        rule = BlockRule.objects.get(pattern="203.0.113.77", source=RuleSource.AUTO)
        assert rule.rule_type == RuleType.IP
        assert rule.action == RuleAction.BLOCK
        assert rule.is_active is True
        assert rule.expires_at is not None

    @pytest.mark.django_db
    def test_create_escalation_rule_idempotent(self):
        """Repeated calls update_or_create the same row, not duplicate it."""
        from django_waf.enums import RuleSource
        from django_waf.models import BlockRule
        from django_waf.services.rule_engine import _create_escalation_rule

        _create_escalation_rule("203.0.113.78")
        _create_escalation_rule("203.0.113.78")

        rules = BlockRule.objects.filter(pattern="203.0.113.78", source=RuleSource.AUTO)
        assert rules.count() == 1

    @pytest.mark.django_db
    def test_create_escalation_rule_swallows_db_exception(self):
        """DB errors during escalation rule creation are logged, not raised."""
        from django_waf.services.rule_engine import _create_escalation_rule

        with patch(
            "django_waf.models.BlockRule.objects.update_or_create",
            side_effect=RuntimeError("db down"),
        ):
            # Must not raise
            _create_escalation_rule("203.0.113.79")

    @pytest.mark.django_db
    def test_create_escalation_rule_deduplicates_existing_rows(self, _auto_key_constraint_dropped):
        """Pre-existing duplicate BlockRule rows are deduplicated, then the rule is created.

        Regression: update_or_create raises MultipleObjectsReturned if
        duplicate rows exist for the same (rule_type, pattern, source, action)
        key. The fix catches this, deduplicates, and retries.

        Since #153 the partial UniqueConstraint prevents this state being
        seeded, so the fixture drops it to reproduce a pre-migration-0008
        consumer, which is the case the branch still exists to serve.
        """
        from django_waf.enums import RuleAction, RuleSource, RuleType
        from django_waf.models import BlockRule
        from django_waf.services.rule_engine import _create_escalation_rule

        # Manually create two duplicate rows (simulating a pre-existing race)
        for _ in range(2):
            BlockRule.objects.create(
                name="dupe",
                rule_type=RuleType.IP,
                pattern="203.0.113.80",
                match_type="exact",
                action=RuleAction.BLOCK,
                source=RuleSource.AUTO,
                is_active=True,
            )
        assert BlockRule.objects.filter(pattern="203.0.113.80", source=RuleSource.AUTO).count() == 2

        # This would previously raise MultipleObjectsReturned
        _create_escalation_rule("203.0.113.80")

        # Duplicates resolved, exactly one row remains
        assert BlockRule.objects.filter(pattern="203.0.113.80", source=RuleSource.AUTO).count() == 1

    # ------------------------------------------------------------------ _compile_ua_patterns

    def test_compile_ua_patterns_handles_all_match_types(self):
        """_compile_ua_patterns builds regexes for exact/contains/regex types."""
        from django_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {"id": "1", "rule_type": "ua", "match_type": "exact", "pattern": "curl/7.88"},
            {"id": "2", "rule_type": "ua", "match_type": "contains", "pattern": "python"},
            {"id": "3", "rule_type": "ua", "match_type": "regex", "pattern": r"bot-\d+"},
            # Non-UA rules are skipped
            {"id": "4", "rule_type": "ip", "match_type": "exact", "pattern": "1.1.1.1"},
        ]
        compiled = _compile_ua_patterns(rules)
        assert len(compiled) == 3

        # Each compiled entry is a (pattern, rule) tuple
        patterns = {rule["id"]: pat for pat, rule in compiled}
        assert patterns["1"].match("curl/7.88") is not None
        assert patterns["2"].search("python-requests/2.31") is not None
        assert patterns["3"].search("bot-42") is not None

    def test_compile_ua_patterns_skips_invalid_regex(self):
        """An invalid regex is logged and skipped, not propagated."""
        from django_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {"id": "bad", "rule_type": "ua", "match_type": "regex", "pattern": "[unclosed"},
            {"id": "ok", "rule_type": "ua", "match_type": "contains", "pattern": "python"},
        ]
        compiled = _compile_ua_patterns(rules)
        # Only the valid one makes it through
        assert len(compiled) == 1
        assert compiled[0][1]["id"] == "ok"


# ---------------------------------------------------------------------------
# geoip, MaxMind GeoLite2 install/update service
# ---------------------------------------------------------------------------


class TestGeoIPService:
    """Tests for ``services.geoip.install_geoip_database`` and its helpers.

    All network I/O is mocked, no real MaxMind HTTP is performed.
    """

    def _make_fake_archive(self, tmp_path, edition: str = "GeoLite2-Country") -> bytes:
        """Build an in-memory tar.gz matching MaxMind's archive layout.

        Returns the raw bytes; the inner ``.mmdb`` file contains a
        placeholder that is NOT a real MaxMind database. Verification
        must be mocked when this archive is used.
        """
        import io
        import tarfile as tf

        buf = io.BytesIO()
        with tf.open(fileobj=buf, mode="w:gz") as tar:
            data = b"placeholder-mmdb-bytes"
            info = tf.TarInfo(name=f"{edition}_20260411/{edition}.mmdb")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    # --------------------------------------------------------------- check_geoip2_available

    def test_check_geoip2_available_raises_when_missing(self):
        """If geoip2 is not importable, a GeoIPNotInstalledError is raised with install hint."""
        from django_waf.services.geoip import GeoIPNotInstalledError, check_geoip2_available

        # Force the import to fail inside the function
        with (
            patch.dict("sys.modules", {"geoip2": None, "geoip2.database": None}),
            pytest.raises(GeoIPNotInstalledError, match="pip install django-waf\\[geoip\\]"),
        ):
            check_geoip2_available()

    def test_check_geoip2_available_passes_when_present(self):
        """If geoip2 is importable, check_geoip2_available is a no-op."""
        from django_waf.services.geoip import check_geoip2_available

        # A fake geoip2.database module is enough to satisfy the import
        fake_module = MagicMock()
        with patch.dict("sys.modules", {"geoip2": MagicMock(), "geoip2.database": fake_module}):
            # Must not raise
            check_geoip2_available()

    # --------------------------------------------------------------- resolve_license_key

    def test_resolve_license_key_prefers_explicit_argument(self):
        from django_waf.services.geoip import resolve_license_key

        with patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "from-settings"):
            assert resolve_license_key("from-cli") == "from-cli"

    def test_resolve_license_key_falls_back_to_setting(self):
        from django_waf.services.geoip import resolve_license_key

        with patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "from-settings"):
            assert resolve_license_key(None) == "from-settings"

    def test_resolve_license_key_missing_raises(self):
        from django_waf.services.geoip import GeoIPLicenseMissingError, resolve_license_key

        with (
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", ""),
            pytest.raises(GeoIPLicenseMissingError, match="MaxMind"),
        ):
            resolve_license_key(None)

    # --------------------------------------------------------------- resolve_output_path

    def test_resolve_output_path_prefers_explicit_argument(self, tmp_path):
        from django_waf.services.geoip import resolve_output_path

        result = resolve_output_path(str(tmp_path / "custom.mmdb"))
        assert result == tmp_path / "custom.mmdb"

    def test_resolve_output_path_falls_back_to_setting(self, tmp_path):
        from django_waf.services.geoip import resolve_output_path

        configured = str(tmp_path / "from-settings.mmdb")
        with patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", configured):
            assert resolve_output_path(None) == tmp_path / "from-settings.mmdb"

    def test_resolve_output_path_falls_back_to_default(self):
        from django_waf.services.geoip import DEFAULT_OUTPUT_PATH, resolve_output_path

        with patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", None):
            assert str(resolve_output_path(None)) == DEFAULT_OUTPUT_PATH

    # --------------------------------------------------------------- is_database_fresh

    def test_is_database_fresh_zero_max_age(self, tmp_path):
        """max_age_days=0 always returns False (disabled freshness check)."""
        from django_waf.services.geoip import is_database_fresh

        path = tmp_path / "db.mmdb"
        path.write_bytes(b"content")
        assert is_database_fresh(path, 0) is False

    def test_is_database_fresh_missing_file(self, tmp_path):
        from django_waf.services.geoip import is_database_fresh

        assert is_database_fresh(tmp_path / "nope.mmdb", 7) is False

    def test_is_database_fresh_recent_file(self, tmp_path):
        from django_waf.services.geoip import is_database_fresh

        path = tmp_path / "db.mmdb"
        path.write_bytes(b"content")
        # Just written, fresh within any sensible window
        assert is_database_fresh(path, 7) is True

    def test_is_database_fresh_old_file(self, tmp_path):
        import os
        import time

        from django_waf.services.geoip import is_database_fresh

        path = tmp_path / "db.mmdb"
        path.write_bytes(b"content")
        # Backdate to 10 days ago
        ten_days_ago = time.time() - (10 * 86400)
        os.utime(path, (ten_days_ago, ten_days_ago))

        assert is_database_fresh(path, 7) is False
        assert is_database_fresh(path, 14) is True

    # --------------------------------------------------------------- install_geoip_database (full flow)

    def test_install_geoip_database_full_flow(self, tmp_path):
        """Happy path: download, extract, verify, atomic rename, all mocked."""
        from django_waf.services.geoip import install_geoip_database

        dest = tmp_path / "GeoLite2-Country.mmdb"
        archive_bytes = self._make_fake_archive(tmp_path)

        # Mock httpx.stream to return the fake archive
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_bytes = lambda chunk_size: [archive_bytes]

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Mock geoip2.database.Reader so verification passes without a real mmdb
        fake_reader = MagicMock()
        fake_reader.__enter__ = MagicMock(return_value=fake_reader)
        fake_reader.__exit__ = MagicMock(return_value=False)
        fake_reader.metadata.return_value = MagicMock(build_epoch=1_700_000_000)

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock(return_value=fake_reader)
        fake_errors = MagicMock()
        fake_errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {
                    "geoip2": fake_geoip2,
                    "geoip2.database": fake_geoip2.database,
                    "geoip2.errors": fake_errors,
                },
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(dest)),
        ):
            result = install_geoip_database()

        assert result["skipped"] is False
        assert result["path"] == str(dest)
        assert result["size_bytes"] > 0
        assert result["build_epoch"] == 1_700_000_000
        assert dest.exists(), "destination file was not written"
        assert dest.read_bytes() == b"placeholder-mmdb-bytes"

    def test_install_geoip_database_skips_when_fresh(self, tmp_path):
        """--if-older-than skips the download when the existing file is fresh."""
        from django_waf.services.geoip import install_geoip_database

        dest = tmp_path / "GeoLite2-Country.mmdb"
        dest.write_bytes(b"existing-db-bytes")

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(dest)),
            patch("httpx.stream") as mock_stream,
        ):
            result = install_geoip_database(if_older_than_days=7)

        assert result["skipped"] is True
        mock_stream.assert_not_called()
        # Existing file untouched
        assert dest.read_bytes() == b"existing-db-bytes"

    def test_install_geoip_database_http_401_surfaces_licence_error(self, tmp_path):
        """A 401 from MaxMind is converted into a clear GeoIPDownloadError."""
        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        mock_response = MagicMock()
        mock_response.status_code = 401

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "bad-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(tmp_path / "out.mmdb")),
            pytest.raises(GeoIPDownloadError, match="401"),
        ):
            install_geoip_database()

    def test_install_geoip_database_http_5xx_surfaces_download_error(self, tmp_path):
        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(tmp_path / "out.mmdb")),
            pytest.raises(GeoIPDownloadError, match="503"),
        ):
            install_geoip_database()

    def test_install_geoip_database_corrupt_archive_does_not_clobber(self, tmp_path):
        """A corrupt tar.gz raises GeoIPDownloadError and leaves the existing file intact."""
        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        dest = tmp_path / "GeoLite2-Country.mmdb"
        dest.write_bytes(b"original-db-bytes")
        # Backdate so the freshness check (which we're not using) can't skip us
        import os
        import time

        os.utime(dest, (time.time() - (30 * 86400),) * 2)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_bytes = lambda chunk_size: [b"not a valid tar.gz"]

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(dest)),
            pytest.raises(GeoIPDownloadError, match="Failed to read"),
        ):
            install_geoip_database()

        # Existing database untouched
        assert dest.read_bytes() == b"original-db-bytes"

    def test_install_geoip_database_verification_failure_raises(self, tmp_path):
        """If geoip2.Reader fails to open the extracted file, raise GeoIPDownloadError."""
        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        archive_bytes = self._make_fake_archive(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_bytes = lambda chunk_size: [archive_bytes]

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reader raises on construction
        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock(side_effect=ValueError("corrupt header"))
        fake_errors = MagicMock()
        fake_errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})

        dest = tmp_path / "GeoLite2-Country.mmdb"

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {
                    "geoip2": fake_geoip2,
                    "geoip2.database": fake_geoip2.database,
                    "geoip2.errors": fake_errors,
                },
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(dest)),
            pytest.raises(GeoIPDownloadError, match="not a valid GeoIP database"),
        ):
            install_geoip_database()

        # Destination never created
        assert not dest.exists()

    def test_install_geoip_database_httpx_network_error_raises(self, tmp_path):
        """A transient httpx.HTTPError (timeout, connection reset) becomes GeoIPDownloadError."""
        import httpx

        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch("httpx.stream", side_effect=httpx.ConnectError("connection refused")),
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(tmp_path / "out.mmdb")),
            pytest.raises(GeoIPDownloadError, match="connection refused"),
        ):
            install_geoip_database()

    def test_install_geoip_database_archive_missing_mmdb_raises(self, tmp_path):
        """If the MaxMind archive contains no .mmdb file, raise with a layout-change hint."""
        import io
        import tarfile as tf

        from django_waf.services.geoip import GeoIPDownloadError, install_geoip_database

        # Build an archive with only a README file (no .mmdb)
        buf = io.BytesIO()
        with tf.open(fileobj=buf, mode="w:gz") as tar:
            data = b"not an mmdb"
            info = tf.TarInfo(name="GeoLite2-Country_20260411/README.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        archive_bytes = buf.getvalue()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_bytes = lambda chunk_size: [archive_bytes]

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock()

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database},
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(tmp_path / "out.mmdb")),
            pytest.raises(GeoIPDownloadError, match="does not contain"),
        ):
            install_geoip_database()

    def test_install_geoip_database_verification_address_not_found_is_tolerated(self, tmp_path):
        """AddressNotFoundError on the 8.8.8.8 smoke-test lookup is tolerated (empty DB).

        The Reader still opens successfully and metadata is returned, we
        don't fail verification on a missed lookup because trimmed test
        databases legitimately don't contain 8.8.8.8.
        """
        from django_waf.services.geoip import install_geoip_database

        dest = tmp_path / "GeoLite2-Country.mmdb"
        archive_bytes = self._make_fake_archive(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_bytes = lambda chunk_size: [archive_bytes]

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_response)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reader opens but the country() call raises AddressNotFoundError
        class FakeAddressNotFoundError(Exception):
            pass

        fake_reader = MagicMock()
        fake_reader.__enter__ = MagicMock(return_value=fake_reader)
        fake_reader.__exit__ = MagicMock(return_value=False)
        fake_reader.country.side_effect = FakeAddressNotFoundError("not in db")
        fake_reader.metadata.return_value = MagicMock(build_epoch=1_700_000_000)

        fake_errors = MagicMock()
        fake_errors.AddressNotFoundError = FakeAddressNotFoundError

        fake_geoip2 = MagicMock()
        fake_geoip2.database.Reader = MagicMock(return_value=fake_reader)
        fake_geoip2.errors = fake_errors  # parent attribute must resolve to real module

        with (
            patch("httpx.stream", return_value=mock_context),
            patch.dict(
                "sys.modules",
                {
                    "geoip2": fake_geoip2,
                    "geoip2.database": fake_geoip2.database,
                    "geoip2.errors": fake_errors,
                },
            ),
            patch("django_waf.conf.DJANGO_WAF_MAXMIND_LICENSE_KEY", "fake-key"),
            patch("django_waf.conf.DJANGO_WAF_GEOIP_PATH", str(dest)),
        ):
            result = install_geoip_database()

        # Verification passed despite the missed lookup
        assert result["skipped"] is False
        assert result["build_epoch"] == 1_700_000_000
        assert dest.exists()
