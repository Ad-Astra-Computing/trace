"""discover_cli smoke tests. The list-builder is covered by
test_discovery; this exercises argv parsing, exit-code mapping,
and stdout formatting."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest

from agents.scout import discover_cli
from agents.scout.feed_client import FeedRateLimit, FeedTransientError


def test_lookback_hours_default_24(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_cli, "list_recent_cves", return_value=["CVE-2026-1"]) as mock_list:
        rc = discover_cli.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "CVE-2026-1"
    kwargs = mock_list.call_args.kwargs
    diff = kwargs["until"] - kwargs["since"]
    assert 23 < diff.total_seconds() / 3600 < 25


def test_explicit_since_until_window() -> None:
    with patch.object(discover_cli, "list_recent_cves", return_value=[]) as mock_list:
        rc = discover_cli.main([
            "--since", "2026-04-28T00:00:00Z",
            "--until", "2026-04-29T00:00:00Z",
        ])
    assert rc == 0
    kwargs = mock_list.call_args.kwargs
    assert kwargs["since"] == datetime(2026, 4, 28, tzinfo=timezone.utc)
    assert kwargs["until"] == datetime(2026, 4, 29, tzinfo=timezone.utc)


def test_lookback_hours_explicit() -> None:
    with patch.object(discover_cli, "list_recent_cves", return_value=[]) as mock_list:
        rc = discover_cli.main(["--lookback-hours", "6"])
    assert rc == 0
    kwargs = mock_list.call_args.kwargs
    diff = kwargs["until"] - kwargs["since"]
    assert 5.9 < diff.total_seconds() / 3600 < 6.1


def test_since_and_lookback_mutually_exclusive(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_cli.main(["--since", "2026-04-28T00:00:00Z", "--lookback-hours", "24"])
    assert rc == 64
    assert "mutually exclusive" in capsys.readouterr().err


def test_naive_datetime_rejected_with_usage_exit(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_cli.main(["--since", "2026-04-28T00:00:00", "--until", "2026-04-29T00:00:00Z"])
    assert rc == 64
    assert "timezone" in capsys.readouterr().err.lower()


def test_unparseable_datetime_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_cli.main(["--since", "not-a-date"])
    assert rc == 64


def test_rate_limit_exits_twenty(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_cli, "list_recent_cves", side_effect=FeedRateLimit(60)):
        rc = discover_cli.main([])
    assert rc == 20
    assert "60s" in capsys.readouterr().err


def test_transient_error_exits_ten() -> None:
    with patch.object(discover_cli, "list_recent_cves", side_effect=FeedTransientError("nope")):
        rc = discover_cli.main([])
    assert rc == 10


def test_api_key_lifted_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "abc-123")
    with patch.object(discover_cli, "list_recent_cves", return_value=[]) as mock_list:
        discover_cli.main([])
    assert mock_list.call_args.kwargs["api_key"] == "abc-123"


def test_no_api_key_passes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    with patch.object(discover_cli, "list_recent_cves", return_value=[]) as mock_list:
        discover_cli.main([])
    assert mock_list.call_args.kwargs["api_key"] is None


def test_multi_cve_output_one_per_line(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_cli, "list_recent_cves", return_value=["CVE-2026-1", "CVE-2026-2"]):
        discover_cli.main([])
    out = capsys.readouterr().out.strip().splitlines()
    assert out == ["CVE-2026-1", "CVE-2026-2"]
