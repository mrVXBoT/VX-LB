import datetime
import pytest

from core import dns_scheduler


def test_normalize_schedule_interval_defaults():
    s = dns_scheduler.normalize_schedule({"enabled": True, "interval_minutes": 30})
    assert s == {"enabled": True, "mode": "interval", "interval_minutes": 30, "daily_time": "03:00"}


def test_next_run_daily_rolls_to_tomorrow():
    now = datetime.datetime(2026, 1, 2, 3, 0).timestamp()
    expected = datetime.datetime(2026, 1, 3, 3, 0).timestamp()
    assert dns_scheduler.next_run_epoch({"mode": "daily", "daily_time": "03:00"}, now) == expected


def test_effective_schedule_pool_override():
    data = {
        "dns_scheduler": {"enabled": True, "mode": "interval", "interval_minutes": 30, "daily_time": "03:00"},
        "pools": {"p": {"rotation": {"inherit_global": False, "enabled": True, "mode": "daily", "daily_time": "04:30"}}},
    }
    assert dns_scheduler.effective_schedule(data, "p")["mode"] == "daily"
    assert dns_scheduler.effective_schedule(data, "p")["daily_time"] == "04:30"


def test_scheduled_dns_pins_current_target():
    data = {
        "dns_scheduler": {"enabled": True, "mode": "interval", "interval_minutes": 30, "daily_time": "03:00"},
        "pools": {"p": {"rotation": {"inherit_global": True, "active_ip": "2.2.2.2"}}},
    }
    assert dns_scheduler.scheduled_dns_ips(data, "p", ["1.1.1.1", "2.2.2.2"]) == (["2.2.2.2"], False)
    assert dns_scheduler.scheduled_dns_ips(data, "p", ["1.1.1.1", "3.3.3.3"]) == (["1.1.1.1"], True)
