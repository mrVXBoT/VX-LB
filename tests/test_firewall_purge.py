"""Tests for ownership-scoped firewall purge of stale VX-LB engine rules."""
import pytest
from unittest.mock import Mock

from core.firewall_purge import PURGE_PROGRAM, purge_kernel_engine_rules


def test_purge_program_scopes_requested_tags():
    """Only VX-LB-owned tags for these identifiers are candidates for deletion."""
    assert "tags.append('vxlb-sec-'+identifier)" in PURGE_PROGRAM
    assert "tags.append('vxlb-vx-'+identifier)" in PURGE_PROGRAM
    # The loop must skip every line that does not carry one of the tags.
    assert "if not any(tag in line for tag in tags):continue" in PURGE_PROGRAM
    # It scans INPUT/OUTPUT/FORWARD only.
    assert "('INPUT','OUTPUT','FORWARD')" in PURGE_PROGRAM


def test_purge_accepts_multiple_identifiers():
    ssh = Mock()
    ssh.execute.return_value = (0, "2", "")
    purge_kernel_engine_rules(ssh, "vx0f9e2d3c1b", "vx-vx0f9e2d3c1b")
    command = ssh.execute.call_args.args[0]
    assert "vx0f9e2d3c1b" in command
    assert "vx-vx0f9e2d3c1b" in command


def test_purge_runs_on_ssh_and_counts():
    ssh = Mock()
    ssh.execute.return_value = (0, "3", "")
    assert purge_kernel_engine_rules(ssh, "vx0f9e2d3c1b") == 3
    command = ssh.execute.call_args.args[0]
    assert "python3 -c " in command
    assert "vx0f9e2d3c1b" in command


def test_purge_ignores_empty_iface_and_errors():
    assert purge_kernel_engine_rules(Mock(), "") == 0
    ssh = Mock()
    ssh.execute.side_effect = RuntimeError("connection lost")
    assert purge_kernel_engine_rules(ssh, "vx-test") == 0


def test_purge_program_only_deletes_vxlb_tagged_rules():
    """The remote program must never delete rules without a VX-LB tag."""
    assert "not any(tag in line for tag in tags):continue" in PURGE_PROGRAM
