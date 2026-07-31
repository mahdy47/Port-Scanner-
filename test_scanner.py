import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import scanner

REPO_DIR = Path(__file__).resolve().parent
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_RE.sub("", text)


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "scanner.py", *args],
        cwd=REPO_DIR,
        capture_output=True,
        text=True,
    )


class TestCidrSafety:
    def test_network_too_large_is_skipped(self, capsys):
        assert scanner.expand_targets("10.0.0.0/21") == []
        assert "expands to more than 1024 hosts" in strip_ansi(capsys.readouterr().out)

    def test_network_at_limit_still_expands(self):
        assert len(scanner.expand_targets("10.0.0.0/22")) == 1022


class TestCliValidation:
    @pytest.mark.parametrize(
        "args,message",
        [
            (["-t", "127.0.0.1", "-p", "1-10", "--workers", "0"],
             "--workers must be at least 1"),
            (["-t", "127.0.0.1", "-p", "1-10", "--timeout", "0"],
             "--timeout must be greater than 0"),
            (["-t", "127.0.0.1", "-p", "1-10", "--retries", "-1"],
             "--retries must be 0 or greater"),
        ],
    )
    def test_invalid_args_exit_nonzero_with_message(self, args, message):
        result = run_cli(*args)
        assert result.returncode != 0
        assert message in strip_ansi(result.stdout)


class TestPortRangeParser:
    def test_valid_range(self):
        assert scanner.parse_port_range("1-100") == (1, 100)

    def test_single_port(self):
        assert scanner.parse_port_range("80") == (80, 80)
        assert scanner.parse_port_range("80-80") == (80, 80)

    def test_invalid_format(self, capsys):
        assert scanner.parse_port_range("abc") is None
        assert "Invalid port range format" in strip_ansi(capsys.readouterr().out)

    def test_reversed_range(self, capsys):
        assert scanner.parse_port_range("100-50") is None
        assert "Invalid port range" in strip_ansi(capsys.readouterr().out)

    def test_out_of_bounds(self):
        assert scanner.parse_port_range("0-80") is None
        assert scanner.parse_port_range("1-999999999") is None
        assert scanner.parse_port_range("70000-80000") is None


class TestConfigBuilder:
    EXPECTED_KEYS = {
        "targets", "start_port", "end_port", "timeout",
        "grab_banners", "do_udp", "polite", "retries", "save_formats",
    }

    def test_build_config_has_expected_keys(self):
        config = scanner._build_config(
            ["127.0.0.1"], 1, 100, 0.5, False, False, False, 0, ["txt"]
        )
        assert set(config) == self.EXPECTED_KEYS

    def test_interactive_config_has_expected_keys(self, monkeypatch):
        inputs = iter(["127.0.0.1", "1", "", "1", "2", "2", "0", "txt"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        config = scanner.interactive_mode()
        assert set(config) == self.EXPECTED_KEYS
        assert config["save_formats"] == ["txt"]

    def test_parse_save_formats(self):
        assert scanner._parse_save_formats(" txt, json ,,") == ["txt", "json"]
        assert scanner._parse_save_formats("") == []


class TestSmoke:
    def test_localhost_scan_smoke(self, monkeypatch):
        monkeypatch.setattr(scanner, "get_ttl", lambda ip: None)
        all_results, os_guesses = scanner.run_scan(
            ["127.0.0.1"], 445, 445, 0.3, False, 0, False, False, 10
        )
        assert "127.0.0.1" in all_results
        assert isinstance(all_results["127.0.0.1"], list)
        assert os_guesses["127.0.0.1"] == "Unknown"

    def test_invalid_target_is_skipped(self, monkeypatch, capsys):
        def fake_resolve(_name):
            raise socket.gaierror

        monkeypatch.setattr(scanner.socket, "gethostbyname", fake_resolve)
        assert scanner.expand_targets("99.99.99.999") == []
        assert "Skipping invalid target" in strip_ansi(capsys.readouterr().out)
