"""dns_block.sh idempotency — running twice leaves /etc/hosts with one entry
per domain, never duplicates."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "dns_block.sh"
SEED_DOMAINS = [
    "monicasue.app.n8n.cloud",
    "pagepoinnc.app.n8n.cloud",
    "tti.app.n8n.cloud",
    "swift-wallat-usdt-send.netlify.app",
    "send-usdt-09-admin.netlify.app",
    "get-proton-vpn.com",
    "vpn-proton-setup.com",
    "files.catbox.moe",
]


def _run(hosts: Path, log: Path, output_dir: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke dns_block.sh in test mode.

    `OUTPUT_DIR` is overridden so the script doesn't pick up stale reports
    from the real `output/` — without that override, a live report with 100+
    domains would bleed into the seed-only assertions below.
    """
    env = os.environ.copy()
    env["HOSTS_FILE"] = str(hosts)
    env["LOG_FILE"] = str(log)
    env["OUTPUT_DIR"] = str(output_dir or hosts.parent / "empty_output")
    env["TEST_MODE"] = "1"
    # Ensure the empty dir exists so the `find` call inside the script
    # succeeds with no results, rather than erroring on a missing directory.
    Path(env["OUTPUT_DIR"]).mkdir(exist_ok=True)
    return subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.fixture
def fake_hosts(tmp_path: Path) -> Path:
    hosts = tmp_path / "hosts"
    # Seed with a typical Fedora default so real localhost entries survive.
    hosts.write_text(
        "127.0.0.1   localhost localhost.localdomain\n::1         localhost localhost.localdomain\n"
    )
    return hosts


@pytest.fixture
def fake_log(tmp_path: Path) -> Path:
    return tmp_path / "blocks.log"


class TestIdempotency:
    def test_first_run_adds_all_seeds(self, fake_hosts: Path, fake_log: Path) -> None:
        result = _run(fake_hosts, fake_log)
        assert result.returncode == 0, result.stderr
        text = fake_hosts.read_text()
        for domain in SEED_DOMAINS:
            assert (
                f"\t{domain}\t" in text
                or f" {domain} " in text
                or f"\t{domain}\n" in text
                or f"\t{domain} " in text
            ), f"seed domain {domain} missing from hosts file:\n{text}"
        assert "Added:          8" in result.stdout

    def test_second_run_adds_nothing(self, fake_hosts: Path, fake_log: Path) -> None:
        first = _run(fake_hosts, fake_log)
        assert first.returncode == 0
        first_contents = fake_hosts.read_text()

        second = _run(fake_hosts, fake_log)
        assert second.returncode == 0
        # Contents must be byte-identical after re-run.
        assert fake_hosts.read_text() == first_contents
        assert "Added:          0" in second.stdout
        # All seeds are skipped as already-present.
        assert "Already-present: 8" in second.stdout

    def test_no_duplicate_entries_for_any_domain(self, fake_hosts: Path, fake_log: Path) -> None:
        _run(fake_hosts, fake_log)
        _run(fake_hosts, fake_log)
        _run(fake_hosts, fake_log)
        text = fake_hosts.read_text()
        for domain in SEED_DOMAINS:
            # Count lines where the second whitespace-separated field equals the domain.
            count = sum(
                1
                for line in text.splitlines()
                if line.strip()
                and not line.lstrip().startswith("#")
                and line.split()[1:2] == [domain]
            )
            assert count == 1, f"domain {domain} appears {count}x, expected 1x\n{text}"

    def test_preserves_existing_hosts_entries(self, fake_hosts: Path, fake_log: Path) -> None:
        result = _run(fake_hosts, fake_log)
        assert result.returncode == 0
        text = fake_hosts.read_text()
        # localhost entries from the fixture must still be present.
        assert "127.0.0.1" in text
        assert "localhost.localdomain" in text
