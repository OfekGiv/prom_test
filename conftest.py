"""pytest fixtures and CLI option injection for prom_test."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

import pytest

from config import L3fwdConfig, load_config, apply_cli_overrides
from process import L3fwdProcess
from remote import RemoteCapture

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)

_DEFAULT_CONFIG = Path(__file__).parent / "config.yaml"


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("prom_test", "prom_test options")
    g.addoption("--prom-config", default=str(_DEFAULT_CONFIG), help="Path to prom_test config.yaml")
    g.addoption("--dry-run", action="store_true", default=False, help="Skip actual process/SSH execution")

    # EAL overrides
    g.addoption("--binary", default=None, help="Path to dpdk-l3fwd binary")
    g.addoption("--lcores", default=None, help="EAL lcore list (e.g. '1-2')")
    g.addoption("--mem-channels", default=None, type=int, help="EAL -n value")
    g.addoption("--pci", default=None, help="PCI address (e.g. '0000:98:00.0')")
    g.addoption("--pci-args", default=None, help="PCI device args (e.g. 'mu_sq_log_grp_size=1')")

    # App overrides
    g.addoption("--portmask", default=None, help="Port mask (e.g. '0x1')")
    g.addoption("--fwd-config", default=None, help="l3fwd --config value")
    g.addoption("--rule-ipv4", default=None, help="Path to IPv4 rule DB")
    g.addoption("--rule-ipv6", default=None, help="Path to IPv6 rule DB")

    # Remote overrides
    g.addoption("--remote-host", default=None, help="Remote server hostname/IP")
    g.addoption("--remote-user", default=None, help="Remote SSH user")
    g.addoption("--remote-iface", default=None, help="Remote NIC to capture on")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def l3fwd_config(request: pytest.FixtureRequest) -> L3fwdConfig:
    cfg_path = request.config.getoption("--prom-config")
    cfg = load_config(cfg_path)
    cfg = apply_cli_overrides(cfg, request.config)
    return cfg


@pytest.fixture(scope="function")
def l3fwd_process(l3fwd_config: L3fwdConfig) -> Iterator[L3fwdProcess]:
    with L3fwdProcess(l3fwd_config) as proc:
        proc.start()
        ready = proc.wait_for_ready()
        if not ready and not l3fwd_config.dry_run:
            pytest.fail("l3fwd did not become ready in time")
        yield proc


@pytest.fixture(scope="function")
def remote_capture(l3fwd_config: L3fwdConfig) -> Iterator[RemoteCapture]:
    with RemoteCapture(l3fwd_config.remote) as cap:
        yield cap
