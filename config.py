"""Configuration dataclasses, YAML loader, and CLI override helpers."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class EalConfig:
    lcores: str = "1-2"
    mem_channels: int = 4
    pci_addr: str = "0000:98:00.0"
    pci_args: str = "mu_sq_log_grp_size=1"


@dataclass
class AppConfig:
    promiscuous: bool = True
    portmask: str = "0x1"
    config: str = ""
    rule_ipv4: Path = Path("/homes/ofer.katz/Tests/l3fwd/ipv4_rule.db")
    rule_ipv6: Path = Path("/homes/ofer.katz/Tests/l3fwd/ipv6_rule.db")


@dataclass
class RemoteConfig:
    host: str = ""
    user: str = ""
    iface: str = ""
    capture_timeout: int = 10
    capture_filter: str = "ip"


@dataclass
class L3fwdConfig:
    binary: Path = Path("/homes/ofer.katz/prom-dpdk/build/examples/dpdk-l3fwd")
    pkts_dir: Path = Path("./pkts")
    lcores: list[int] = field(default_factory=lambda: [1, 2])
    startup_timeout: int = 30
    dry_run: bool = False
    use_sudo: bool = True
    eal: EalConfig = field(default_factory=EalConfig)
    app: AppConfig = field(default_factory=AppConfig)
    remote: RemoteConfig = field(default_factory=RemoteConfig)


def _parse_lcores(s: str) -> list[int]:
    """Parse an EAL lcore list/range string into a list of ints.

    Examples:
        "1-2" -> [1, 2]
        "2,4,6,8" -> [2, 4, 6, 8]
        "1-2,4" -> [1, 2, 4]
    """

    if not s:
        return []

    out: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return out


def _lcores_to_fwd_config(lcores: list[int]) -> str:
    """Generate an l3fwd --config string for a list of lcores.

    The format is:
        (0,0,lcore0),(0,1,lcore1),...
    """
    return ",".join(f"(0,{i},{lc})" for i, lc in enumerate(lcores))


def _count_fwd_config_entries(config: str) -> int:
    """Count how many (0,i,lcore) entries appear in a config string."""
    import re

    return len(re.findall(r"\(\s*0\s*,\s*\d+\s*,\s*\d+\s*\)", config))


def _from_dict(data: dict[str, Any]) -> L3fwdConfig:
    eal_data = data.get("eal", {})
    app_data = data.get("app", {})
    remote_data = data.get("remote", {})

    defaults = L3fwdConfig()

    eal = EalConfig(
        lcores=eal_data.get("lcores", EalConfig.lcores),
        mem_channels=int(eal_data.get("mem_channels", EalConfig.mem_channels)),
        pci_addr=eal_data.get("pci_addr", EalConfig.pci_addr),
        pci_args=eal_data.get("pci_args", EalConfig.pci_args),
    )

    # Determine the actual lcore list used for both EAL and packet generation.
    # Prefer an explicit top-level `lcores:` list in YAML; otherwise derive it
    # from the EAL `lcores` string (e.g. "1-2", "2,4,6,8").
    if "lcores" in data:
        lcores = list(data["lcores"])
    else:
        lcores = _parse_lcores(eal.lcores)

    app_config = str(app_data.get("config", ""))
    if not app_config or _count_fwd_config_entries(app_config) != len(lcores):
        app_config = _lcores_to_fwd_config(lcores)

    app = AppConfig(
        promiscuous=bool(app_data.get("promiscuous", AppConfig.promiscuous)),
        portmask=str(app_data.get("portmask", AppConfig.portmask)),
        config=app_config,
        rule_ipv4=Path(app_data["rule_ipv4"]) if "rule_ipv4" in app_data else AppConfig.rule_ipv4,
        rule_ipv6=Path(app_data["rule_ipv6"]) if "rule_ipv6" in app_data else AppConfig.rule_ipv6,
    )

    remote = RemoteConfig(
        host=remote_data.get("host", ""),
        user=remote_data.get("user", ""),
        iface=remote_data.get("iface", ""),
        capture_timeout=int(remote_data.get("capture_timeout", 10)),
        capture_filter=remote_data.get("capture_filter", "ip"),
    )

    defaults = L3fwdConfig()
    return L3fwdConfig(
        binary=Path(data.get("binary", defaults.binary)),
        pkts_dir=Path(data.get("pkts_dir", defaults.pkts_dir)),
        lcores=lcores,
        startup_timeout=int(data.get("startup_timeout", defaults.startup_timeout)),
        dry_run=bool(data.get("dry_run", False)),
        use_sudo=bool(data.get("use_sudo", True)),
        eal=eal,
        app=app,
        remote=remote,
    )


def load_config(yaml_path: str | Path) -> L3fwdConfig:
    """Parse a YAML file into an L3fwdConfig."""
    with open(yaml_path) as f:
        data = yaml.safe_load(f) or {}
    return _from_dict(data)


def apply_cli_overrides(cfg: L3fwdConfig, args: Any) -> L3fwdConfig:
    """
    Apply overrides from a parsed argparse Namespace (or pytest config)
    on top of an existing L3fwdConfig.  Only non-None values override.
    """
    cfg = copy.deepcopy(cfg)

    def _get(name: str):
        if hasattr(args, "getoption"):
            try:
                return args.getoption(name)
            except ValueError:
                return None
        return getattr(args, name, None)

    if (v := _get("--binary") or _get("binary")) is not None:
        cfg.binary = Path(v)
    if (v := _get("--pkts-dir") or _get("pkts_dir")) is not None:
        cfg.pkts_dir = Path(v)
    if (v := _get("--startup-timeout") or _get("startup_timeout")) is not None:
        cfg.startup_timeout = int(v)
    if _get("--dry-run") or _get("dry_run"):
        cfg.dry_run = True

    # EAL
    if (v := _get("--lcores") or _get("lcores")) is not None:
        # If app.config was auto-generated from the previous lcore list, refresh it.
        prev_auto = _lcores_to_fwd_config(cfg.lcores)

        cfg.eal.lcores = v
        new_lcores = _parse_lcores(v)
        cfg.lcores = new_lcores

        if cfg.app.config == prev_auto:
            cfg.app.config = _lcores_to_fwd_config(new_lcores)
    if (v := _get("--mem-channels") or _get("mem_channels")) is not None:
        cfg.eal.mem_channels = int(v)
    if (v := _get("--pci") or _get("pci")) is not None:
        cfg.eal.pci_addr = v
    if (v := _get("--pci-args") or _get("pci_args")) is not None:
        cfg.eal.pci_args = v

    # App
    if (v := _get("--portmask") or _get("portmask")) is not None:
        cfg.app.portmask = v
    if (v := _get("--fwd-config") or _get("fwd_config")) is not None:
        cfg.app.config = v
    if (v := _get("--rule-ipv4") or _get("rule_ipv4")) is not None:
        cfg.app.rule_ipv4 = Path(v)
    if (v := _get("--rule-ipv6") or _get("rule_ipv6")) is not None:
        cfg.app.rule_ipv6 = Path(v)

    # Remote
    if (v := _get("--remote-host") or _get("remote_host")) is not None:
        cfg.remote.host = v
    if (v := _get("--remote-user") or _get("remote_user")) is not None:
        cfg.remote.user = v
    if (v := _get("--remote-iface") or _get("remote_iface")) is not None:
        cfg.remote.iface = v

    return cfg
