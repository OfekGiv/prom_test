"""L3fwdProcess — subprocess lifecycle manager for dpdk-l3fwd."""

from __future__ import annotations

import logging
import math
import os
import signal
import subprocess
import threading
import time
from collections import deque
from typing import Iterator

from config import L3fwdConfig

log = logging.getLogger(__name__)

_READY_PATTERN = "entering main loop on lcore"
_DRAIN_INTERVAL = 0.05  # seconds between pipe reads


class L3fwdProcess:
    def __init__(self, cfg: L3fwdConfig) -> None:
        self._cfg = cfg
        self._proc: subprocess.Popen | None = None
        self._stdout: deque[str] = deque()
        self._stderr: deque[str] = deque()
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def build_cmd(self) -> list[str]:
        """Construct the full dpdk-l3fwd argv list from config."""
        eal = self._cfg.eal
        app = self._cfg.app

        cmd = []
        if self._cfg.use_sudo:
            cmd.append("sudo")
        cmd += [
            str(self._cfg.binary),
            # EAL args
            "-l", eal.lcores,
            "-n", str(eal.mem_channels),
            "-a", f"{eal.pci_addr},{eal.pci_args}{int(math.log2(len(self._cfg.lcores)))}",
            "--trace", "pmd.net.mlx5.db.ring",
            "--trace-dir", str(self._cfg.traces_dir.resolve()),
            "--",
            # App args
            "-p", app.portmask,
            f"--config={app.config}",
            f"--rule_ipv4={app.rule_ipv4}",
            f"--rule_ipv6={app.rule_ipv6}",
        ]
        if app.promiscuous:
            cmd.insert(cmd.index("--") + 1, "-P")

        return cmd

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        cmd = self.build_cmd()
        log.info("Starting l3fwd: %s", " ".join(cmd))

        if self._cfg.dry_run:
            log.info("[dry-run] skipping Popen")
            return

        self._cfg.traces_dir.mkdir(parents=True, exist_ok=True)
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
            cwd=self._cfg.pkts_dir.resolve().parent,
        )

        for stream, buf, level in [
            (self._proc.stdout, self._stdout, logging.INFO),
            (self._proc.stderr, self._stderr, logging.WARNING),
        ]:
            t = threading.Thread(
                target=self._drain,
                args=(stream, buf, level),
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def wait_for_ready(self, pattern: str = _READY_PATTERN) -> bool:
        """
        Block until `pattern` appears in stdout or startup_timeout elapses.
        Returns True if the pattern was found, False on timeout.
        """
        if self._cfg.dry_run:
            log.info("[dry-run] skipping wait_for_ready")
            return True

        deadline = time.monotonic() + self._cfg.startup_timeout
        while time.monotonic() < deadline:
            all_lines = list(self._stdout) + list(self._stderr)
            if any(pattern in line for line in all_lines):
                log.info("l3fwd is ready (pattern: %r)", pattern)
                return True
            if self._proc and self._proc.poll() is not None:
                log.error("l3fwd exited early (rc=%d)", self._proc.returncode)
                return False
            time.sleep(_DRAIN_INTERVAL)

        log.error("Timed out waiting for l3fwd ready pattern %r", pattern)
        return False

    def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is not None:
            return  # already exited

        log.info("Stopping l3fwd (SIGINT to process group)...")
        os.killpg(os.getpgid(self._proc.pid), signal.SIGINT)
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            log.warning("l3fwd did not exit after SIGINT, sending SIGKILL")
            os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            self._proc.wait()

        # DPDK creates trace dirs as root with 0700; make them readable
        traces_dir = self._cfg.traces_dir
        if traces_dir.exists():
            subprocess.run(
                ["sudo", "chmod", "-R", "a+rX", str(traces_dir)],
                check=False,
            )

        for t in self._threads:
            t.join(timeout=2)
        self._threads.clear()
        log.info("l3fwd stopped (rc=%s)", self._proc.returncode)

    # ------------------------------------------------------------------
    # Output access
    # ------------------------------------------------------------------

    def stdout_lines(self) -> list[str]:
        return list(self._stdout)

    def stderr_lines(self) -> list[str]:
        return list(self._stderr)

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode if self._proc else None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> L3fwdProcess:
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _drain(self, stream, buf: deque, level: int) -> None:
        """Read lines from *stream* into *buf* and log them."""
        for line in stream:
            line = line.rstrip("\n")
            buf.append(line)
            log.log(level, "[l3fwd] %s", line)
