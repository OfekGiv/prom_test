"""RemoteCapture — SSH-based tcpdump wrapper."""

from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path

from config import RemoteConfig

log = logging.getLogger(__name__)


class RemoteCapture:
    """
    Manages a remote packet capture session over SSH.

    If ``cfg.host`` is empty all methods are no-ops, enabling local-only
    development without a remote server.
    """

    def __init__(self, cfg: RemoteConfig) -> None:
        self._cfg = cfg
        self._remote_pcap: str = "/tmp/prom_capture.pcap"
        self._remote_log: str = "/tmp/prom_capture.log"

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------

    def start_capture(self, output_file: str | None = None) -> None:
        if not self._cfg.host:
            log.debug("RemoteCapture: no host configured, skipping start_capture")
            return

        self._remote_pcap = output_file or "/tmp/prom_capture.pcap"
        self._ssh(
            f"sudo rm -f {shlex.quote(self._remote_pcap)} {shlex.quote(self._remote_log)}",
            check=False,
        )

        capture_filter = self._cfg.capture_filter.strip() if self._cfg.capture_filter else ""
        filter_part = f" {shlex.quote(capture_filter)} " if capture_filter else " "
        cmd = (
            f"nohup sudo tcpdump -i {shlex.quote(self._cfg.iface)} "
            f"-B 16384 -s 128 "
            f"{filter_part}"
            f"-w {shlex.quote(self._remote_pcap)}"
            f" > {shlex.quote(self._remote_log)} 2>&1 < /dev/null & echo $!"
        )
        result = self._ssh(cmd, check=False)
        if result.returncode == 0:
            pid = result.stdout.strip()
            log.info("Remote tcpdump started on %s (pid=%s)", self._cfg.host, pid)

            # Fail early if tcpdump exits immediately (e.g., invalid/down iface)
            check_result = self._ssh(
                (
                    f"sleep 1; "
                    f"if ps -p {shlex.quote(pid)} >/dev/null 2>&1; then echo RUNNING; else echo NOT_RUNNING; fi; "
                    f"test -e {shlex.quote(self._remote_pcap)} && echo PCAP_EXISTS || echo PCAP_MISSING; "
                    f"test -f {shlex.quote(self._remote_log)} && tail -n 20 {shlex.quote(self._remote_log)} || true"
                ),
                check=False,
            )
            if "NOT_RUNNING" in check_result.stdout and "PCAP_MISSING" in check_result.stdout:
                raise RuntimeError(
                    "Remote tcpdump exited immediately and did not create capture file. "
                    f"Host={self._cfg.host} iface={self._cfg.iface}. "
                    f"tcpdump output:\n{check_result.stdout.strip()}"
                )
        else:
            log.error("Failed to start remote tcpdump: %s", result.stderr)
            raise RuntimeError(
                f"Failed to start remote tcpdump on {self._cfg.host}: {result.stderr.strip()}"
            )

    def stop_capture(self) -> None:
        if not self._cfg.host:
            log.debug("RemoteCapture: no host configured, skipping stop_capture")
            return

        self._ssh("sudo pkill -INT tcpdump || true", check=False)
        log.info("Stopped remote tcpdump on %s", self._cfg.host)

    # ------------------------------------------------------------------
    # Data retrieval
    # ------------------------------------------------------------------

    def fetch_pcap(self, local_path: Path) -> Path:
        """SCP the remote pcap to *local_path* and return the local path."""
        if not self._cfg.host:
            log.debug("RemoteCapture: no host configured, skipping fetch_pcap")
            return local_path

        src = f"{self._cfg.user}@{self._cfg.host}:{self._remote_pcap}"
        try:
            subprocess.run(
                ["scp", src, str(local_path)],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            diag = self._ssh(
                (
                    f"sudo ls -l {shlex.quote(self._remote_pcap)} 2>&1 || true; "
                    f"test -f {shlex.quote(self._remote_log)} && tail -n 40 {shlex.quote(self._remote_log)} || true"
                ),
                check=False,
            )
            raise RuntimeError(
                "Failed to fetch remote pcap. "
                f"Remote file={self._remote_pcap} host={self._cfg.host} iface={self._cfg.iface}. "
                f"scp rc={exc.returncode}. Diagnostics:\n{diag.stdout.strip()}"
            ) from exc
        log.info("Fetched pcap: %s -> %s", src, local_path)
        return local_path

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> RemoteCapture:
        return self

    def __exit__(self, *_) -> None:
        self.stop_capture()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ssh(self, remote_cmd: str, *, check: bool = True) -> subprocess.CompletedProcess:
        target = f"{self._cfg.user}@{self._cfg.host}" if self._cfg.user else self._cfg.host
        argv = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            target,
            remote_cmd,
        ]
        log.debug("SSH: %s", " ".join(argv))
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=check,
        )
