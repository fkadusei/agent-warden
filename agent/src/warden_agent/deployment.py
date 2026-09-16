"""Running the example deployment for a benchmark: the Go binaries, the tool servers,
and (with Warden) a real `warden serve` with its receipt log.

Everything lives in a temporary directory with synthetic keys and is removed afterwards.
"""

from __future__ import annotations

import os
import secrets
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

BINARIES = ("warden", "example-tools", "warden-verify")
CHAIN = "warden-bench"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def wait_port(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing is listening on 127.0.0.1:{port}")


def build(repo: Path, into: Path) -> dict[str, Path]:
    """Build the Go commands the benchmark drives."""
    into.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    for name in BINARIES:
        path = into / name
        subprocess.run(["go", "build", "-o", str(path), f"./cmd/{name}"], cwd=repo, check=True)
        out[name] = path
    return out


class ToolServers:
    """The example tool servers, restarted for each scenario's planted content."""

    def __init__(self, binary: Path, token: str, log: Path) -> None:
        self._binary, self._token, self._log = binary, token, log
        self.port = free_port()
        self._proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def restart(self, scenario_id: str) -> None:
        self.stop()
        with self._log.open("ab") as out:
            self._proc = subprocess.Popen(
                [str(self._binary), "--listen", f"127.0.0.1:{self.port}", "--scenario", scenario_id],
                env={**os.environ, "EXAMPLE_PAYMENTS_TOKEN": self._token},
                stdout=out,
                stderr=out,
            )
        wait_port(self.port)

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(timeout=10)
            self._proc = None


@dataclass(frozen=True)
class Credential:
    cert: Path
    key: Path


@dataclass(frozen=True)
class Evidence:
    receipts: Path
    receipt_bytes: int
    receipts_count: int
    verified: bool


class Warden:
    """A real `warden serve` over the example deployment."""

    def __init__(self, binaries: dict[str, Path], work: Path, tools_url: str, token: str) -> None:
        self._bin = binaries
        self._dir = work / "warden"
        self._token = token
        self._log = work / "serve.log"
        self.port = free_port()
        self._approver_port = free_port()
        self._proc: subprocess.Popen[bytes] | None = None
        self._run(
            "warden",
            "init",
            "--dir",
            str(self._dir),
            "--tools-url",
            tools_url,
            "--listen",
            f"127.0.0.1:{self.port}",
            "--approver-listen",
            f"127.0.0.1:{self._approver_port}",
            "--chain",
            CHAIN,
        )

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    @property
    def ca(self) -> Path:
        return self._dir / "pki" / "ca.pem"

    def _run(self, binary: str, *args: str) -> str:
        done = subprocess.run(
            [str(self._bin[binary]), *args],
            capture_output=True,
            text=True,
            env={**os.environ, "WARDEN_SECRET_PAYMENTS": self._token},
        )
        if done.returncode != 0:
            raise RuntimeError(
                f"{binary} {' '.join(args)} failed: {done.stderr.strip() or done.stdout.strip()}"
            )
        return done.stdout

    def config(self) -> str:
        return str(self._dir / "warden.json")

    def pin(self) -> None:
        self._run("warden", "pin", "--config", self.config(), "--write")

    def start(self) -> None:
        with self._log.open("ab") as out:
            self._proc = subprocess.Popen(
                [str(self._bin["warden"]), "serve", "--config", self.config()],
                env={**os.environ, "WARDEN_SECRET_PAYMENTS": self._token},
                stdout=out,
                stderr=out,
            )
        wait_port(self.port)

    def issue_task(self, principal: str, task: str) -> Credential:
        prefix = self._dir / f"agent-{task}"
        self._run(
            "warden",
            "issue-task",
            "--config",
            self.config(),
            "--agent",
            "warden-bench",
            "--principal",
            principal,
            "--task",
            task,
            "--out",
            str(prefix),
        )
        return Credential(Path(f"{prefix}.pem"), Path(f"{prefix}.key"))

    def stop_and_export(self, out_dir: Path) -> Evidence:
        """Stop Warden (writing a final checkpoint), export the log, and verify it."""
        if self._proc is not None:
            self._proc.send_signal(signal.SIGINT)
            self._proc.wait(timeout=30)
            self._proc = None
        out_dir.mkdir(parents=True, exist_ok=True)
        receipts = out_dir / "receipts.jsonl"
        self._run("warden", "export", "--config", self.config(), "--out", str(receipts))
        for name in ("keys.json",):
            shutil.copy(self._dir / name, out_dir / name)
        anchor = self._dir / "data" / "anchor.jsonl"
        shutil.copy(anchor, out_dir / "anchor.jsonl")
        verify = subprocess.run(
            [
                str(self._bin["warden-verify"]),
                "--log",
                str(receipts),
                "--chain",
                CHAIN,
                "--keys",
                str(out_dir / "keys.json"),
                "--anchor",
                str(out_dir / "anchor.jsonl"),
            ],
            capture_output=True,
            text=True,
        )
        data = receipts.read_bytes()
        return Evidence(receipts, len(data), len(data.splitlines()), verify.returncode == 0)


def new_token() -> str:
    """A synthetic payments token for one benchmark run."""
    return f"bench-{secrets.token_hex(8)}"
