#!/usr/bin/env python3
"""Run the API suite against a disposable, loopback-only native PostgreSQL.

Use the API virtualenv. Set PG_BIN to a directory containing PostgreSQL 16's
initdb, postgres and pg_ctl. This is a local fallback, not container validation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import psycopg


def stop_owned_server(server: subprocess.Popen, pg_ctl: str, data: Path, log) -> None:
    """Reap our child even when pg_ctl fails, before its data directory is removed."""
    if server.poll() is not None:
        return
    try:
        subprocess.run([pg_ctl, "-D", str(data), "-m", "immediate", "-w", "stop"],
                       stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
        server.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def main() -> int:
    api = Path(__file__).resolve().parents[1]
    binaries = {}
    for name in ("initdb", "postgres", "pg_ctl"):
        binary = (str(Path(os.environ["PG_BIN"]) / name) if os.environ.get("PG_BIN")
                  else shutil.which(name))
        if not binary or not os.access(binary, os.X_OK):
            raise SystemExit(f"Missing {name}; set PG_BIN to your PostgreSQL 16 bin directory")
        binaries[name] = binary
    version = subprocess.check_output([binaries["postgres"], "--version"], text=True).strip()
    if not version.startswith("postgres (PostgreSQL) 16."):
        raise SystemExit(f"Expected PostgreSQL 16, found {version}")

    password = secrets.token_hex(24)
    with tempfile.TemporaryDirectory(prefix="anonflow-pg-") as temporary:
        root = Path(temporary)
        data = root / "data"
        pwfile = root / "password"
        pwfile.touch(mode=0o600)
        pwfile.write_text(password)
        with (root / "server.log").open("w+") as log:
            subprocess.run([binaries["initdb"], "-D", str(data), "-U", "anonflow_test",
                            "--pwfile", str(pwfile), "--auth-host=scram-sha-256",
                            "--auth-local=scram-sha-256", "--encoding=UTF8", "--locale=C"],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
            pwfile.unlink()
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            server = subprocess.Popen([binaries["postgres"], "-D", str(data), "-h", "127.0.0.1",
                                       "-p", str(port), "-c", "unix_socket_directories="],
                                      stdout=log, stderr=subprocess.STDOUT)
            try:
                connection = dict(host="127.0.0.1", port=port, user="anonflow_test",
                                  password=password, connect_timeout=1)
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with psycopg.connect(**connection, dbname="postgres", autocommit=True) as conn:
                            conn.execute("CREATE DATABASE anonflow_test")
                            identity = conn.execute("SELECT version()").fetchone()[0]
                        break
                    except psycopg.OperationalError:
                        if server.poll() is not None or time.monotonic() > deadline:
                            log.seek(0)
                            print(log.read().replace(password, "[redacted]"), file=sys.stderr)
                            raise SystemExit("Disposable PostgreSQL did not become ready")
                        time.sleep(0.2)
                environment = os.environ.copy()
                environment["ANONFLOW_POSTGRES_TEST_DSN"] = (
                    f"postgresql://anonflow_test:{password}@127.0.0.1:{port}/anonflow_test")
                print(json.dumps({"postgres": identity, "scope": "disposable native PostgreSQL; not CI image"}), flush=True)
                arguments = sys.argv[1:] or ["-q", "-ra"]
                result = subprocess.run([sys.executable, "-m", "pytest", *arguments], cwd=api,
                                        env=environment, capture_output=True, text=True)
                print(result.stdout.replace(password, "[redacted]"), end="")
                print(result.stderr.replace(password, "[redacted]"), end="", file=sys.stderr)
                return result.returncode
            finally:
                stop_owned_server(server, binaries["pg_ctl"], data, log)


if __name__ == "__main__":
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(main())
